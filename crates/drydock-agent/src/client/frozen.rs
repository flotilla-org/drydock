//! The frozen upgrade path, over plain HTTP/1.1: hello, the resumable upload
//! of a blob, activation and confirmation. Every agent generation serves
//! these requests with these meanings, so a host can bring an agent of any
//! release to its own build before it relies on anything else. Once hello
//! matches, `GET /control` turns the same connection into the current wire.
use super::*;
use hyper::client::conn::http1;

pub(super) struct UpgradePath {
    sender: http1::SendRequest<RequestBody>,
    driver: tokio::task::JoinHandle<()>,
    pub(super) hello: Hello,
}
impl Drop for UpgradePath {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl UpgradePath {
    /// HTTP/1.1 on a fresh connection to the agent, and its hello.
    pub(super) async fn connect(stream: ByteStream) -> io::Result<Self> {
        let (sender, connection) =
            http1::handshake(hyper_util::rt::TokioIo::new(stream)).await.map_err(|e| link_error("HTTP/1.1 handshake", e))?;
        let driver = tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        });
        let hello = Hello { fingerprint: String::new(), features: vec![], platform: None, boot_id: String::new(), probation: false };
        let mut path = Self { sender, driver, hello };
        path.hello = decode(path.send("GET", "/hello", &[], empty()).await?, "GET", "/hello").await?;
        Ok(path)
    }
    async fn request(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: RequestBody,
    ) -> io::Result<http::Response<axum::body::Body>> {
        let context = || format!("{method} {uri}");
        self.sender.ready().await.map_err(|e| link_error(context(), e))?;
        let mut request = http::Request::builder().method(method).uri(uri).header(http::header::HOST, "agent");
        for (name, value) in headers {
            request = request.header(*name, value);
        }
        let response = self.sender.send_request(request.body(body).map_err(invalid)?).await.map_err(|e| link_error(context(), e))?;
        let (parts, body) = response.into_parts();
        Ok(http::Response::from_parts(parts, axum::body::Body::new(body)))
    }
    async fn send(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: RequestBody,
    ) -> io::Result<http::Response<axum::body::Body>> {
        let response = self.request(method, uri, headers, body).await?;
        if !response.status().is_success() {
            let status = response.status();
            return Err(refusal(method, uri, status, response.into_body()).await);
        }
        Ok(response)
    }
    /// Send `method` and read its whole reply, so the connection is free
    /// for the next request.
    async fn exchange(
        &mut self,
        method: &str,
        uri: &str,
        headers: &[(&str, String)],
        body: RequestBody,
    ) -> io::Result<http::Response<Bytes>> {
        let response = self.send(method, uri, headers, body).await?;
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.map_err(|e| link_error(format!("{method} {uri}"), e))?.to_bytes();
        Ok(http::Response::from_parts(parts, bytes))
    }
    /// Whether the agent holds a completed blob of `sha256`, and otherwise
    /// how much of an upload of it.
    async fn state(&mut self, sha256: &str) -> io::Result<Option<(u64, bool)>> {
        match self.exchange("HEAD", &format!("/blobs/{sha256}"), &[], empty()).await {
            Ok(_) => return Ok(Some((0, true))),
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            Err(_) => {}
        }
        match self.exchange("HEAD", &format!("/uploads/{sha256}"), &upload_headers(false, "")[..1], empty()).await {
            Ok(response) => Ok(Some(upload_progress(response.headers()))),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    /// Upload `executable` as a blob unless the agent holds it, continuing
    /// any upload of it an earlier attempt left. Returns its digest.
    pub(super) async fn put(&mut self, executable: &[u8]) -> io::Result<String> {
        let sha256 = format!("{:x}", Sha256::digest(executable));
        let length = executable.len() as u64;
        let (uri, headers, rest) = match self.state(&sha256).await? {
            Some((_, true)) => return Ok(sha256),
            None => {
                let mut headers = upload_headers(true, "application/octet-stream");
                headers.push(("upload-length", length.to_string()));
                (format!("/blobs/{sha256}"), headers, executable)
            }
            Some((offset, false)) => {
                let mut headers = upload_headers(true, "application/partial-upload");
                headers.push(("upload-offset", offset.to_string()));
                (format!("/uploads/{sha256}"), headers, &executable[offset.min(length) as usize..])
            }
        };
        let method = if uri.starts_with("/blobs/") { "PUT" } else { "PATCH" };
        self.exchange(method, &uri, &headers, full(Bytes::copy_from_slice(rest))).await?;
        Ok(sha256)
    }
    /// Activate the completed upload of `sha256`; the agent drains for up to
    /// `drain`, then re-execs. An agent from before the drain sends no body.
    pub(super) async fn activate(&mut self, sha256: &str, drain: std::time::Duration) -> io::Result<Activated> {
        let uri = format!("/upgrade{}", query(&DigestQuery { sha256: digest(sha256)?.to_owned() })?);
        let body = json_body(&Activation { drain_ms: drain.as_millis().try_into().unwrap_or(u64::MAX) })?;
        let response = self.exchange("POST", &uri, &[("content-type", "application/json".into())], body).await?;
        if response.body().is_empty() {
            return Ok(Activated { sha256: sha256.into(), running: vec![] });
        }
        serde_json::from_slice(response.body())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("POST {uri}: malformed reply: {e}")))
    }
    pub(super) async fn confirm(&mut self) -> io::Result<()> {
        self.exchange("POST", "/upgrade/confirm", &[], empty()).await.map(drop)
    }
    /// Carry on over the current wire on this connection. Only an agent
    /// whose hello matched `expected` is asked: the route belongs to this
    /// build's wire, not to the frozen path.
    pub(super) async fn into_client(mut self, expected: &str) -> io::Result<Client> {
        let headers = [("connection", "upgrade".to_owned()), ("upgrade", crate::CONTROL.to_owned())];
        let mut response = self.request("GET", "/control", &headers, empty()).await?;
        if response.status() != http::StatusCode::SWITCHING_PROTOCOLS {
            let status = response.status();
            return Err(refusal("GET", "/control", status, response.into_body()).await);
        }
        let stream = link::upgraded(hyper::upgrade::on(&mut response)).await.map_err(|e| link_error("GET /control", e))?;
        Client::connect(stream, expected).await
    }
}
