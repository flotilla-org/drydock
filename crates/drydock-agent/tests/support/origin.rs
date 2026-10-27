//! An in-process HTTP/1.1 server standing in for the network boundary: a
//! release download host, an OCI registry, its token service or its blob
//! CDN. It records every request, and each test's handler states what a
//! request must carry; a request that does not is answered 400, so a fetch
//! succeeds only by making the requests the real service requires.
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

#[derive(Clone, Debug)]
pub struct Request {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
}
impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    /// The start of a `Range: bytes=N-` request; the agent asks for no other kind.
    pub fn range_start(&self) -> Option<u64> {
        let range = self.header("range")?;
        let start = range.strip_prefix("bytes=")?.strip_suffix('-').expect("only open-ended ranges are asked for");
        Some(start.parse().expect("a numeric range start"))
    }
}

#[derive(Clone)]
pub enum Content {
    Memory(Arc<Vec<u8>>),
    /// Streamed from disk, never held whole.
    File(PathBuf, u64),
}
impl Content {
    pub fn bytes(bytes: Vec<u8>) -> Self {
        Self::Memory(Arc::new(bytes))
    }
    fn len(&self) -> u64 {
        match self {
            Self::Memory(bytes) => bytes.len() as u64,
            Self::File(_, len) => *len,
        }
    }
}
pub enum Reply {
    Status(u16, Vec<(&'static str, String)>, Vec<u8>),
    /// The content: 206 for a satisfiable `Range` when `ranges`, else 200
    /// whole. `cut_after` closes the connection after that many body bytes,
    /// with the full length already declared.
    Content {
        content: Content,
        ranges: bool,
        cut_after: Option<u64>,
    },
}
impl Reply {
    pub fn content(content: Content) -> Self {
        Self::Content { content, ranges: true, cut_after: None }
    }
    pub fn bad(message: impl Into<String>) -> Self {
        Self::Status(400, vec![], message.into().into_bytes())
    }
}
type Handler = Arc<dyn Fn(&Request) -> Reply + Send + Sync>;

pub struct Origin {
    pub address: std::net::SocketAddr,
    log: Arc<Mutex<Vec<Request>>>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Origin {
    pub async fn start(handler: impl Fn(&Request) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let log: Arc<Mutex<Vec<Request>>> = Arc::default();
        let handler: Handler = Arc::new(handler);
        let recorded = log.clone();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let (handler, log) = (handler.clone(), recorded.clone());
                tokio::spawn(async move {
                    let _ = serve(stream, handler, log).await;
                });
            }
        });
        Self { address, log, task }
    }
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }
    pub fn requests(&self) -> Vec<Request> {
        self.log.lock().unwrap().clone()
    }
}
async fn serve(mut stream: tokio::net::TcpStream, handler: Handler, log: Arc<Mutex<Vec<Request>>>) -> std::io::Result<()> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        head.push(stream.read_u8().await?);
    }
    let text = String::from_utf8(head).unwrap();
    let mut lines = text.split("\r\n");
    let mut first = lines.next().unwrap().split(' ');
    let (method, target) = (first.next().unwrap().to_owned(), first.next().unwrap().to_owned());
    let headers = lines
        .filter(|l| !l.is_empty())
        .map(|l| l.split_once(':').unwrap())
        .map(|(n, v)| (n.trim().to_owned(), v.trim().to_owned()))
        .collect();
    let request = Request { method, target, headers };
    log.lock().unwrap().push(request.clone());
    // Requirements every request to every stand-in meets: a GET carrying
    // the Host it was sent to, asking for the bytes as stored.
    let reply = if request.method != "GET" || request.header("host").is_none() || request.header("accept-encoding") != Some("identity") {
        Reply::bad("a GET with Host and Accept-Encoding: identity is required")
    } else {
        handler(&request)
    };
    match reply {
        Reply::Status(status, headers, body) => {
            let mut response = format!("HTTP/1.1 {status} Status\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
            for (name, value) in headers {
                response.push_str(&format!("{name}: {value}\r\n"));
            }
            response.push_str("\r\n");
            stream.write_all(response.as_bytes()).await?;
            stream.write_all(&body).await?;
        }
        Reply::Content { content, ranges, cut_after } => {
            let size = content.len();
            let start = request.range_start().filter(|_| ranges);
            let head = match start {
                Some(start) if start >= size => {
                    let head = format!("HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{size}\r\nContent-Length: 0\r\n\r\n");
                    stream.write_all(head.as_bytes()).await?;
                    return stream.shutdown().await;
                }
                Some(start) => format!(
                    "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {start}-{}/{size}\r\nContent-Length: {}\r\n",
                    size - 1,
                    size - start
                ),
                None => format!("HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n"),
            };
            let accept = if ranges { "Accept-Ranges: bytes\r\n" } else { "" };
            stream.write_all(format!("{head}{accept}Connection: close\r\n\r\n").as_bytes()).await?;
            let start = start.unwrap_or(0);
            let end = cut_after.map_or(size, |cut| (start + cut).min(size));
            match content {
                Content::Memory(bytes) => stream.write_all(&bytes[start as usize..end as usize]).await?,
                Content::File(path, _) => {
                    use tokio::io::AsyncSeekExt;
                    let mut file = tokio::fs::File::open(path).await?;
                    file.seek(std::io::SeekFrom::Start(start)).await?;
                    tokio::io::copy(&mut file.take(end - start), &mut stream).await?;
                }
            }
        }
    }
    stream.shutdown().await
}
