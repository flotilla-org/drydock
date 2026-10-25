//! Provider API seam shared by embedded and socket-backed callers.
use crate::client::{Client, Error, WireResponse};
use axum::http::Method;
use drydock_protocol::*;
pub type ObservationStream = futures::stream::BoxStream<'static, Result<ObserveRecord, Error>>;

/// The provider HTTP surface, usable through a daemon socket or an embedded
/// router. Paths are segment arrays so provider names and IDs remain opaque.
/// Host configuration and credential refresh are deliberately outside this API.
#[async_trait::async_trait]
pub trait ProviderApi: Send + Sync {
    /// Typed discovery with the same protocol compatibility checks as the socket client.
    async fn hello(&self) -> Result<Hello, Error>;
    async fn observe(&self, since: Option<&str>) -> Result<ObservationStream, Error>;
    async fn request(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<WireResponse, Error>;
    async fn list(&self, provider: &str) -> Result<Vec<Environment>, Error> {
        api_json(self, Method::GET, &["v1", "providers", provider, "environments"], &[], None).await
    }
    async fn inspect(&self, provider: &str, id: &str) -> Result<Environment, Error> {
        api_json(self, Method::GET, &["v1", "providers", provider, "environments", id], &[], None).await
    }
    async fn prepare(&self, provider: &str, request: &PrepareRequest) -> Result<Prepared, Error> {
        api_json(
            self,
            Method::POST,
            &["v1", "providers", provider, "prepare"],
            &[],
            Some(serde_json::to_value(request).map_err(|_| Error::InvalidRequest)?),
        )
        .await
    }
    async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Environment, Error> {
        api_json(
            self,
            Method::POST,
            &["v1", "providers", provider, "environments"],
            &[],
            Some(serde_json::to_value(request).map_err(|_| Error::InvalidRequest)?),
        )
        .await
    }
    async fn destroy(&self, provider: &str, id: &str) -> Result<(), Error> {
        api_json(self, Method::DELETE, &["v1", "providers", provider, "environments", id], &[], None).await
    }
    async fn reach(&self, provider: &str, id: &str) -> Result<Reach, Error> {
        api_json(self, Method::POST, &["v1", "providers", provider, "environments", id, "reach"], &[], None).await
    }
    async fn suspend(&self, provider: &str, id: &str) -> Result<ResumeToken, Error> {
        api_json(self, Method::POST, &["v1", "providers", provider, "environments", id, "suspend"], &[], None).await
    }
    async fn resume(&self, provider: &str, id: &str, token: &ResumeToken) -> Result<(), Error> {
        api_json(
            self,
            Method::POST,
            &["v1", "providers", provider, "environments", id, "resume"],
            &[],
            Some(serde_json::to_value(token).map_err(|_| Error::InvalidRequest)?),
        )
        .await
    }
    async fn export(&self, provider: &str, id: &str) -> Result<Export, Error> {
        api_json(self, Method::POST, &["v1", "providers", provider, "environments", id, "export"], &[], None).await
    }
    async fn quota(&self, provider: &str) -> Result<Quota, Error> {
        api_json(self, Method::GET, &["v1", "providers", provider, "quota"], &[], None).await
    }
    async fn usage(&self, provider: &str, period: &Period) -> Result<Usage, Error> {
        let value = serde_json::to_value(period).map_err(|_| Error::InvalidRequest)?;
        api_json(
            self,
            Method::GET,
            &["v1", "providers", provider, "usage"],
            &[
                ("start", value["start"].as_str().ok_or(Error::InvalidRequest)?),
                ("end", value["end"].as_str().ok_or(Error::InvalidRequest)?),
            ],
            None,
        )
        .await
    }
    async fn relay(&self, provider: &str, id: &str) -> Result<rigging_stream::ByteStream, Error>;
    async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<rigging_stream::ByteStream, Error>;
}
async fn api_json<T: serde::de::DeserializeOwned>(
    api: &(impl ProviderApi + ?Sized),
    method: Method,
    segments: &[&str],
    query: &[(&str, &str)],
    body: Option<serde_json::Value>,
) -> Result<T, Error> {
    let response = api.request(method, segments, query, body.as_ref()).await?;
    if !(200..300).contains(&response.status) {
        return Err(Error::Protocol(serde_json::from_value(response.body).map_err(|_| Error::InvalidResponse)?));
    }
    serde_json::from_value(response.body).map_err(|_| Error::InvalidResponse)
}
#[async_trait::async_trait]
impl ProviderApi for Client {
    async fn hello(&self) -> Result<Hello, Error> {
        Client::hello(self).await
    }
    async fn observe(&self, since: Option<&str>) -> Result<ObservationStream, Error> {
        let mut records = Client::observe(self, since).await?;
        Ok(Box::pin(async_stream::stream! {
            loop { match records.next().await {
                Ok(Some(record)) => yield Ok(record),
                Ok(None) => break,
                Err(error) => {yield Err(error);break;}
            }}
        }))
    }

    async fn relay(&self, provider: &str, id: &str) -> Result<rigging_stream::ByteStream, Error> {
        Client::relay(self, provider, id).await
    }
    async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<rigging_stream::ByteStream, Error> {
        Client::exec(self, provider, id, command).await
    }

    async fn request(
        &self,
        method: Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&serde_json::Value>,
    ) -> Result<WireResponse, Error> {
        self.wire_response(method, segments, query, body).await
    }
}
