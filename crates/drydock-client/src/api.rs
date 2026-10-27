//! Provider API seam shared by embedded and socket-backed callers.
use crate::{Client, Error, Method};
use drydock_protocol::*;
pub use drydock_provider::Provisioned;
use rigging_stream::ByteStream;
pub type ObservationStream = futures::stream::BoxStream<'static, Result<ObserveRecord, Error>>;

/// Provider operations. The server runtime implements them once; the HTTP
/// router adapts requests to them, and the socket client implements them over
/// HTTP for remote callers. Host configuration and credential refresh are
/// deliberately outside this API.
#[async_trait::async_trait]
pub trait ProviderApi: Send + Sync {
    /// Typed discovery with the same protocol compatibility checks as the socket client.
    async fn hello(&self) -> Result<Hello, Error>;
    async fn observe(&self, since: Option<&str>) -> Result<ObservationStream, Error>;
    async fn prepare(&self, provider: &str, request: &PrepareRequest) -> Result<Prepared, Error>;
    async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Provisioned<Environment>, Error>;
    async fn list(&self, provider: &str) -> Result<Vec<Environment>, Error>;
    async fn inspect(&self, provider: &str, id: &str) -> Result<Environment, Error>;
    async fn destroy(&self, provider: &str, id: &str) -> Result<(), Error>;
    async fn reach(&self, provider: &str, id: &str) -> Result<Reach, Error>;
    async fn suspend(&self, provider: &str, id: &str) -> Result<ResumeToken, Error>;
    async fn resume(&self, provider: &str, id: &str, token: &ResumeToken) -> Result<(), Error>;
    async fn export(&self, provider: &str, id: &str) -> Result<Export, Error>;
    async fn quota(&self, provider: &str) -> Result<Quota, Error>;
    async fn usage(&self, provider: &str, period: &Period) -> Result<Usage, Error>;
    async fn relay(&self, provider: &str, id: &str) -> Result<ByteStream, Error>;
    async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<ByteStream, Error>;
}
#[async_trait::async_trait]
impl ProviderApi for Client {
    async fn hello(&self) -> Result<Hello, Error> {
        let hello: Hello = self.call::<_, ()>(Method::GET, &["v1", "hello"], None).await?;
        if !hello.is_compatible() {
            return Err(Error::VersionMismatch);
        }
        Ok(hello)
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
    async fn prepare(&self, provider: &str, request: &PrepareRequest) -> Result<Prepared, Error> {
        self.call(Method::POST, &["v1", "providers", provider, "prepare"], Some(request)).await
    }
    async fn provision(&self, provider: &str, request: &ProvisionRequest) -> Result<Provisioned<Environment>, Error> {
        let request = self.request(Method::POST, &["v1", "providers", provider, "environments"])?.json(request);
        Ok(match self.execute_response(request).await? {
            (201, environment) => Provisioned::Created(environment),
            (_, environment) => Provisioned::Existing(environment),
        })
    }
    async fn list(&self, provider: &str) -> Result<Vec<Environment>, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments"], None).await
    }
    async fn inspect(&self, provider: &str, id: &str) -> Result<Environment, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "environments", id], None).await
    }
    async fn destroy(&self, provider: &str, id: &str) -> Result<(), Error> {
        self.call::<_, ()>(Method::DELETE, &["v1", "providers", provider, "environments", id], None).await
    }
    async fn reach(&self, provider: &str, id: &str) -> Result<Reach, Error> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "reach"], None).await
    }
    async fn suspend(&self, provider: &str, id: &str) -> Result<ResumeToken, Error> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "suspend"], None).await
    }
    async fn resume(&self, provider: &str, id: &str, token: &ResumeToken) -> Result<(), Error> {
        self.call(Method::POST, &["v1", "providers", provider, "environments", id, "resume"], Some(token)).await
    }
    async fn export(&self, provider: &str, id: &str) -> Result<Export, Error> {
        self.call::<_, ()>(Method::POST, &["v1", "providers", provider, "environments", id, "export"], None).await
    }
    async fn quota(&self, provider: &str) -> Result<Quota, Error> {
        self.call::<_, ()>(Method::GET, &["v1", "providers", provider, "quota"], None).await
    }
    async fn usage(&self, provider: &str, period: &Period) -> Result<Usage, Error> {
        Ok(self.execute_response(self.request(Method::GET, &["v1", "providers", provider, "usage"])?.query(period)).await?.1)
    }
    async fn relay(&self, provider: &str, id: &str) -> Result<ByteStream, Error> {
        self.upgrade::<()>(provider, id, "relay", "drydock-relay", None).await
    }
    async fn exec(&self, provider: &str, id: &str, command: &ExecRequest) -> Result<ByteStream, Error> {
        self.upgrade(provider, id, "exec", "drydock-stream", Some(command)).await
    }
}
