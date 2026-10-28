// The one fake provider shared by the bridge, loader and runtime tests.
#![allow(dead_code)]
use drydock_host::module::{HttpClient, Provisioned};
use drydock_host::reference;
use drydock_protocol::*;
use std::time::Duration;

#[derive(Default)]
pub struct Control {
    pub execute_http: std::sync::atomic::AtomicBool,
    pub disable_exec: std::sync::atomic::AtomicBool,
    pub skip_list_timestamp: std::sync::atomic::AtomicBool,
    pub skip_egress_measurement: std::sync::atomic::AtomicBool,
    pub timestamp: std::sync::Mutex<Option<chrono::DateTime<chrono::Utc>>>,
    pub global_limit: std::sync::atomic::AtomicBool,
    pub list_limit: std::sync::atomic::AtomicU32,
    pub list_period: std::sync::atomic::AtomicU64,
    pub entered: tokio::sync::Notify,
    pub release: tokio::sync::Notify,

    pub hold_list: std::sync::atomic::AtomicBool,
    pub hold_list_result: std::sync::atomic::AtomicBool,
    pub list_result_ready: tokio::sync::Notify,
    pub list_result_release: tokio::sync::Notify,
    pub list_entered: tokio::sync::Notify,
    pub list_release: tokio::sync::Notify,
    pub vendor: std::sync::Mutex<VendorState>,
    pub list_held: tokio::sync::Notify,
    pub http_url: std::sync::Mutex<Option<String>>,
    pub reject_list: std::sync::atomic::AtomicBool,
    pub missing_tool: std::sync::atomic::AtomicBool,
    pub dropped: tokio::sync::Notify,
    pub hold_destroy: std::sync::atomic::AtomicBool,
    pub fail_destroy: std::sync::atomic::AtomicBool,
    pub fail_inspect: std::sync::atomic::AtomicBool,
    pub destroy_entered: tokio::sync::Notify,
    pub destroy_release: tokio::sync::Notify,
    pub hold_success: std::sync::atomic::AtomicBool,
    pub success_entered: tokio::sync::Notify,
    pub success_release: tokio::sync::Notify,
    pub list_calls: std::sync::atomic::AtomicUsize,
    /// The credential each list call carried.
    pub list_credentials: std::sync::Mutex<Vec<Option<String>>>,
    pub configured: std::sync::atomic::AtomicUsize,
    pub slow_configure: std::sync::atomic::AtomicBool,
}
#[derive(Default)]
pub struct VendorState {
    pub row: Option<Environment>,
    pub error: bool,
}
pub struct ControlledModule(pub std::sync::Arc<Control>);
pub struct ControlledProvider {
    http: std::sync::Arc<dyn HttpClient>,
    inner: std::sync::Arc<dyn drydock_host::module::Provider>,
    control: std::sync::Arc<Control>,
}
impl Drop for ControlledProvider {
    fn drop(&mut self) {
        self.control.dropped.notify_one();
    }
}
// The gate and error flag stand in for the vendor network boundary; all resource
// behavior is delegated to the real reference provider, through real HTTP sockets.
#[async_trait::async_trait]
impl drydock_host::module::Module for ControlledModule {
    fn version(&self) -> &str {
        "test"
    }
    async fn configure(
        &self,
        name: &str,
        c: &ProviderConfiguration,
        http: std::sync::Arc<dyn HttpClient>,
    ) -> drydock_host::module::Result<std::sync::Arc<dyn drydock_host::module::Provider>> {
        self.0.configured.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.0.slow_configure.load(std::sync::atomic::Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let inner = drydock_host::module::Module::configure(&reference::ReferenceModule, name, c, http.clone()).await?;
        Ok(std::sync::Arc::new(ControlledProvider { inner, http, control: self.0.clone() }))
    }
}
#[async_trait::async_trait]
impl drydock_host::module::Provider for ControlledProvider {
    fn readiness(&self, c: &drydock_host::module::Credentials) -> Readiness {
        if self.control.missing_tool.load(std::sync::atomic::Ordering::SeqCst) {
            Readiness::MissingTool { reason: "test tool absent".into() }
        } else {
            self.inner.readiness(c)
        }
    }

    fn observation(&self) -> ObservationMode {
        ObservationMode::Poll { interval_ms: 10 }
    }
    fn rate_limits(&self) -> Vec<RateLimit> {
        let requests = self.control.list_limit.load(std::sync::atomic::Ordering::SeqCst);
        if requests == 0 {
            vec![]
        } else {
            vec![RateLimit {
                operation: if self.control.global_limit.load(std::sync::atomic::Ordering::SeqCst) { "*" } else { "list" }.into(),
                requests,
                period_seconds: self.control.list_period.load(std::sync::atomic::Ordering::SeqCst).max(1),
            }]
        }
    }
    fn operations(&self) -> drydock_host::module::Operations<'_> {
        drydock_host::module::Operations {
            exec: if self.control.disable_exec.load(std::sync::atomic::Ordering::SeqCst) { None } else { self.inner.operations().exec },
            ..self.inner.operations()
        }
    }
    fn capabilities(&self) -> Capabilities {
        let mut capabilities = self.inner.capabilities();
        capabilities.fallback_runner = !self.control.disable_exec.load(std::sync::atomic::Ordering::SeqCst);
        capabilities
    }
    async fn prepare(&self, r: PrepareRequest, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Prepared> {
        if self.control.hold_success.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.control.success_entered.notify_one();
            self.control.success_release.notified().await;
        }
        if c.token().is_some_and(|t| t.expose() == "old") {
            self.control.entered.notify_one();
            self.control.release.notified().await;
            return Err(ProtocolError::CredentialRejected { reason: "old credential rejected".into() });
        }
        if self.control.execute_http.load(std::sync::atomic::Ordering::SeqCst) {
            let url = self.control.http_url.lock().unwrap().clone().unwrap_or_else(|| "https://vendor.example/prepare".into());
            let mut request = reqwest::Request::new(reqwest::Method::GET, url.parse().unwrap());
            request.headers_mut().insert("Authorization", format!("Bearer {}", c.token().unwrap().expose()).parse().unwrap());
            let response = self
                .http
                .execute(request, &rigging_http_client::http_channel_label("GET", &url))
                .await
                .map_err(|_| ProtocolError::unavailable("transport failure", None))?;
            if response.status() == 401 {
                return Err(ProtocolError::CredentialRejected { reason: "vendor rejected credential".into() });
            }
            assert!(response.status().is_success());
        }
        self.inner.prepare(r, c).await
    }
    async fn provision(&self, r: ProvisionRequest, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Provisioned> {
        self.inner.provision(r, c).await
    }
    async fn list(&self, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Vec<Environment>> {
        use std::sync::atomic::Ordering::SeqCst;
        self.control.list_credentials.lock().unwrap().push(c.token().map(|token| token.expose().to_owned()));
        if self.control.hold_list.load(SeqCst) {
            self.control.list_held.notify_one();
            self.control.list_release.notified().await;
        }
        let mut rows = self.inner.list(c).await?;
        // Capture the complete external response atomically: failure and inventory
        // can never come from two different vendor revisions.
        let vendor = {
            let state = self.control.vendor.lock().unwrap();
            (state.error, state.row.clone())
        };
        self.control.list_calls.fetch_add(1, SeqCst);
        self.control.list_entered.notify_waiters();
        if self.control.reject_list.load(SeqCst) {
            return Err(ProtocolError::CredentialRejected { reason: "vendor credential rejected".into() });
        }
        if vendor.0 {
            return Err(ProtocolError::unavailable("vendor unavailable", None));
        }
        if let Some(row) = vendor.1 {
            rows.push(Environment {
                egress_measured: !self.control.skip_egress_measurement.load(SeqCst),
                timestamp: if self.control.skip_list_timestamp.load(SeqCst) {
                    None
                } else {
                    self.control.timestamp.lock().unwrap().map(Into::into)
                },
                ..row
            });
        }
        if self.control.hold_list_result.swap(false, SeqCst) {
            self.control.list_result_ready.notify_one();
            self.control.list_result_release.notified().await;
        }
        Ok(rows)
    }
    async fn inspect(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Environment> {
        if self.control.fail_inspect.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(ProtocolError::unavailable("vendor unavailable", None));
        }
        if let Some(row) = self.control.vendor.lock().unwrap().row.clone().filter(|row| row.id == id) {
            return Ok(Environment { egress_measured: true, timestamp: self.control.timestamp.lock().unwrap().map(Into::into), ..row });
        }
        self.inner.inspect(id, c).await
    }
    async fn destroy(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<()> {
        self.inner.destroy(id, c).await?;
        if self.control.hold_destroy.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.control.destroy_entered.notify_one();
            self.control.destroy_release.notified().await;
        }
        if self.control.fail_destroy.load(std::sync::atomic::Ordering::SeqCst) {
            Err(ProtocolError::unavailable("ambiguous vendor failure", None))
        } else {
            Ok(())
        }
    }
    async fn reach(&self, id: &str, c: &drydock_host::module::Credentials) -> drydock_host::module::Result<Reach> {
        self.inner.reach(id, c).await
    }
    async fn relay(
        &self,
        id: &str,
        c: &drydock_host::module::Credentials,
    ) -> drydock_host::module::Result<drydock_host::module::ByteStream> {
        self.inner.relay(id, c).await
    }
}
