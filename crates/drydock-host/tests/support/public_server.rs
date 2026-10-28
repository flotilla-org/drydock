// Serve the main-server runtime through the production public router for the
// existing HTTP harnesses, including the server-only credential route.
#![allow(dead_code)]
use drydock::runtime::Runtime;

/// Shutdown stops the runtime first, ending its streams, then drains HTTP.
pub async fn serve_unix(
    runtime: Runtime,
    path: impl AsRef<std::path::Path>,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> std::io::Result<()> {
    let stop = runtime.shutdown(shutdown);
    let router = drydock::api::server_router(std::sync::Arc::new(runtime.clone()), runtime.stopping());
    rigging_http_serve::UnixServer::bind(path, 0o600).await?.serve(router, rigging_http_serve::Caller::<()>::Unix, stop).await
}
pub async fn client(runtime: Runtime, path: std::path::PathBuf) -> drydock::client::Client {
    use drydock::api::ProviderApi;
    let client = drydock::client::Client::unix(&path).unwrap();
    tokio::spawn(serve_unix(runtime, path, std::future::pending()));
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while client.hello().await.is_err() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    client
}
