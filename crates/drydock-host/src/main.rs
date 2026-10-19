use drydock_host::{Host, reference};
#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with_ansi(false)
        .with_writer(std::io::stderr)
        .init();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut host = Host::new(reference::registry());
    if let Ok(path) = std::env::var("DRYDOCK_PROXY_CA") {
        host = host.with_proxy_ca(std::fs::read(path)?);
    }
    // Register SIGTERM before binding so managed shutdown always drains streams.
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
    };
    match args.as_slice() {
        [flag, path] if flag == "--unix" => {
            // SAFETY: geteuid has no preconditions.
            host.serve_unix(path, unsafe { libc::geteuid() }, shutdown).await
        }
        [flag, address, token_flag, path] if flag == "--tcp" && token_flag == "--token-file" => {
            host.serve_tcp(address.parse().map_err(std::io::Error::other)?, path, shutdown).await
        }
        _ => Err(std::io::Error::other("usage: drydock-host --unix PATH | --tcp LOOPBACK:PORT --token-file PATH")),
    }
}
