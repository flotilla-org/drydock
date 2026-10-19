use drydock_host::{Host, reference};
#[tokio::main]
async fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut host = Host::new(reference::registry());
    if let Ok(path) = std::env::var("DRYDOCK_PROXY_CA") {
        host = host.with_proxy_ca(std::fs::read(path)?);
    }
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    match args.as_slice() {
        [flag, path] if flag == "--unix" => {
            // SAFETY: geteuid has no preconditions.
            host.serve_unix(path, unsafe { libc::geteuid() }, shutdown)
                .await
        }
        [flag, address, token_flag, path] if flag == "--tcp" && token_flag == "--token-file" => {
            host.serve_tcp(
                address.parse().map_err(std::io::Error::other)?,
                path,
                shutdown,
            )
            .await
        }
        _ => Err(std::io::Error::other(
            "usage: drydock-host --unix PATH | --tcp LOOPBACK:PORT --token-file PATH",
        )),
    }
}
