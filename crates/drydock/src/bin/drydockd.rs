use clap::Parser;
use drydock::{
    config::{Config, resolve_paths},
    daemon::{Daemon, HostOption},
    local,
};
use std::path::PathBuf;
#[derive(Parser)]
#[command(about = "Supervise drydock providers and serve the provider API")]
struct Args {
    #[arg(long)]
    config: Option<PathBuf>,
    #[arg(long)]
    socket: Option<PathBuf>,
    /// Use these externally owned hosts instead of installed companions. Never part of provider configuration.
    #[arg(long)]
    external_host: Vec<PathBuf>,
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<(), String> {
    let args = Args::parse();
    let (config, socket) = resolve_paths(args.config, args.socket, &rigging_process::ProcessEnvVars)?;
    let socket = std::path::absolute(socket).map_err(|e| e.to_string())?;
    let run = socket.parent().ok_or("socket needs parent directory")?;
    local::private_dir(run)?;
    let _lock = local::lock(&local::socket_lock_path(&socket, ".lock"))?;
    _lock.try_lock().map_err(|_| "another daemon owns this socket")?;
    let mut options = if args.external_host.is_empty() { HostOption::installed().await? } else { Vec::new() };
    for (i, path) in args.external_host.into_iter().enumerate() {
        options.push(HostOption {
            optional: false,
            name: format!("external-{i}"),
            connection: drydock::HostConnection::ExternalUnix { path },
        });
    }
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).map_err(|e| e.to_string())?;
    let daemon = Daemon::start(Config::load(&config).await?, run, run.join("keys"), options).await?;
    daemon
        .serve(&socket, async move {
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = terminate.recv() => {} }
        })
        .await
        .map_err(|e| e.to_string())
}
