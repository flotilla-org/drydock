use clap::{Parser, Subcommand};
use drydock::{HostSpec, Supervisor, credentials::BuiltinCredentials};
use drydock_protocol::ProvisionRequest;
use std::{path::PathBuf, sync::Arc, time::Duration};

#[derive(Parser)]
#[command(about = "Drive configured language hosts without a store")]
struct Args {
    #[arg(long)]
    config: PathBuf,
    #[arg(long)]
    runtime_directory: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Hosts,
    Instances,
    List {
        host: String,
        provider: String,
    },
    /// Provision from a JSON ProvisionRequest, including an already prepared image.
    Launch {
        host: String,
        provider: String,
        request: PathBuf,
    },
    Destroy {
        host: String,
        provider: String,
        id: String,
    },
}
#[tokio::main]
async fn main() -> std::process::ExitCode {
    match run().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    // Deliberately suppress serde diagnostics: a malformed document can contain a secret.
    let specs: Vec<HostSpec> = serde_json::from_slice(&tokio::fs::read(args.config).await?).map_err(|_| "invalid host configuration")?;
    let supervisor = Supervisor::new(args.runtime_directory, Arc::new(BuiltinCredentials::default()));
    let selected = match &args.command {
        Command::List { host, .. } | Command::Launch { host, .. } | Command::Destroy { host, .. } => Some(host),
        _ => None,
    };
    if selected.is_some_and(|name| !specs.iter().any(|s| &s.name == name)) {
        return Err("unknown host".into());
    }
    for spec in specs {
        if selected.is_some_and(|name| &spec.name != name) {
            continue;
        }
        let name = spec.name.clone();
        let mut handle = supervisor.start(spec).await?;
        let status = handle.ready(Duration::from_secs(15)).await;
        match &args.command {
            Command::Hosts => {
                let current = handle.status.borrow().clone();
                println!("{}", serde_json::json!({"host":name,"readiness":current.readiness}));
            }
            Command::Instances => {
                for (provider, readiness) in handle.instances() {
                    println!("{}", serde_json::json!({"host":name,"instance":provider,"readiness":readiness}));
                }
            }
            Command::List { provider, .. } => {
                let status = status?;
                instance_ready(&handle, provider)?;
                let cache = drydock::client::StatusCache::new(handle.client.clone(), &status.providers);
                println!("{}", serde_json::to_string(&cache.list(provider).await?)?);
            }
            Command::Launch { provider, request, .. } => {
                status?;
                instance_ready(&handle, provider)?;
                let request: ProvisionRequest =
                    serde_json::from_slice(&tokio::fs::read(request).await?).map_err(|_| "invalid launch request")?;
                println!("{}", serde_json::to_string(&handle.client.provision(provider, &request).await?)?);
            }
            Command::Destroy { provider, id, .. } => {
                status?;
                instance_ready(&handle, provider)?;
                handle.client.destroy(provider, id).await?;
            }
        }
    }
    Ok(())
}

fn instance_ready(handle: &drydock::HostHandle, provider: &str) -> Result<(), drydock::client::Error> {
    match handle.instances().remove(provider) {
        Some(drydock_protocol::Readiness::Ready) => Ok(()),
        Some(readiness) => Err(drydock::client::Error::NotReady(readiness)),
        None => Err(drydock::client::Error::NotReady(drydock_protocol::Readiness::Unknown { reason: "instance not configured".into() })),
    }
}
