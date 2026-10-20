use clap::{Parser, Subcommand};
use drydock::{HostSpec, Supervisor, credentials::BuiltinCredentials};
use drydock_protocol::{PrepareRequest, ProvisionRequest};
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
    /// Run destructive ADR 0070 checks using a unique label from a JSON options file.
    Conformance {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        options: PathBuf,
        /// Explicit consent to provision resources and incur provider charges.
        #[arg(long)]
        live: bool,
    },
    /// Look up or build a prepared form; stdout is the JSON used by launch/conformance.
    Prepare {
        host: String,
        provider: String,
        image_digest: String,
        tools_digest: String,
    },
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
    let conformance_options = if let Command::Conformance { options, .. } = &args.command {
        let options: drydock::conformance::Options =
            serde_json::from_slice(&tokio::fs::read(options).await?).map_err(|_| "invalid conformance options")?;
        options.timeouts.validate()?;
        Some(options)
    } else {
        None
    };
    // Deliberately suppress serde diagnostics: a malformed document can contain a secret.
    let specs: Vec<HostSpec> = serde_json::from_slice(&tokio::fs::read(args.config).await?).map_err(|_| "invalid host configuration")?;
    let mut supervisor = Supervisor::new(args.runtime_directory, Arc::new(BuiltinCredentials::default()));
    if let Some(options) = &conformance_options {
        supervisor.request_timeout = Duration::from_secs(options.timeouts.request_seconds);
    }
    let selected = match &args.command {
        Command::Prepare { host, .. } | Command::List { host, .. } | Command::Launch { host, .. } | Command::Destroy { host, .. } => {
            Some(host)
        }
        _ => None,
    };
    if selected.is_some_and(|name| !specs.iter().any(|s| &s.name == name)) {
        return Err("unknown host".into());
    }
    if let Command::Conformance { provider, live, .. } = &args.command {
        let matching: Vec<_> = specs.iter().filter(|s| s.configuration.providers.iter().any(|p| &p.name == provider)).collect();
        if matching.len() != 1 {
            return Err("conformance provider must identify exactly one configured host".into());
        }
        // Provider names do not establish whether a module is hermetic.
        if !live
            && matching[0]
                .configuration
                .providers
                .iter()
                .filter(|p| &p.name == provider)
                .any(|p| !matching[0].configuration.modules.iter().any(|m| m.name == p.module && m.entrypoint == "reference"))
        {
            return Err("live-provider conformance requires --live".into());
        }
    }
    for spec in specs {
        if let Command::Conformance { provider, .. } = &args.command
            && !spec.configuration.providers.iter().any(|p| &p.name == provider)
        {
            continue;
        }
        if selected.is_some_and(|name| &spec.name != name) {
            continue;
        }
        let name = spec.name.clone();
        let mut handle = supervisor.start(spec).await?;
        let status =
            handle.ready(Duration::from_secs(conformance_options.as_ref().map_or(15, |options| options.timeouts.startup_seconds))).await;
        match &args.command {
            Command::Conformance { provider, .. } => {
                status?;
                instance_ready(&handle, provider)?;
                let options = conformance_options.as_ref().ok_or("missing conformance options")?;
                let report = drydock::conformance::run(&handle.client, provider, options).await;
                println!("{}", serde_json::to_string(&report)?);
                if !report.passed() {
                    return Err("provider failed conformance".into());
                }
            }
            Command::Prepare { provider, image_digest, tools_digest, .. } => {
                status?;
                instance_ready(&handle, provider)?;
                println!(
                    "{}",
                    serde_json::to_string(
                        &handle
                            .client
                            .prepare(provider, &PrepareRequest { image_digest: image_digest.clone(), tools_digest: tools_digest.clone() })
                            .await?
                    )?
                );
            }
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
