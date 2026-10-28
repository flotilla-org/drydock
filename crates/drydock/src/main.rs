use clap::{Parser, Subcommand};
use drydock::{
    api::ProviderApi,
    client::{Client, Method},
    config::resolve_paths,
    launch::LaunchOptions,
};
use serde::de::DeserializeOwned;
use std::{path::PathBuf, time::Duration};
#[derive(Parser)]
#[command(about = "Launch and manage environments through the drydock daemon")]
struct Args {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    Providers,
    List {
        provider: String,
    },
    Prepare {
        provider: String,
        #[command(flatten)]
        options: LaunchOptions,
    },
    Launch {
        provider: String,
        #[command(flatten)]
        options: LaunchOptions,
    },
    Inspect {
        provider: String,
        id: String,
    },
    Shell {
        provider: String,
        id: String,
    },
    Destroy {
        provider: String,
        id: String,
    },
    /// Run destructive ADR 0070 checks against a configured provider.
    Conformance {
        #[arg(long)]
        provider: String,
        #[arg(long)]
        options: PathBuf,
        #[arg(long)]
        live: bool,
    },
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
async fn call<T: DeserializeOwned>(
    client: &Client,
    method: Method,
    path: &[&str],
    body: Option<&serde_json::Value>,
) -> Result<T, Box<dyn std::error::Error>> {
    let (status, body) = client.wire(method, path, &[], body).await?;
    if !(200..300).contains(&status) {
        return Err(drydock::client::Error::Protocol(serde_json::from_value(body)?).into());
    }
    Ok(serde_json::from_value(body)?)
}
async fn progress<T>(message: &str, operation: impl std::future::Future<Output = T>) -> T {
    eprintln!("{message}");
    tokio::pin!(operation);
    loop {
        tokio::select! { value = &mut operation => return value, _ = tokio::time::sleep(Duration::from_secs(2)) => eprintln!("Still preparing the provider image and environment…") }
    }
}
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let (config, socket) = resolve_paths(args.config, args.socket, &rigging_process::ProcessEnvVars)?;
    let client = drydock::local::connect(&std::path::absolute(config)?, &std::path::absolute(socket)?)
        .await?
        .with_request_timeout(Duration::from_secs(600));
    let launch = matches!(args.command, Command::Launch { .. });
    let output = match args.command {
        Command::Providers => call(&client, Method::GET, &["v1", "providers"], None).await?,
        Command::List { provider } => serde_json::to_value(client.list(&provider).await?)?,
        Command::Inspect { provider, id } => serde_json::to_value(client.inspect(&provider, &id).await?)?,
        Command::Prepare { provider, options } | Command::Launch { provider, options } => {
            let body = serde_json::to_value(options)?;
            progress(
                if launch { "Preparing image and launching environment…" } else { "Preparing image…" },
                call(&client, Method::POST, &["v1", "providers", &provider, if launch { "launch" } else { "prepare" }], Some(&body)),
            )
            .await?
        }
        Command::Destroy { provider, id } => {
            client.destroy(&provider, &id).await?;
            return Ok(());
        }
        Command::Shell { provider, id } => {
            let session: drydock::shell::Session =
                call(&client, Method::POST, &["v1", "providers", &provider, "environments", &id, "shell"], None).await?;
            let status = drydock::shell::SshCommand::new(session)?.run().await?;
            if !status.success() {
                return Err("SSH session failed".into());
            }
            return Ok(());
        }
        Command::Conformance { provider, options, live } => {
            let options: drydock::conformance::Options =
                serde_json::from_slice(&tokio::fs::read(options).await?).map_err(|_| "invalid conformance options")?;
            options.timeouts.validate()?;
            let declaration = client.provider(&provider).await?;
            if !live && declaration.module != "reference" {
                return Err("live-provider conformance requires --live".into());
            }
            if options.billing_settle_millis > 0 {
                eprintln!("Billing checks wait {} ms after each sample for vendor accounting to settle.", options.billing_settle_millis);
            }
            let report = drydock::conformance::run(
                &client.clone().with_request_timeout(Duration::from_secs(options.timeouts.request_seconds)),
                &provider,
                &options,
            )
            .await;
            println!("{}", serde_json::to_string(&report)?);
            if !report.passed() {
                return Err("provider failed conformance".into());
            }
            return Ok(());
        }
    };
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}
