use clap::{Parser, Subcommand};
use remonce::agent;
use remonce::web;

#[derive(Parser)]
#[command(name = "remonce")]
#[command(about = "Remote monitor and command execution: run approved commands on a host")]
struct Cli {
    /// Run with a security-degraded configuration. Unlocks settings that
    /// broaden the trust surface (HTTP non-loopback OIDC issuer, OS TSA
    /// trust store, long approval_validity, wildcard CORS). Each
    /// active gate is logged at startup and every audit entry includes
    /// `insecure: true`.
    #[arg(long, global = true)]
    insecure: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the OIDC/Web Proxy Server (signer)
    Web,
    /// Run the Execution Agent (remote executor)
    Agent,
    /// Add your approval to a request (one fresh login per signature)
    Approve {
        /// Path to the request file (with or without approvals), or '-' for stdin
        #[arg(long, short = 'b')]
        bundle: String,
        /// Write the approved request to this file instead of stdout
        #[arg(long, short = 'o')]
        output: Option<String>,
    },
    /// Run an approved request on an agent; you are logged in as the executor
    Submit {
        /// Path to the approved request file, or '-' for stdin
        #[arg(long, short = 'b')]
        bundle: String,
        /// Agent URL to submit to (defaults to `agent_url` from config.toml)
        #[arg(long)]
        agent: Option<String>,
    },
    /// Run the central revocation service (persistent, estate-wide revocations)
    RevocationService,
    /// Revoke (cancel) an approved request on an agent
    Revoke {
        /// Path to the approved request file, or '-' for stdin
        #[arg(long, short = 'b')]
        bundle: String,
        /// Agent URL to submit to (defaults to `agent_url` from config.toml)
        #[arg(long)]
        agent: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Web => {
            println!("Starting Web Proxy...");
            web::run(cli.insecure).await.map_err(|e| e.into())
        }
        Commands::Agent => {
            println!("Starting Execution Agent...");
            agent::run(cli.insecure).await
        }
        Commands::RevocationService => {
            println!("Starting Revocation Service...");
            remonce::revocation::run(cli.insecure).await
        }
        Commands::Approve { bundle, output } => {
            remonce::cli::run_approve(remonce::cli::ApproveArgs { bundle, output }, cli.insecure).await
        }
        Commands::Submit { bundle, agent } => {
            remonce::cli::run_submit(remonce::cli::SubmitArgs { bundle, agent }, cli.insecure).await
        }
        Commands::Revoke { bundle, agent } => {
            remonce::cli::run_revoke(remonce::cli::RevokeArgs { bundle, agent }, cli.insecure).await
        }
    }
}
