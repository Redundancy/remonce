use clap::{Parser, Subcommand};
use remonce::agent;
use remonce::web;

#[derive(Parser)]
#[command(name = "remonce")]
#[command(about = "Remote Monitoring and Secure Execution")]
struct Cli {
    /// Run with a security-degraded configuration. Unlocks settings that
    /// broaden the trust surface (HTTP non-loopback OIDC issuer, OS TSA
    /// trust store, long operator_max_validity, wildcard CORS). Each
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
    }
}
