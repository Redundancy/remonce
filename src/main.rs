use clap::{Parser, Subcommand};
use remonse::agent;
use remonse::web;

#[derive(Parser)]
#[command(name = "remonse")]
#[command(about = "Remote Monitoring and Secure Execution")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the OIDC/Web Proxy Server
    Web,
    /// Run the Execution Agent
    Agent,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Web => {
            println!("Starting Web Proxy...");
            // web::run returns specialized AppError, we map it to Box<dyn Error> for main
            web::run().await.map_err(|e| e.into())
        }
        Commands::Agent => {
            println!("Starting Execution Agent...");
            agent::run().await
        }
    }
}
