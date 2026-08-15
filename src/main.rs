mod cli;
mod commands;
mod config;
mod doctor;
mod error;
mod pricing;
mod security;
pub mod source;
mod state;
mod target;

use clap::Parser;
use cli::Cli;
use error::{AppError, Result};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        if !matches!(error, AppError::Cancelled) {
            eprintln!("error: {error}");
        }
        std::process::exit(error.exit_code());
    }
}

async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_target(false)
        .try_init()
        .ok();

    let cli = Cli::parse();
    commands::run(cli).await
}
