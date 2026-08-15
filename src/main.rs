mod cli;
mod commands;
mod config;
mod doctor;
mod error;
mod pricing;
mod security;
pub mod source;
mod state;
mod storage;
mod target;

use clap::Parser;
use cli::Cli;
use cliclack::{Theme, ThemeState};
use console::{Style, style};
use error::{AppError, Result};

struct MeowAiTheme;

impl Theme for MeowAiTheme {
    fn state_symbol_color(&self, state: &ThemeState) -> Style {
        match state {
            ThemeState::Submit => Style::new().cyan(),
            _ => self.bar_color(state),
        }
    }

    fn radio_symbol(&self, state: &ThemeState, selected: bool) -> String {
        match state {
            ThemeState::Active if selected => style("●").cyan().to_string(),
            ThemeState::Active => style("○").dim().to_string(),
            _ => String::new(),
        }
    }

    fn active_symbol(&self) -> String {
        style("◆").cyan().to_string()
    }

    fn submit_symbol(&self) -> String {
        style("◇").cyan().to_string()
    }
}

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
    cliclack::set_theme(MeowAiTheme);
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
