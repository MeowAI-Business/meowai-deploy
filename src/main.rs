mod cli;
mod commands;
mod config;
mod doctor;
mod error;
mod pricing;
mod registry;
mod security;
pub mod source;
mod source_key_store;
mod state;
mod storage;
mod target;
mod updater;

use std::env;

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

    fn format_footer(&self, state: &ThemeState) -> String {
        match state {
            ThemeState::Submit => "\n".to_owned(),
            ThemeState::Active => format!("{}\n", style("└").cyan()),
            ThemeState::Cancel => format!("{}  Operation cancelled.\n", style("└").red()),
            ThemeState::Error(message) => {
                format!("{}  {}\n", style("└").yellow(), style(message).yellow())
            }
        }
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
    let log_filter = || {
        tracing_subscriber::EnvFilter::try_new(env::var("MEOWAI_DEPLOY_LOG").unwrap_or_else(|_| {
            "meowai_deploy=debug,reqwest=warn,hyper=warn,h2=warn,rustls=warn".to_owned()
        }))
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("meowai_deploy=debug"))
    };
    if let Ok(log_file) = storage::open_log_file() {
        tracing_subscriber::fmt()
            .with_env_filter(log_filter())
            .with_writer(log_file)
            .with_target(false)
            .with_ansi(false)
            .try_init()
            .ok();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(log_filter())
            .with_target(false)
            .try_init()
            .ok();
    }

    let cli = Cli::parse();
    commands::run(cli).await
}
