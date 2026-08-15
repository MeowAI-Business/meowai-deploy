use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use crate::config::DEFAULT_SOURCE_URL;

#[derive(Debug, Parser)]
#[command(
    name = "meowai-deploy",
    version,
    about = "Deploy and operate a downstream New API site",
    long_about = "meowai-deploy is the Rust CLI for the MeowAI onboard workflow."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check local or target-host prerequisites.
    Doctor(DoctorArgs),
    /// Start the interactive onboard workflow.
    Onboard(OnboardArgs),
    /// Synchronize source groups, status and downstream resources.
    Sync(SyncArgs),
    /// Show the current deployment state.
    Status(DeploymentArgs),
    /// Remove resources created by this deployment.
    Rollback(RollbackArgs),
    /// Remove locally stored session credentials.
    Logout(DeploymentArgs),
}

#[derive(Debug, Args)]
pub struct DeploymentArgs {
    /// Deployment directory containing deployment.toml and state.json.
    #[arg(long, default_value = "/opt/meowai-deploy/newapi")]
    pub directory: PathBuf,
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    #[command(flatten)]
    pub deployment: DeploymentArgs,

    /// Re-import the bundled pricing snapshots. By default pricing is left untouched.
    #[arg(long)]
    pub pricing: bool,

    /// Apply managed configuration changes even when a drift was detected.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    #[command(flatten)]
    pub deployment: DeploymentArgs,

    /// Confirm deletion of the downstream Compose project and its bind-mounted data.
    #[arg(long)]
    pub yes: bool,

    /// Also revoke this deployment's source Tokens and public status Key.
    #[arg(long)]
    pub revoke_source: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Source URL used for the connectivity check.
    #[arg(long, default_value = DEFAULT_SOURCE_URL)]
    pub source_url: String,

    /// Directory whose parent will receive the deployment data.
    #[arg(long, default_value = "/opt/meowai-deploy/newapi")]
    pub directory: PathBuf,

    /// Do not make the source connectivity request.
    #[arg(long)]
    pub skip_network: bool,

    /// Print machine-readable JSON instead of a terminal table.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("target")
        .args(["local", "ssh"])
        .required(false)
        .multiple(false)
))]
pub struct OnboardArgs {
    /// Run against the current host (the default).
    #[arg(long)]
    pub local: bool,

    /// Run against an SSH target such as user@example.com.
    #[arg(long)]
    pub ssh: Option<String>,

    /// Load non-interactive values from a TOML file.
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Skip prompts and require all values to be present in the config file.
    #[arg(long)]
    pub non_interactive: bool,

    /// Validate and print the resolved plan without performing deployment.
    #[arg(long)]
    pub dry_run: bool,

    /// Write a non-secret TOML configuration template and exit.
    #[arg(long, value_name = "FILE")]
    pub write_config: Option<PathBuf>,
}
