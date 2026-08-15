use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

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
    /// Start the local browser deployment workbench.
    Web(WebArgs),
    /// Check local or target-host prerequisites.
    Doctor(DoctorArgs),
    /// Start the interactive onboard workflow.
    Onboard(OnboardArgs),
    /// Synchronize source groups, status and downstream resources.
    Sync(SyncArgs),
    /// Show the current deployment state.
    Status(DeploymentArgs),
    /// Remove downstream services and data while preserving local onboard state.
    Clean(CleanArgs),
    /// Remove resources created by this deployment.
    Rollback(RollbackArgs),
    /// Remove locally stored session credentials.
    Logout(DeploymentArgs),
    /// Check for or install a newer meowai-deploy release.
    Update(UpdateArgs),
}

#[derive(Debug, Args)]
pub struct WebArgs {
    /// Print the loopback URL without opening a browser.
    #[arg(long)]
    pub no_open: bool,
}

#[derive(Debug, Args)]
pub struct DeploymentArgs {}

#[derive(Debug, Args)]
pub struct CleanArgs {
    /// Confirm deletion of downstream containers, generated files, and data.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct UpdateArgs {
    /// Check the latest release without replacing the current binary.
    #[arg(long)]
    pub check: bool,

    /// Install an available update without asking for confirmation.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    /// Re-import current source pricing, Seedance, and marketplace settings.
    #[arg(long)]
    pub pricing: bool,

    /// Apply managed configuration changes even when a drift was detected.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct RollbackArgs {
    /// Confirm deletion of the downstream Compose project and its bind-mounted data.
    #[arg(long)]
    pub yes: bool,

    /// Also revoke this source account's group Tokens and public status Key.
    #[arg(long)]
    pub revoke_source: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Directory whose parent will receive the deployment data.
    #[arg(long, default_value = "/opt/meowai-deploy/newapi")]
    pub directory: PathBuf,

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
