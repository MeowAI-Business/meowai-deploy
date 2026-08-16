use std::{env, io::IsTerminal};

use cliclack::confirm;
use console::style;
use self_update::{backends::github, update::ReleaseUpdate};
use serde::{Deserialize, Serialize};

use crate::{
    cli::UpdateArgs,
    error::{AppError, Result},
    state::unix_timestamp,
    storage::{self, UPDATE_CHECK_FILE},
};

const REPOSITORY_OWNER: &str = "MeowAI-Business";
const REPOSITORY_NAME: &str = "meowai-deploy";
const UPDATE_INTERVAL_SECONDS: i64 = 24 * 60 * 60;

#[derive(Clone, Debug, Deserialize, Serialize)]
struct UpdateCheckState {
    checked_at: i64,
    latest_version: Option<String>,
}

struct LatestRelease {
    version: String,
}

pub async fn run(args: &UpdateArgs) -> Result<()> {
    let latest = fetch_latest_release().await?;
    let current = env!("CARGO_PKG_VERSION");
    let available = is_newer(current, &latest.version)?;
    print_versions(current, &latest.version, available);
    persist_check(Some(latest.version.clone()))?;

    if args.check || !available {
        return Ok(());
    }
    if cfg!(debug_assertions) {
        return Err(AppError::Message(
            "development builds only support `meowai-deploy update --check`; install a release build before self-updating"
                .to_owned(),
        ));
    }
    release_target(env::consts::OS, env::consts::ARCH)?;
    if !args.yes {
        let confirmed = confirm(format!("更新到 v{}？", latest.version))
            .initial_value(true)
            .interact()
            .map_err(AppError::from_prompt)?;
        if !confirmed {
            return Err(AppError::Cancelled);
        }
    }

    let version = latest.version.clone();
    tokio::task::spawn_blocking(move || install_release(&version))
        .await
        .map_err(|error| AppError::Message(format!("update task failed: {error}")))??;
    println!();
    println!(
        "{} {}",
        style("✓").green(),
        style(format!("已更新到 v{}", latest.version)).bold()
    );
    println!();
    Ok(())
}

pub async fn check_periodically() {
    if cfg!(debug_assertions)
        || !std::io::stderr().is_terminal()
        || env::var_os("MEOWAI_DEPLOY_DISABLE_UPDATE_CHECK").is_some()
        || !check_is_due()
    {
        return;
    }
    match fetch_latest_release().await {
        Ok(latest) => {
            let current = env!("CARGO_PKG_VERSION");
            if is_newer(current, &latest.version).unwrap_or(false) {
                eprintln!();
                eprintln!(
                    "{}",
                    style(format!(
                        "meowai-deploy v{} 可用（当前 v{}）；运行 `meowai-deploy update` 自动更新。",
                        latest.version, current
                    ))
                    .yellow()
                );
                eprintln!();
            }
            let _ = persist_check(Some(latest.version));
        }
        Err(_) => {
            let _ = persist_check(None);
        }
    }
}

async fn fetch_latest_release() -> Result<LatestRelease> {
    tokio::task::spawn_blocking(|| {
        let updater = update_builder(false)?;
        let release = updater
            .get_latest_release()
            .map_err(|error| AppError::Message(format!("check GitHub release: {error}")))?;
        Ok(LatestRelease {
            version: release.version,
        })
    })
    .await
    .map_err(|error| AppError::Message(format!("release check task failed: {error}")))?
}

fn install_release(version: &str) -> Result<()> {
    let mut builder = github::Update::configure();
    configure_builder(&mut builder)?;
    let updater = builder
        .target_version_tag(&format!("v{version}"))
        .show_download_progress(true)
        .show_output(false)
        .no_confirm(true)
        .build()
        .map_err(|error| AppError::Message(format!("configure updater: {error}")))?;
    let status = updater
        .update_extended()
        .map_err(|error| AppError::Message(format!("install update: {error}")))?;
    if !status.updated() {
        return Err(AppError::Message(
            "the selected release did not update the current binary".to_owned(),
        ));
    }
    Ok(())
}

fn update_builder(show_output: bool) -> Result<Box<dyn ReleaseUpdate>> {
    let mut builder = github::Update::configure();
    configure_builder(&mut builder)?;
    builder
        .show_output(show_output)
        .no_confirm(true)
        .build()
        .map_err(|error| AppError::Message(format!("configure updater: {error}")))
}

fn configure_builder(builder: &mut github::UpdateBuilder) -> Result<()> {
    let target = release_target(env::consts::OS, env::consts::ARCH)?;
    let archive_binary = archive_binary_name();
    builder
        .repo_owner(REPOSITORY_OWNER)
        .repo_name(REPOSITORY_NAME)
        .bin_name(archive_binary)
        .bin_path_in_archive(archive_binary)
        .target(target)
        .current_version(env!("CARGO_PKG_VERSION"));
    if let Ok(url) = env::var("MEOWAI_DEPLOY_GITHUB_API_URL") {
        builder.with_url(url.trim_end_matches('/'));
    }
    if let Ok(token) = env::var("GITHUB_TOKEN") {
        builder.auth_token(&token);
    }
    Ok(())
}

fn release_target(operating_system: &str, architecture: &str) -> Result<&'static str> {
    match (operating_system, architecture) {
        ("linux", "x86_64") => Ok("linux-amd64"),
        ("linux", "aarch64") => Ok("linux-arm64"),
        ("macos", "x86_64") => Ok("macos-amd64"),
        ("macos", "aarch64") => Ok("macos-arm64"),
        ("windows", "x86_64") => Ok("windows-amd64"),
        _ => Err(AppError::Message(format!(
            "automatic updates do not support {operating_system}/{architecture}"
        ))),
    }
}

fn archive_binary_name() -> &'static str {
    if cfg!(windows) {
        "meowai-deploy.exe"
    } else {
        "meowai-deploy"
    }
}

fn is_newer(current: &str, latest: &str) -> Result<bool> {
    self_update::version::bump_is_greater(current, latest)
        .map_err(|error| AppError::Message(format!("compare release versions: {error}")))
}

fn check_is_due() -> bool {
    let Some(content) = storage::read(UPDATE_CHECK_FILE).ok().flatten() else {
        return true;
    };
    let Ok(state) = serde_json::from_slice::<UpdateCheckState>(&content) else {
        return true;
    };
    unix_timestamp().saturating_sub(state.checked_at) >= UPDATE_INTERVAL_SECONDS
}

fn persist_check(latest_version: Option<String>) -> Result<()> {
    let content = serde_json::to_vec_pretty(&UpdateCheckState {
        checked_at: unix_timestamp(),
        latest_version,
    })
    .map_err(|error| AppError::State(format!("serialize update-check.json: {error}")))?;
    storage::write(UPDATE_CHECK_FILE, &content)
}

fn print_versions(current: &str, latest: &str, available: bool) {
    println!();
    println!("{}", style("CLI 版本").bold());
    println!("  当前版本  v{current}");
    println!("  最新版本  v{latest}");
    println!(
        "  状态      {}",
        if available {
            style("有可用更新").yellow().to_string()
        } else {
            style("已是最新版本").green().to_string()
        }
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_versions_are_compared_without_lexical_ordering() {
        assert!(is_newer("0.9.0", "0.10.0").expect("compare versions"));
        assert!(!is_newer("1.2.0", "1.2.0").expect("compare versions"));
        assert!(!is_newer("2.0.0", "1.9.9").expect("compare versions"));
    }

    #[test]
    fn release_target_matches_supported_operating_system_and_architecture() {
        assert_eq!(release_target("linux", "x86_64").unwrap(), "linux-amd64");
        assert_eq!(release_target("linux", "aarch64").unwrap(), "linux-arm64");
        assert_eq!(release_target("macos", "x86_64").unwrap(), "macos-amd64");
        assert_eq!(release_target("macos", "aarch64").unwrap(), "macos-arm64");
        assert_eq!(
            release_target("windows", "x86_64").unwrap(),
            "windows-amd64"
        );
    }

    #[test]
    fn unsupported_release_targets_are_rejected() {
        assert!(release_target("windows", "aarch64").is_err());
        assert!(release_target("freebsd", "x86_64").is_err());
    }
}
