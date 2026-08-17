use std::{env, io::IsTerminal};

use cliclack::confirm;
use console::style;
use self_update::{backends::github, update::ReleaseUpdate};
use serde::{Deserialize, Serialize};

use crate::{
    cli::{UpdateArgs, UpdateChannel},
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
    tag: String,
    commit: Option<String>,
}

const BUILD_CHANNEL: &str = match option_env!("MEOWAI_DEPLOY_BUILD_CHANNEL") {
    Some(value) => value,
    None => "stable",
};
pub(crate) const BUILD_VERSION: &str = match option_env!("MEOWAI_DEPLOY_BUILD_VERSION") {
    Some(value) => value,
    None => env!("CARGO_PKG_VERSION"),
};
const BUILD_SHA: &str = match option_env!("MEOWAI_DEPLOY_BUILD_SHA") {
    Some(value) => value,
    None => "",
};

pub async fn run(args: &UpdateArgs) -> Result<()> {
    let latest = fetch_latest_release(args.channel).await?;
    let current = env!("CARGO_PKG_VERSION");
    let available = update_is_available(args.channel, current, &latest)?;
    print_versions(args.channel, &latest, available);
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
        let confirmed = confirm(format!("更新到 {}？", release_label(args.channel, &latest)))
            .initial_value(true)
            .interact()
            .map_err(AppError::from_prompt)?;
        if !confirmed {
            return Err(AppError::Cancelled);
        }
    }

    let tag = latest.tag.clone();
    tokio::task::spawn_blocking(move || install_release(&tag))
        .await
        .map_err(|error| AppError::Message(format!("update task failed: {error}")))??;
    println!();
    println!(
        "{} {}",
        style("✓").green(),
        style(format!("已更新到 {}", release_label(args.channel, &latest))).bold()
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
    match fetch_latest_release(UpdateChannel::Stable).await {
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

async fn fetch_latest_release(channel: UpdateChannel) -> Result<LatestRelease> {
    tokio::task::spawn_blocking(move || match channel {
        UpdateChannel::Stable => {
            let updater = update_builder(false)?;
            let release = updater
                .get_latest_release()
                .map_err(|error| AppError::Message(format!("check GitHub release: {error}")))?;
            Ok(LatestRelease {
                tag: format!("v{}", release.version),
                version: release.version,
                commit: None,
            })
        }
        UpdateChannel::Canary => fetch_latest_canary(),
    })
    .await
    .map_err(|error| AppError::Message(format!("release check task failed: {error}")))?
}

fn fetch_latest_canary() -> Result<LatestRelease> {
    let target = release_target(env::consts::OS, env::consts::ARCH)?;
    let mut builder = github::ReleaseList::configure();
    builder
        .repo_owner(REPOSITORY_OWNER)
        .repo_name(REPOSITORY_NAME)
        .with_target(target);
    if let Ok(url) = env::var("MEOWAI_DEPLOY_GITHUB_API_URL") {
        builder.with_url(url.trim_end_matches('/'));
    }
    if let Ok(token) = env::var("GITHUB_TOKEN") {
        builder.auth_token(&token);
    }
    let releases = builder
        .build()
        .map_err(|error| AppError::Message(format!("configure Canary release check: {error}")))?
        .fetch()
        .map_err(|error| AppError::Message(format!("check GitHub Canary releases: {error}")))?;
    releases
        .into_iter()
        .find_map(|release| {
            parse_canary_version(&release.version).map(|commit| LatestRelease {
                tag: format!("v{}", release.version),
                version: release.version,
                commit: Some(commit),
            })
        })
        .ok_or_else(|| {
            AppError::Message(format!(
                "no Canary release is available for {target}; use `meowai-deploy update --channel stable`"
            ))
        })
}

fn install_release(tag: &str) -> Result<()> {
    let mut builder = github::Update::configure();
    configure_builder(&mut builder)?;
    let updater = builder
        .target_version_tag(tag)
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

fn parse_canary_version(version: &str) -> Option<String> {
    let (_, suffix) = version.split_once("-canary.")?;
    let commit = suffix.rsplit('.').next()?;
    if (7..=40).contains(&commit.len()) && commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        Some(commit.to_ascii_lowercase())
    } else {
        None
    }
}

fn update_is_available(
    channel: UpdateChannel,
    current: &str,
    latest: &LatestRelease,
) -> Result<bool> {
    match channel {
        UpdateChannel::Stable => is_newer(current, &latest.version),
        UpdateChannel::Canary => {
            let latest_commit = latest.commit.as_deref().ok_or_else(|| {
                AppError::Message("Canary release is missing its commit identity".to_owned())
            })?;
            Ok(BUILD_CHANNEL != "canary"
                || BUILD_SHA.is_empty()
                || !BUILD_SHA.to_ascii_lowercase().starts_with(latest_commit))
        }
    }
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

fn release_label(channel: UpdateChannel, latest: &LatestRelease) -> String {
    match channel {
        UpdateChannel::Stable => format!("v{}", latest.version),
        UpdateChannel::Canary => latest.tag.clone(),
    }
}

fn print_versions(channel: UpdateChannel, latest: &LatestRelease, available: bool) {
    println!();
    println!("{}", style("CLI 版本").bold());
    println!(
        "  更新通道  {}",
        match channel {
            UpdateChannel::Stable => "stable",
            UpdateChannel::Canary => "canary",
        }
    );
    let current_label = if BUILD_CHANNEL == "canary" {
        format!("v{BUILD_VERSION}")
    } else {
        format!("v{BUILD_VERSION} stable")
    };
    println!("  当前版本  {current_label}");
    println!("  最新版本  {}", release_label(channel, latest));
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
    fn canary_versions_carry_a_commit_identity() {
        assert_eq!(
            parse_canary_version("1.2.1-canary.20260817T093012Z.e7717f9").as_deref(),
            Some("e7717f9")
        );
        assert!(parse_canary_version("1.2.1").is_none());
        assert!(parse_canary_version("1.2.1-canary.now.not-a-sha").is_none());
    }

    #[test]
    fn stable_builds_can_opt_in_to_the_latest_canary() {
        let latest = LatestRelease {
            version: "1.2.1-canary.20260817T093012Z.e7717f9".to_owned(),
            tag: "v1.2.1-canary.20260817T093012Z.e7717f9".to_owned(),
            commit: Some("e7717f9".to_owned()),
        };
        assert!(
            update_is_available(UpdateChannel::Canary, "1.2.1", &latest)
                .expect("compare Canary commit")
        );
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
