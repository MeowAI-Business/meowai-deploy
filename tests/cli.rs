use std::{path::Path, process::Command};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_meowai-deploy"))
}

#[test]
fn help_lists_supported_commands() {
    let output = binary().arg("--help").output().expect("run help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "bootstrap",
        "doctor",
        "onboard",
        "sync",
        "status",
        "clean",
        "rollback",
        "logout",
        "update",
    ] {
        assert!(
            stdout.contains(command),
            "missing {command} in help: {stdout}"
        );
    }

    let doctor_output = binary()
        .args(["doctor", "--help"])
        .output()
        .expect("run doctor help");
    assert!(doctor_output.status.success());
    let doctor_help = String::from_utf8_lossy(&doctor_output.stdout);
    assert!(!doctor_help.contains("--newapi-port"));
    assert!(!doctor_help.contains("--kuma-port"));
    assert!(!doctor_help.contains("--source-url"));
    assert!(!doctor_help.contains("--skip-network"));
    assert!(doctor_help.contains("--ssh"));
}

#[test]
fn update_help_exposes_stable_and_canary_channels() {
    let output = binary()
        .args(["update", "--help"])
        .output()
        .expect("run update help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--channel <CHANNEL>"));
    assert!(stdout.contains("stable, canary"));
}

#[test]
fn version_reports_the_embedded_build_version() {
    let output = binary().arg("--version").output().expect("run version");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("meowai-deploy {}", env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn no_args_prints_help_without_starting_onboard() {
    let output = binary().output().expect("run without arguments");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stdout.contains("Usage: meowai-deploy [COMMAND]"));
    assert!(!stderr.contains("网站名称"));
}

#[test]
fn sync_is_implemented_and_exposes_operational_flags() {
    let help = binary()
        .args(["sync", "--help"])
        .output()
        .expect("run sync help");
    assert!(help.status.success());
    let stdout = String::from_utf8_lossy(&help.stdout);
    for flag in ["--check", "--details", "--apply", "--force"] {
        assert!(
            stdout.contains(flag),
            "missing {flag} in sync help: {stdout}"
        );
    }
    assert!(!stdout.contains("--pricing"));

    let output = binary()
        .env(
            "MEOWAI_DEPLOY_HOME",
            tempfile::tempdir()
                .expect("create temporary state directory")
                .path(),
        )
        .arg("sync")
        .output()
        .expect("run sync against missing deployment");
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("not implemented"));
}

#[test]
fn sync_check_conflicts_with_apply_and_apply_accepts_csv_modules() {
    let conflict = binary()
        .args(["sync", "--check", "--apply", "groups,channels"])
        .output()
        .expect("run conflicting sync flags");
    assert_eq!(conflict.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&conflict.stderr);
    assert!(stderr.contains("cannot be used with"));

    let directory = tempfile::tempdir().expect("create temporary directory");
    let parsed = binary()
        .env("MEOWAI_DEPLOY_HOME", directory.path())
        .args(["sync", "--apply", "groups,channels"])
        .output()
        .expect("run sync with CSV modules");
    assert_eq!(parsed.status.code(), Some(1));
    assert!(!String::from_utf8_lossy(&parsed.stderr).contains("invalid value"));
}

#[test]
fn status_without_deployment_is_a_normal_state() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let output = binary()
        .env("MEOWAI_DEPLOY_HOME", directory.path())
        .arg("status")
        .output()
        .expect("run status");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("尚未 onboard") || stderr.contains("尚未 onboard"),
        "unexpected output: {stdout}{stderr}"
    );
    assert!(!stderr.contains("deployment.toml"));
}

#[test]
fn doctor_json_is_non_interactive_and_does_not_contact_saved_targets() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let output = binary()
        .env("MEOWAI_DEPLOY_HOME", directory.path())
        .env("MEOWAI_DEPLOY_DISABLE_UPDATE_CHECK", "1")
        .args(["doctor", "--json"])
        .output()
        .expect("run doctor json");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("doctor JSON");
    assert_eq!(report["schema_version"], 1);
    assert!(report["platform"].as_str().is_some());
    assert!(report["checks"].is_array());
    assert!(report["blocking_failures"].is_number());
}

#[test]
fn no_color_disables_ansi_in_terminal_facing_output() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let output = binary()
        .env("NO_COLOR", "1")
        .env("MEOWAI_DEPLOY_HOME", directory.path())
        .args(["doctor", "--json"])
        .output()
        .expect("run no-color doctor");
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!combined.contains('\u{1b}'));
}

#[test]
fn installer_is_a_verified_bash_script() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    let script = std::fs::read_to_string(path).expect("read install script");
    assert!(script.starts_with("#!/usr/bin/env bash"));
    assert!(script.contains("sha256sum"));
    assert!(script.contains("checksums-sha256.txt"));
    assert!(script.contains("MEOWAI_DEPLOY_RELEASE_BASE_URL"));
    assert!(script.contains("target_os=\"macos\""));
    assert!(script.contains("target_arch=\"arm64\""));
    assert!(script.contains("meowai-deploy-${target_os}-${target_arch}.tar.gz"));
    assert!(script.contains("Added ~/.local/bin to PATH"));
    assert!(script.contains("Run: meowai-deploy doctor"));
    assert!(script.contains("Then: meowai-deploy onboard"));
}

#[test]
fn linux_release_binaries_are_built_with_musl() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml");
    let workflow = std::fs::read_to_string(path).expect("read release workflow");
    assert!(workflow.contains("x86_64-unknown-linux-musl"));
    assert!(workflow.contains("aarch64-unknown-linux-musl"));
    assert!(workflow.contains("musl-tools"));
    assert!(workflow.contains("Requesting program interpreter"));
}

#[test]
fn windows_release_binaries_cover_amd64_and_arm64() {
    let release = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/release.yml"),
    )
    .expect("read release workflow");
    let canary = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows/canary.yml"),
    )
    .expect("read Canary workflow");
    for workflow in [release, canary] {
        for marker in [
            "windows-amd64",
            "windows-arm64",
            "x86_64-pc-windows-msvc",
            "aarch64-pc-windows-msvc",
            "windows-11-arm",
        ] {
            assert!(
                workflow.contains(marker),
                "missing Windows marker: {marker}"
            );
        }
    }
}

#[test]
fn installer_is_a_verified_powershell_script_for_windows_users() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.ps1");
    let script = std::fs::read_to_string(path).expect("read PowerShell installer");
    for marker in [
        "Invoke-WebRequest",
        "Get-FileHash -Algorithm SHA256",
        "Expand-Archive",
        "@('ARM64', 'AARCH64')",
        "meowai-deploy-windows-$targetArch.zip",
        "meowai-deploy.exe",
        "GetEnvironmentVariable('Path', 'User')",
        "SetEnvironmentVariable('Path', $updatedPath, 'User')",
        "Run: meowai-deploy doctor",
        "Then: meowai-deploy onboard --ssh user@linux-host",
    ] {
        assert!(
            script.contains(marker),
            "missing PowerShell marker: {marker}"
        );
    }
    assert!(!script.contains("MEOWAI_DEPLOY_SOURCE_PASSWORD"));
}
