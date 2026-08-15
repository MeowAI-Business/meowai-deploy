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
        "doctor", "onboard", "sync", "status", "clean", "rollback", "logout", "update",
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
    for flag in ["--pricing", "--force"] {
        assert!(
            stdout.contains(flag),
            "missing {flag} in sync help: {stdout}"
        );
    }

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
    assert!(stderr.contains("deployment.toml"));
    assert!(!stderr.contains("not implemented"));
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
