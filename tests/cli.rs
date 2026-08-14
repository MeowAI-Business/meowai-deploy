use std::{path::Path, process::Command};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_meowai-deploy"))
}

#[test]
fn help_lists_supported_commands() {
    let output = binary().arg("--help").output().expect("run help");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in ["doctor", "onboard", "sync", "status", "rollback", "logout"] {
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
fn unimplemented_command_has_explicit_exit_code() {
    let output = binary().arg("sync").output().expect("run sync");
    assert_eq!(output.status.code(), Some(3));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not implemented in the current release"));
}

#[test]
fn installer_is_a_verified_bash_script() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("install.sh");
    let script = std::fs::read_to_string(path).expect("read install script");
    assert!(script.starts_with("#!/usr/bin/env bash"));
    assert!(script.contains("sha256sum"));
    assert!(script.contains("MEOWAI_DEPLOY_RELEASE_BASE_URL"));
}
