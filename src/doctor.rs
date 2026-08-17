use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use comfy_table::{Cell, Color, Table, presets::UTF8_FULL};
use console::style;
use serde::Serialize;

use crate::{
    application::input,
    cli::DoctorArgs,
    config::{DeploymentConfig, Target},
    error::{AppError, Result},
    platform, storage,
    target::{
        TargetExecutor,
        remote_path::RemotePath,
        ssh::{ProgramStatus, discover_openssh},
    },
};

const MIN_FREE_BYTES: u64 = 5 * 1024 * 1024 * 1024;

#[derive(Debug, Serialize)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
    pub blocking: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Pass,
    Fail,
    Warn,
}

#[derive(Debug, Serialize)]
pub struct Report {
    /// Versioned so scripts can reject an incompatible JSON contract.
    pub schema_version: u8,
    pub platform: String,
    pub checks: Vec<Check>,
    pub blocking_failures: usize,
}

pub async fn run(args: &DoctorArgs) -> Result<()> {
    // Remote diagnostics are opt-in. A saved SSH target must never be contacted merely by
    // running `doctor` without an explicit destination.
    let destination = args.ssh.clone();
    let mut checks = vec![check_architecture(), check_state_directory()];
    if let Some(destination) = destination {
        checks.extend(check_remote_target(&destination, &args.directory));
    } else if cfg!(windows) {
        checks.push(check_ssh_client());
    } else {
        checks.extend([
            check_command("docker", &["--version"], true, "Docker CLI"),
            check_compose(),
            check_command("curl", &["--version"], true, "curl"),
            check_directory(&args.directory),
            check_disk(&args.directory),
        ]);
    }

    let blocking_failures = checks
        .iter()
        .filter(|check| check.blocking && matches!(check.status, CheckStatus::Fail))
        .count();
    let report = Report {
        schema_version: 1,
        platform: format!("{}/{}", std::env::consts::OS, std::env::consts::ARCH),
        checks,
        blocking_failures,
    };
    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|error| AppError::Message(error.to_string()))?
        );
    } else {
        print_table(&report);
    }
    if report.blocking_failures > 0 {
        return Err(AppError::DoctorFailed);
    }
    Ok(())
}

pub fn preflight_onboard(args: &crate::cli::OnboardArgs) -> Result<()> {
    if !cfg!(windows) {
        return Ok(());
    }
    if args.local {
        return Err(AppError::InvalidConfig(
            "Windows 控制端不支持本机部署；请使用 --ssh user@linux-host".to_owned(),
        ));
    }
    if let Some(path) = &args.config {
        let config = DeploymentConfig::from_file(path)?;
        if matches!(config.target, Target::Local) && args.ssh.is_none() {
            return Err(AppError::InvalidConfig(
                "Windows 控制端配置必须使用 SSH Linux target".to_owned(),
            ));
        }
    }
    let check = check_ssh_client();
    if matches!(check.status, CheckStatus::Fail) {
        return Err(AppError::Message(format!(
            "SSH_CLIENT_MISSING: {}；请先运行 meowai-deploy bootstrap",
            check.detail
        )));
    }
    Ok(())
}

fn check_architecture() -> Check {
    check_architecture_for(std::env::consts::OS, std::env::consts::ARCH)
}

fn check_architecture_for(operating_system: &str, architecture: &str) -> Check {
    let architecture_name = match architecture {
        "x86_64" => Some("amd64"),
        "aarch64" => Some("arm64"),
        _ => None,
    };
    if matches!(operating_system, "linux" | "macos" | "windows") && architecture_name.is_some() {
        Check {
            name: "architecture".to_owned(),
            status: CheckStatus::Pass,
            detail: format!(
                "{operating_system} {} supported",
                architecture_name.expect("supported architecture")
            ),
            blocking: true,
        }
    } else {
        Check {
            name: "architecture".to_owned(),
            status: CheckStatus::Fail,
            detail: format!(
                "{operating_system}/{architecture} detected; supported targets are Linux, macOS, and Windows on amd64 or arm64"
            ),
            blocking: true,
        }
    }
}

fn check_state_directory() -> Check {
    let root = match storage::directory() {
        Ok(root) => root,
        Err(error) => {
            return Check {
                name: "state directory".to_owned(),
                status: CheckStatus::Fail,
                detail: error.to_string(),
                blocking: true,
            };
        }
    };
    match platform::ensure_private_directory(&root).and_then(|_| {
        platform::private_path_is_restricted(&root, true).map(|restricted| {
            if restricted {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "state directory permissions are too broad",
                ))
            }
        })
    }) {
        Ok(Ok(())) => Check {
            name: "state directory".to_owned(),
            status: CheckStatus::Pass,
            detail: format!("{} is private and writable", root.display()),
            blocking: true,
        },
        Ok(Err(error)) | Err(error) => Check {
            name: "state directory".to_owned(),
            status: CheckStatus::Fail,
            detail: format!("{}: {error}", root.display()),
            blocking: true,
        },
    }
}

fn check_ssh_client() -> Check {
    let report = discover_openssh();
    if report.ssh.status == ProgramStatus::Pass && report.scp.status == ProgramStatus::Pass {
        Check {
            name: "OpenSSH Client".to_owned(),
            status: CheckStatus::Pass,
            detail: format!(
                "{} / {}",
                report
                    .ssh
                    .path
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                report
                    .scp
                    .path
                    .map(|path| path.display().to_string())
                    .unwrap_or_default()
            ),
            blocking: true,
        }
    } else {
        Check {
            name: "OpenSSH Client".to_owned(),
            status: CheckStatus::Fail,
            detail: report
                .ssh
                .detail
                .or(report.scp.detail)
                .unwrap_or_else(|| "ssh/scp 不可用".to_owned()),
            blocking: true,
        }
    }
}

fn check_remote_target(destination: &str, directory: &Path) -> Vec<Check> {
    let mut checks = vec![check_ssh_client()];
    if let Err(error) = input::validate_ssh_destination(destination) {
        checks.push(Check {
            name: "SSH target".to_owned(),
            status: CheckStatus::Fail,
            detail: error.message,
            blocking: true,
        });
        return checks;
    }
    let remote = match RemotePath::parse(&directory.to_string_lossy()) {
        Ok(path) => path,
        Err(error) => {
            checks.push(Check {
                name: "remote directory".to_owned(),
                status: CheckStatus::Fail,
                detail: error.to_string(),
                blocking: true,
            });
            return checks;
        }
    };
    let executor = TargetExecutor::new(
        Target::Ssh {
            destination: destination.to_owned(),
        },
        PathBuf::from(remote.as_str()),
    );
    match executor.remote_diagnostics() {
        Ok(output) => checks.extend(parse_remote_checks(&output.stdout)),
        Err(error) => checks.push(Check {
            name: "remote SSH diagnostics".to_owned(),
            status: CheckStatus::Fail,
            detail: error.to_string(),
            blocking: true,
        }),
    }
    checks
}

fn parse_remote_checks(bytes: &[u8]) -> Vec<Check> {
    let text = String::from_utf8_lossy(bytes);
    let values = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut checks = Vec::new();
    for (key, name, blocking) in [
        ("os", "remote OS", true),
        ("arch", "remote architecture", true),
        ("docker_cli", "remote Docker CLI", true),
        ("docker_daemon", "remote Docker daemon", true),
        ("compose", "remote Docker Compose", true),
        ("curl", "remote curl", true),
        ("directory", "remote directory", true),
    ] {
        let value = values.get(key).copied().unwrap_or("missing");
        let pass = match key {
            "os" => value == "Linux",
            "arch" => matches!(value, "x86_64" | "aarch64"),
            _ => value == "pass",
        };
        checks.push(Check {
            name: name.to_owned(),
            status: if pass {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            detail: value.to_owned(),
            blocking,
        });
    }
    let disk = values
        .get("disk_bytes")
        .and_then(|value| value.parse::<u64>().ok());
    checks.push(Check {
        name: "remote disk space".to_owned(),
        status: match disk {
            Some(bytes) if bytes >= MIN_FREE_BYTES => CheckStatus::Pass,
            Some(_) => CheckStatus::Warn,
            None => CheckStatus::Warn,
        },
        detail: disk
            .map(format_bytes)
            .unwrap_or_else(|| "df did not return a readable result".to_owned()),
        blocking: false,
    });
    checks
}

fn check_command(program: &str, args: &[&str], blocking: bool, label: &str) -> Check {
    match Command::new(program).args(args).output() {
        Ok(output) if output.status.success() => Check {
            name: label.to_owned(),
            status: CheckStatus::Pass,
            detail: first_line(&output.stdout).unwrap_or_else(|| "available".to_owned()),
            blocking,
        },
        Ok(output) => Check {
            name: label.to_owned(),
            status: CheckStatus::Fail,
            detail: first_line(&output.stderr)
                .unwrap_or_else(|| "command returned a failure".to_owned()),
            blocking,
        },
        Err(error) => Check {
            name: label.to_owned(),
            status: CheckStatus::Fail,
            detail: error.to_string(),
            blocking,
        },
    }
}

fn check_compose() -> Check {
    if let Ok(output) = Command::new("docker").args(["compose", "version"]).output()
        && output.status.success()
    {
        return Check {
            name: "Docker Compose".to_owned(),
            status: CheckStatus::Pass,
            detail: first_line(&output.stdout).unwrap_or_else(|| "plugin available".to_owned()),
            blocking: true,
        };
    }
    check_command("docker-compose", &["version"], true, "Docker Compose")
}

fn check_directory(directory: &Path) -> Check {
    let existing = nearest_existing_parent(directory);
    match fs::metadata(&existing) {
        Ok(metadata) if metadata.is_dir() && !metadata.permissions().readonly() => Check {
            name: "deployment directory".to_owned(),
            status: CheckStatus::Pass,
            detail: format!(
                "{} is writable or can receive the target directory",
                existing.display()
            ),
            blocking: true,
        },
        Ok(metadata) if metadata.is_dir() => Check {
            name: "deployment directory".to_owned(),
            status: CheckStatus::Fail,
            detail: format!("{} is read-only", existing.display()),
            blocking: true,
        },
        Ok(_) => Check {
            name: "deployment directory".to_owned(),
            status: CheckStatus::Fail,
            detail: format!("{} is not a directory", existing.display()),
            blocking: true,
        },
        Err(error) => Check {
            name: "deployment directory".to_owned(),
            status: CheckStatus::Fail,
            detail: format!("cannot inspect {}: {error}", existing.display()),
            blocking: true,
        },
    }
}

fn check_disk(directory: &Path) -> Check {
    let existing = nearest_existing_parent(directory);
    let output = Command::new("df")
        .args(["-Pk", &existing.to_string_lossy()])
        .output();
    let available = output.ok().and_then(|result| {
        if !result.status.success() {
            return None;
        }
        let line = String::from_utf8_lossy(&result.stdout)
            .lines()
            .last()?
            .to_owned();
        line.split_whitespace().nth(3)?.parse::<u64>().ok()
    });
    match available {
        Some(kilobytes) => {
            let bytes = kilobytes.saturating_mul(1024);
            let status = if bytes >= MIN_FREE_BYTES {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            };
            Check {
                name: "disk space".to_owned(),
                status,
                detail: format!("{} free", format_bytes(bytes)),
                blocking: false,
            }
        }
        None => Check {
            name: "disk space".to_owned(),
            status: CheckStatus::Warn,
            detail: "df did not return a readable result".to_owned(),
            blocking: false,
        },
    }
}

fn print_table(report: &Report) {
    let mut table = Table::new();
    table.load_preset(UTF8_FULL);
    table.set_header(vec!["Check", "Status", "Detail"]);
    for check in &report.checks {
        let status = match check.status {
            CheckStatus::Pass => Cell::new("PASS").fg(Color::Green),
            CheckStatus::Fail => Cell::new("FAIL").fg(Color::Red),
            CheckStatus::Warn => Cell::new("WARN").fg(Color::Yellow),
        };
        table.add_row(vec![
            Cell::new(&check.name),
            status,
            Cell::new(&check.detail),
        ]);
    }
    println!("{table}");
    if report.blocking_failures == 0 {
        println!(
            "{}",
            style("doctor passed: no blocking checks failed").green()
        );
    } else {
        println!(
            "{}",
            style(format!(
                "doctor failed: {} blocking check(s)",
                report.blocking_failures
            ))
            .red()
        );
    }
}

fn nearest_existing_parent(path: &Path) -> PathBuf {
    let mut candidate = path.to_owned();
    while !candidate.exists() {
        if !candidate.pop() {
            return PathBuf::from(".");
        }
    }
    candidate
}

fn first_line(bytes: &[u8]) -> Option<String> {
    String::from_utf8_lossy(bytes)
        .lines()
        .next()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
}

fn format_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / (1024 * 1024))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn architecture_check_accepts_supported_operating_systems_on_amd64_and_arm64() {
        for (operating_system, architecture) in [
            ("linux", "x86_64"),
            ("linux", "aarch64"),
            ("macos", "x86_64"),
            ("macos", "aarch64"),
            ("windows", "x86_64"),
            ("windows", "aarch64"),
        ] {
            let check = check_architecture_for(operating_system, architecture);
            assert!(matches!(check.status, CheckStatus::Pass));
            assert!(check.blocking);
        }
        assert!(matches!(
            check_architecture_for("linux", "riscv64").status,
            CheckStatus::Fail
        ));
    }

    #[test]
    fn report_json_has_a_stable_machine_readable_contract() {
        let report = Report {
            schema_version: 1,
            platform: "linux/x86_64".to_owned(),
            checks: vec![Check {
                name: "architecture".to_owned(),
                status: CheckStatus::Pass,
                detail: "linux amd64 supported".to_owned(),
                blocking: true,
            }],
            blocking_failures: 0,
        };
        let value = serde_json::to_value(report).expect("serialize doctor report");
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["platform"], "linux/x86_64");
        assert_eq!(value["checks"][0]["status"], "PASS");
        assert_eq!(value["checks"][0]["blocking"], true);
        assert_eq!(value["blocking_failures"], 0);
    }

    #[test]
    fn remote_checks_classify_supported_linux_target_and_disk_warning() {
        let checks = parse_remote_checks(
            b"os=Linux\narch=x86_64\ndocker_cli=pass\ndocker_daemon=pass\ncompose=pass\ncurl=pass\ndirectory=pass\ndisk_bytes=1024\n",
        );
        assert!(checks.iter().any(|check| {
            check.name == "remote OS" && matches!(check.status, CheckStatus::Pass)
        }));
        assert!(checks.iter().any(|check| {
            check.name == "remote disk space" && matches!(check.status, CheckStatus::Warn)
        }));
    }
}
