use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use comfy_table::{Cell, Color, Table, presets::UTF8_FULL};
use console::style;
use serde::Serialize;

use crate::{
    cli::DoctorArgs,
    error::{AppError, Result},
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
    pub checks: Vec<Check>,
    pub blocking_failures: usize,
}

pub async fn run(args: &DoctorArgs) -> Result<()> {
    let checks = vec![
        check_architecture(),
        check_command("docker", &["--version"], true, "Docker CLI"),
        check_compose(),
        check_command("curl", &["--version"], true, "curl"),
        check_directory(&args.directory),
        check_disk(&args.directory),
    ];

    let blocking_failures = checks
        .iter()
        .filter(|check| check.blocking && matches!(check.status, CheckStatus::Fail))
        .count();
    let report = Report {
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

fn check_architecture() -> Check {
    let architecture = std::env::consts::ARCH;
    let operating_system = std::env::consts::OS;
    if architecture == "x86_64" && operating_system == "linux" {
        Check {
            name: "architecture".to_owned(),
            status: CheckStatus::Pass,
            detail: "linux amd64 target supported".to_owned(),
            blocking: true,
        }
    } else if architecture == "x86_64" {
        Check {
            name: "architecture".to_owned(),
            status: CheckStatus::Warn,
            detail: format!(
                "{operating_system}/x86_64 development host; deployment target is Linux amd64"
            ),
            blocking: false,
        }
    } else {
        Check {
            name: "architecture".to_owned(),
            status: CheckStatus::Fail,
            detail: format!(
                "{operating_system}/{architecture} detected; this release supports Linux amd64 only"
            ),
            blocking: true,
        }
    }
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
