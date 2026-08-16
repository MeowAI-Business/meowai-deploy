use std::{env, path::Path, process::Command};

#[cfg(windows)]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::process::ExitStatus;

use console::style;
use serde::Serialize;

use crate::{
    cli::BootstrapArgs,
    error::{AppError, Result},
    target::ssh::{ProgramDiscovery, ProgramStatus, SshDiscovery, discover_openssh},
};

#[derive(Debug, Serialize)]
pub struct BootstrapReport {
    pub platform: String,
    pub ssh: ProgramDiscovery,
    pub scp: ProgramDiscovery,
    pub restart_required: bool,
}

impl BootstrapReport {
    fn from_discovery(discovery: SshDiscovery) -> Self {
        Self {
            platform: discovery.platform,
            ssh: discovery.ssh,
            scp: discovery.scp,
            restart_required: false,
        }
    }

    fn ready(&self) -> bool {
        self.ssh.status == ProgramStatus::Pass && self.scp.status == ProgramStatus::Pass
    }
}

pub fn run(args: &BootstrapArgs) -> Result<()> {
    let mut report = BootstrapReport::from_discovery(discover_openssh());
    if args.json {
        print_json(&report)?;
        return require_ready(&report);
    }
    if report.ready() || args.check {
        print_human(&report);
        return require_ready(&report);
    }

    println!();
    println!("{}", style("正在安装 OpenSSH Client").bold());
    install_openssh()?;
    report = BootstrapReport::from_discovery(discover_openssh());
    print_human(&report);
    require_ready(&report)
}

fn print_json(report: &BootstrapReport) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(report)
            .map_err(|error| AppError::Message(format!("serialize bootstrap report: {error}")))?
    );
    Ok(())
}

fn print_human(report: &BootstrapReport) {
    println!();
    println!("{}", style("OpenSSH Client").bold());
    print_program("ssh", &report.ssh);
    print_program("scp", &report.scp);
    if report.restart_required {
        println!("  {}", style("系统要求重启后再继续").yellow());
    }
    println!();
}

fn print_program(name: &str, program: &ProgramDiscovery) {
    match program.status {
        ProgramStatus::Pass => {
            let path = program
                .path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "unknown".to_owned());
            let detail = program.version.as_deref().unwrap_or("可用");
            println!("  {} {name}  {path} · {detail}", style("PASS").green());
        }
        ProgramStatus::Fail => println!(
            "  {} {name}  {}",
            style("FAIL").red(),
            program.detail.as_deref().unwrap_or("不可用")
        ),
    }
}

fn require_ready(report: &BootstrapReport) -> Result<()> {
    if report.ready() {
        Ok(())
    } else {
        Err(AppError::Message(
            "SSH_CLIENT_MISSING: OpenSSH ssh/scp 不可用；运行 meowai-deploy bootstrap 安装"
                .to_owned(),
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", test))]
fn program_exists(program: &str) -> bool {
    let path = Path::new(program);
    if path.components().count() > 1 {
        return path.is_file();
    }
    env::var_os("PATH")
        .map(|path| env::split_paths(&path).any(|directory| directory.join(program).is_file()))
        .unwrap_or(false)
}

fn install_error(message: &str, error: std::io::Error) -> AppError {
    AppError::Message(format!("SSH_INSTALL_FAILED: {message}: {error}"))
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn install_openssh() -> Result<()> {
    Err(AppError::Message(
        "SSH_INSTALL_UNAVAILABLE: 当前操作系统不支持自动安装 OpenSSH Client".to_owned(),
    ))
}

#[cfg(windows)]
fn install_openssh() -> Result<()> {
    let system_root = env::var_os("SystemRoot")
        .or_else(|| env::var_os("WINDIR"))
        .ok_or_else(|| {
            AppError::Message("SSH_INSTALL_UNAVAILABLE: 未找到 Windows 系统目录".to_owned())
        })?;
    let dism = PathBuf::from(system_root).join("System32").join("dism.exe");
    match windows_capability_state(&dism)? {
        WindowsCapabilityState::Installed => Ok(()),
        WindowsCapabilityState::Unavailable => Err(AppError::Message(
            "SSH_INSTALL_UNAVAILABLE: 当前 Windows 不提供 OpenSSH Client capability".to_owned(),
        )),
        WindowsCapabilityState::Missing => {
            let script = format!(
                "$p = Start-Process -FilePath '{}' -ArgumentList '/Online','/Add-Capability','/CapabilityName:OpenSSH.Client~~~~0.0.1.0','/Quiet','/NoRestart' -Verb RunAs -Wait -PassThru; exit $p.ExitCode",
                dism.display().to_string().replace('\'', "''")
            );
            let status = Command::new("powershell.exe")
                .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"])
                .arg(script)
                .status()
                .map_err(|error| install_error("无法启动 Windows OpenSSH 安装进程", error))?;
            match status.code().unwrap_or(1) {
                0 => Ok(()),
                3010 => Err(AppError::Message(
                    "SSH_RESTART_REQUIRED: OpenSSH Client 已安装，但 Windows 要求重启".to_owned(),
                )),
                code => Err(AppError::Message(format!(
                    "SSH_INSTALL_FAILED: Windows capability 安装失败（退出码 {code}）"
                ))),
            }
        }
    }
}

#[cfg(target_os = "linux")]
fn install_openssh() -> Result<()> {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let installer = select_linux_installer(&os_release, program_exists).ok_or_else(|| {
        AppError::Message(
            "SSH_INSTALL_UNAVAILABLE: 未找到受支持的 Linux 包管理器，请手工安装 OpenSSH Client"
                .to_owned(),
        )
    })?;
    let status = run_linux_installer(&installer)?;
    if status.success() {
        return Ok(());
    }
    if let Some(fallback) = installer.fallback_args() {
        if run_linux_command(installer.program, &fallback)?.success() {
            return Ok(());
        }
    }
    Err(AppError::Message(format!(
        "SSH_INSTALL_FAILED: {} 安装 OpenSSH Client 失败；请检查软件源和管理员权限",
        installer.program
    )))
}

#[cfg(target_os = "macos")]
fn install_openssh() -> Result<()> {
    let brew = ["/opt/homebrew/bin/brew", "/usr/local/bin/brew", "brew"]
        .into_iter()
        .find(|program| program_exists(program))
        .ok_or_else(|| {
            AppError::Message(
                "SSH_INSTALL_UNAVAILABLE: macOS 系统 SSH 缺失且未安装 Homebrew，请先修复系统 OpenSSH"
                    .to_owned(),
            )
        })?;
    let status = Command::new(brew)
        .args(["install", "openssh"])
        .status()
        .map_err(|error| install_error("无法启动 Homebrew", error))?;
    if status.success() {
        Ok(())
    } else {
        Err(AppError::Message(format!(
            "SSH_INSTALL_FAILED: brew install openssh 返回 {status}"
        )))
    }
}

#[cfg(windows)]
fn windows_capability_state(dism: &Path) -> Result<WindowsCapabilityState> {
    let output = Command::new(dism)
        .args([
            "/Online",
            "/Get-CapabilityInfo",
            "/CapabilityName:OpenSSH.Client~~~~0.0.1.0",
            "/English",
        ])
        .output()
        .map_err(|error| install_error("无法查询 Windows OpenSSH capability", error))?;
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(parse_windows_capability(&text))
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WindowsCapabilityState {
    Installed,
    Missing,
    Unavailable,
}

#[cfg(any(windows, test))]
fn parse_windows_capability(output: &str) -> WindowsCapabilityState {
    let lowercase = output.to_ascii_lowercase();
    if lowercase.lines().any(|line| {
        line.contains("state") && line.contains("installed") && !line.contains("not present")
    }) {
        WindowsCapabilityState::Installed
    } else if lowercase.contains("not present") || lowercase.contains("notpresent") {
        WindowsCapabilityState::Missing
    } else {
        WindowsCapabilityState::Unavailable
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct LinuxInstaller {
    program: &'static str,
    args: Vec<&'static str>,
    fallback_package: Option<&'static str>,
}

#[cfg(any(target_os = "linux", test))]
impl LinuxInstaller {
    #[cfg(target_os = "linux")]
    fn fallback_args(&self) -> Option<Vec<&'static str>> {
        self.fallback_package.map(|package| match self.program {
            "apk" => vec!["add", "--no-cache", package],
            _ => vec!["install", "-y", package],
        })
    }
}

#[cfg(any(target_os = "linux", test))]
fn select_linux_installer(
    os_release: &str,
    available: impl Fn(&str) -> bool,
) -> Option<LinuxInstaller> {
    let family = linux_family(os_release);
    let choices: &[(&str, &[&str], Option<&str>)] = match family.as_str() {
        "debian" => &[("apt-get", &["install", "-y", "openssh-client"], None)],
        "rhel" => &[
            ("dnf", &["install", "-y", "openssh-clients"], None),
            ("yum", &["install", "-y", "openssh-clients"], None),
        ],
        "alpine" => &[(
            "apk",
            &["add", "--no-cache", "openssh-client-default"],
            Some("openssh-client"),
        )],
        "arch" => &[(
            "pacman",
            &["-S", "--needed", "--noconfirm", "openssh"],
            None,
        )],
        "suse" => &[(
            "zypper",
            &["--non-interactive", "install", "openssh-clients"],
            None,
        )],
        _ => &[],
    };
    choices
        .iter()
        .find(|(program, _, _)| available(program))
        .map(|(program, args, fallback_package)| LinuxInstaller {
            program,
            args: args.to_vec(),
            fallback_package: *fallback_package,
        })
}

#[cfg(any(target_os = "linux", test))]
fn linux_family(os_release: &str) -> String {
    let mut values = String::new();
    for line in os_release.lines() {
        if let Some(value) = line
            .strip_prefix("ID=")
            .or_else(|| line.strip_prefix("ID_LIKE="))
        {
            values.push(' ');
            values.push_str(value.trim_matches('"'));
        }
    }
    if values.contains("debian") || values.contains("ubuntu") {
        "debian"
    } else if ["rhel", "fedora", "centos", "rocky", "almalinux"]
        .iter()
        .any(|value| values.contains(value))
    {
        "rhel"
    } else if values.contains("alpine") {
        "alpine"
    } else if values.contains("arch") || values.contains("manjaro") {
        "arch"
    } else if values.contains("suse") || values.contains("opensuse") {
        "suse"
    } else {
        "unknown"
    }
    .to_owned()
}

#[cfg(target_os = "linux")]
fn run_linux_installer(installer: &LinuxInstaller) -> Result<ExitStatus> {
    run_linux_command(installer.program, &installer.args)
}

#[cfg(target_os = "linux")]
fn run_linux_command(program: &str, args: &[&str]) -> Result<ExitStatus> {
    let is_root = Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .is_some_and(|output| output.status.success() && output.stdout.starts_with(b"0"));
    let mut command = if is_root {
        Command::new(program)
    } else if program_exists("sudo") {
        let mut command = Command::new("sudo");
        command.arg(program);
        command
    } else {
        return Err(AppError::Message(
            "SSH_INSTALL_FAILED: 安装 OpenSSH Client 需要 root 或 sudo".to_owned(),
        ));
    };
    command
        .args(args)
        .status()
        .map_err(|error| install_error("无法启动 Linux 包管理器", error))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_parser_distinguishes_installed_missing_and_unavailable() {
        assert_eq!(
            parse_windows_capability("State : Installed"),
            WindowsCapabilityState::Installed
        );
        assert_eq!(
            parse_windows_capability("State : Not Present"),
            WindowsCapabilityState::Missing
        );
        assert_eq!(
            parse_windows_capability("Error: 87"),
            WindowsCapabilityState::Unavailable
        );
    }

    #[test]
    fn linux_installers_use_a_fixed_distribution_whitelist() {
        let cases = [
            ("ID=ubuntu\nID_LIKE=debian", "apt-get", "openssh-client"),
            (
                "ID=rocky\nID_LIKE=\"rhel fedora\"",
                "dnf",
                "openssh-clients",
            ),
            ("ID=alpine", "apk", "openssh-client-default"),
            ("ID=arch", "pacman", "openssh"),
            (
                "ID=opensuse-leap\nID_LIKE=suse",
                "zypper",
                "openssh-clients",
            ),
        ];
        for (release, program, package) in cases {
            let installer = select_linux_installer(release, |candidate| candidate == program)
                .expect("supported installer");
            assert_eq!(installer.program, program);
            assert!(installer.args.contains(&package));
        }
        assert!(select_linux_installer("ID=gentoo", |_| true).is_none());
    }

    #[test]
    fn json_report_uses_stable_uppercase_status_values() {
        use std::path::PathBuf;

        let report = BootstrapReport {
            platform: "windows-amd64".to_owned(),
            ssh: ProgramDiscovery {
                status: ProgramStatus::Pass,
                path: Some(PathBuf::from(r"C:\Windows\System32\OpenSSH\ssh.exe")),
                version: Some("OpenSSH_for_Windows".to_owned()),
                source: Some("Windows capability".to_owned()),
                detail: None,
            },
            scp: ProgramDiscovery {
                status: ProgramStatus::Fail,
                path: None,
                version: None,
                source: None,
                detail: Some("missing".to_owned()),
            },
            restart_required: false,
        };
        let json = serde_json::to_string(&report).expect("serialize report");
        assert!(json.contains("\"status\":\"PASS\""));
        assert!(json.contains("\"status\":\"FAIL\""));
    }
}
