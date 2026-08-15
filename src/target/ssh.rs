use std::{
    env,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
};

use serde::Serialize;

const CONNECT_TIMEOUT_SECONDS: &str = "10";

#[derive(Clone, Debug)]
pub struct SshClient {
    ssh: PathBuf,
    scp: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SshDiscovery {
    pub platform: String,
    pub ssh: ProgramDiscovery,
    pub scp: ProgramDiscovery,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProgramDiscovery {
    pub status: ProgramStatus,
    pub path: Option<PathBuf>,
    pub version: Option<String>,
    pub source: Option<String>,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ProgramStatus {
    Pass,
    Fail,
}

impl SshClient {
    pub fn discover() -> Result<Self, SshError> {
        let report = discover_openssh();
        let ssh = report.ssh.path.ok_or_else(|| {
            SshError::new(
                SshErrorKind::NotInstalled,
                "未找到可用的 OpenSSH ssh 客户端；请先运行 meowai-deploy bootstrap",
            )
        })?;
        let scp = report.scp.path.ok_or_else(|| {
            SshError::new(
                SshErrorKind::NotInstalled,
                "未找到可用的 OpenSSH scp 客户端；请先运行 meowai-deploy bootstrap",
            )
        })?;
        Ok(Self { ssh, scp })
    }

    #[cfg(test)]
    pub fn from_programs(ssh: PathBuf, scp: PathBuf) -> Self {
        Self { ssh, scp }
    }

    pub fn probe(&self, destination: &str) -> Result<(), SshError> {
        let output = self
            .ssh_command()
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg(destination)
            .arg("printf '%s' meowai-ssh-ok")
            .output()
            .map_err(|error| SshError::launch("ssh probe", error))?;
        if output.status.success() && output.stdout == b"meowai-ssh-ok" {
            Ok(())
        } else {
            Err(SshError::from_output("SSH 连接预检失败", &output))
        }
    }

    pub fn probe_interactive(&self, destination: &str) -> Result<(), SshError> {
        let status = self
            .ssh_command_without_batch_mode()
            .arg("-o")
            .arg("StrictHostKeyChecking=ask")
            .args(["-o", "PasswordAuthentication=no"])
            .args(["-o", "KbdInteractiveAuthentication=no"])
            .args(["-o", "NumberOfPasswordPrompts=0"])
            .arg(destination)
            .arg("printf '%s' meowai-ssh-ok")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| SshError::launch("interactive ssh probe", error))?;
        if !status.success() {
            return Err(SshError::new(
                SshErrorKind::Connection,
                "SSH 首次连接或认证失败",
            ));
        }
        self.probe(destination)
    }

    pub fn exec(
        &self,
        destination: &str,
        remote_command: &str,
        stdin: &[u8],
    ) -> Result<Output, SshError> {
        let mut child = self
            .ssh_command()
            .arg("-o")
            .arg("StrictHostKeyChecking=yes")
            .arg(destination)
            .arg(remote_command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| SshError::launch("ssh exec", error))?;
        child
            .stdin
            .as_mut()
            .ok_or_else(|| SshError::new(SshErrorKind::Execution, "SSH 标准输入不可用"))?
            .write_all(stdin)
            .map_err(|error| SshError::launch("ssh stdin", error))?;
        child
            .wait_with_output()
            .map_err(|error| SshError::launch("ssh wait", error))
    }

    pub fn upload(
        &self,
        destination: &str,
        local: &Path,
        remote: &str,
    ) -> Result<Output, SshError> {
        let remote_spec = format!("{destination}:{remote}");
        self.scp_command()
            .args(["-q", "-p", "-o", "BatchMode=yes", "-o"])
            .arg(format!("ConnectTimeout={CONNECT_TIMEOUT_SECONDS}"))
            .args(["-o", "StrictHostKeyChecking=yes"])
            .arg(local)
            .arg(remote_spec)
            .output()
            .map_err(|error| SshError::launch("scp upload", error))
    }

    pub fn tunnel(
        &self,
        destination: &str,
        local_port: u16,
        remote_port: u16,
    ) -> Result<Child, SshError> {
        self.ssh_command()
            .args([
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ExitOnForwardFailure=yes",
            ])
            .args(["-N", "-L"])
            .arg(format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}"))
            .arg(destination)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|error| SshError::launch("ssh tunnel", error))
    }

    fn ssh_command(&self) -> Command {
        let mut command = self.ssh_command_without_batch_mode();
        command.args(["-o", "BatchMode=yes"]);
        command
    }

    fn ssh_command_without_batch_mode(&self) -> Command {
        let mut command = Command::new(&self.ssh);
        command
            .args(["-o", "ConnectTimeout=10", "-o", "ConnectionAttempts=1"])
            .env("LC_ALL", "C");
        command
    }

    fn scp_command(&self) -> Command {
        let mut command = Command::new(&self.scp);
        command.env("LC_ALL", "C");
        command
    }
}

pub fn discover_openssh() -> SshDiscovery {
    discover_openssh_in(env::var_os("PATH").as_deref(), default_search_directories())
}

fn discover_openssh_in(
    path: Option<&std::ffi::OsStr>,
    defaults: Vec<(PathBuf, &'static str)>,
) -> SshDiscovery {
    let executable_suffix = if cfg!(windows) { ".exe" } else { "" };
    let mut directories = Vec::new();
    if let Some(path) = path {
        directories.extend(env::split_paths(path).map(|directory| (directory, "PATH")));
    }
    for entry in defaults {
        if !directories.iter().any(|(path, _)| path == &entry.0) {
            directories.push(entry);
        }
    }
    let ssh = discover_program(&directories, &format!("ssh{executable_suffix}"), true);
    let scp = discover_program(&directories, &format!("scp{executable_suffix}"), false);
    SshDiscovery {
        platform: format!("{}-{}", env::consts::OS, normalized_architecture()),
        ssh,
        scp,
    }
}

fn discover_program(
    directories: &[(PathBuf, &'static str)],
    executable: &str,
    read_version: bool,
) -> ProgramDiscovery {
    for (directory, source) in directories {
        let candidate = directory.join(executable);
        if !candidate.is_file() {
            continue;
        }
        let launch = if read_version {
            Command::new(&candidate).arg("-V").output()
        } else {
            Command::new(&candidate).output()
        };
        match launch {
            Ok(output) if read_version && !output.status.success() => {
                return ProgramDiscovery {
                    status: ProgramStatus::Fail,
                    path: None,
                    version: None,
                    source: Some((*source).to_owned()),
                    detail: Some(format!(
                        "{} -V returned {}",
                        candidate.display(),
                        output.status
                    )),
                };
            }
            Ok(output) => {
                let version = read_version.then(|| first_output_line(&output)).flatten();
                return ProgramDiscovery {
                    status: ProgramStatus::Pass,
                    path: Some(candidate),
                    version,
                    source: Some((*source).to_owned()),
                    detail: None,
                };
            }
            Err(error) => {
                return ProgramDiscovery {
                    status: ProgramStatus::Fail,
                    path: None,
                    version: None,
                    source: Some((*source).to_owned()),
                    detail: Some(error.to_string()),
                };
            }
        }
    }
    ProgramDiscovery {
        status: ProgramStatus::Fail,
        path: None,
        version: None,
        source: None,
        detail: Some(format!("{executable} not found")),
    }
}

fn default_search_directories() -> Vec<(PathBuf, &'static str)> {
    let mut directories = Vec::new();
    #[cfg(windows)]
    if let Some(windows) = env::var_os("WINDIR") {
        directories.push((
            PathBuf::from(windows).join("System32").join("OpenSSH"),
            "Windows capability",
        ));
    }
    #[cfg(target_os = "macos")]
    {
        directories.extend([
            (PathBuf::from("/usr/bin"), "macOS system"),
            (PathBuf::from("/opt/homebrew/opt/openssh/bin"), "Homebrew"),
            (PathBuf::from("/usr/local/opt/openssh/bin"), "Homebrew"),
        ]);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    directories.extend([
        (PathBuf::from("/usr/bin"), "system"),
        (PathBuf::from("/bin"), "system"),
        (PathBuf::from("/usr/local/bin"), "system"),
    ]);
    directories
}

fn normalized_architecture() -> &'static str {
    match env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn first_output_line(output: &Output) -> Option<String> {
    [&output.stderr[..], &output.stdout[..]]
        .into_iter()
        .flat_map(|bytes| {
            String::from_utf8_lossy(bytes)
                .lines()
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .map(|line| line.trim().to_owned())
        .find(|line| !line.is_empty())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshErrorKind {
    NotInstalled,
    HostKeyUnknown,
    HostKeyChanged,
    Authentication,
    Connection,
    Execution,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct SshError {
    kind: SshErrorKind,
    message: String,
    diagnostic: Option<String>,
}

impl SshError {
    fn new(kind: SshErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            diagnostic: None,
        }
    }

    fn launch(operation: &str, error: io::Error) -> Self {
        Self {
            kind: if error.kind() == io::ErrorKind::NotFound {
                SshErrorKind::NotInstalled
            } else {
                SshErrorKind::Execution
            },
            message: format!("无法启动 {operation}"),
            diagnostic: Some(error.to_string()),
        }
    }

    fn from_output(message: &str, output: &Output) -> Self {
        let diagnostic = String::from_utf8_lossy(&output.stderr)
            .lines()
            .take(8)
            .collect::<Vec<_>>()
            .join(" | ");
        let kind = classify_diagnostic(&diagnostic);
        Self {
            kind,
            message: message.to_owned(),
            diagnostic: (!diagnostic.is_empty()).then_some(diagnostic),
        }
    }

    pub fn code(&self) -> &'static str {
        match self.kind {
            SshErrorKind::NotInstalled => "SSH_CLIENT_MISSING",
            SshErrorKind::HostKeyUnknown => "SSH_HOST_KEY_UNKNOWN",
            SshErrorKind::HostKeyChanged => "SSH_HOST_KEY_CHANGED",
            SshErrorKind::Authentication => "SSH_AUTHENTICATION_FAILED",
            SshErrorKind::Connection => "SSH_CONNECTION_FAILED",
            SshErrorKind::Execution => "SSH_EXECUTION_FAILED",
        }
    }

    pub fn public_message(&self) -> &str {
        &self.message
    }

    pub fn diagnostic(&self) -> Option<&str> {
        self.diagnostic.as_deref()
    }
}

fn classify_diagnostic(diagnostic: &str) -> SshErrorKind {
    let lowercase = diagnostic.to_ascii_lowercase();
    if lowercase.contains("remote host identification has changed") {
        SshErrorKind::HostKeyChanged
    } else if lowercase.contains("host key verification failed")
        || lowercase.contains("no host key is known")
    {
        SshErrorKind::HostKeyUnknown
    } else if lowercase.contains("permission denied") {
        SshErrorKind::Authentication
    } else if lowercase.contains("connection refused")
        || lowercase.contains("connection timed out")
        || lowercase.contains("could not resolve hostname")
    {
        SshErrorKind::Connection
    } else {
        SshErrorKind::Execution
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_errors_have_stable_host_key_and_authentication_codes() {
        let cases = [
            ("Host key verification failed.", "SSH_HOST_KEY_UNKNOWN"),
            (
                "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!",
                "SSH_HOST_KEY_CHANGED",
            ),
            (
                "Permission denied (publickey).",
                "SSH_AUTHENTICATION_FAILED",
            ),
            ("Connection refused", "SSH_CONNECTION_FAILED"),
        ];
        for (stderr, expected) in cases {
            let error = SshError::new(classify_diagnostic(stderr), "probe");
            assert_eq!(error.code(), expected);
        }
    }

    #[cfg(unix)]
    #[test]
    fn discovery_uses_path_before_platform_defaults() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().expect("temporary directory");
        for name in ["ssh", "scp"] {
            let path = temporary.path().join(name);
            fs::write(&path, "#!/bin/sh\necho fake-openssh >&2\nexit 0\n").expect("fake program");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("program mode");
        }
        let path = env::join_paths([temporary.path()]).expect("test path");
        let report = discover_openssh_in(Some(&path), Vec::new());
        assert_eq!(report.ssh.status, ProgramStatus::Pass);
        assert_eq!(report.scp.status, ProgramStatus::Pass);
        assert_eq!(report.ssh.source.as_deref(), Some("PATH"));
        assert_eq!(report.ssh.version.as_deref(), Some("fake-openssh"));
    }

    #[cfg(unix)]
    #[test]
    fn fake_ssh_and_scp_processes_receive_non_interactive_arguments() {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().expect("temporary directory");
        let ssh = temporary.path().join("ssh");
        fs::write(
            &ssh,
            "#!/bin/sh\ncase \"$*\" in *meowai-ssh-ok*) printf meowai-ssh-ok;; *) cat >/dev/null; printf executed;; esac\n",
        )
        .expect("fake ssh");
        let scp = temporary.path().join("scp");
        fs::write(&scp, "#!/bin/sh\nexit 0\n").expect("fake scp");
        for path in [&ssh, &scp] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("program mode");
        }
        let client = SshClient::from_programs(ssh, scp);
        client.probe("user@example.test").expect("probe");
        let output = client
            .exec("user@example.test", "sh -s", b"printf safe")
            .expect("exec");
        assert!(output.status.success());
        assert_eq!(output.stdout, b"executed");
        let local = temporary.path().join("payload");
        fs::write(&local, b"payload").expect("payload");
        assert!(
            client
                .upload("user@example.test", &local, "/tmp/payload")
                .expect("upload")
                .status
                .success()
        );
    }
}
