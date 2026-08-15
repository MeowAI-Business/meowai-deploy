pub mod compose;
pub mod kuma;
pub mod newapi;

use std::{
    borrow::Cow,
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

use shell_escape::escape;

use crate::{
    config::Target,
    error::{AppError, Result},
    registry::RegistryCredentials,
    security::{sha256_hex, write_private_file},
};

const PRIVILEGED_SCRIPT_RUNNER: &str = r#"if [ "$(id -u)" -eq 0 ]; then
    exec sh -s
elif command -v sudo >/dev/null 2>&1 && sudo -n sh -c true >/dev/null 2>&1; then
    exec sudo -n sh -s
else
    exec sh -s
fi"#;

#[derive(Clone, Debug)]
pub struct TargetExecutor {
    target: Target,
    directory: PathBuf,
}

pub struct TargetEndpoint {
    base_url: String,
    tunnel: Option<std::process::Child>,
}

impl TargetEndpoint {
    pub fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for TargetEndpoint {
    fn drop(&mut self) {
        if let Some(child) = &mut self.tunnel {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl TargetExecutor {
    pub fn new(target: Target, directory: PathBuf) -> Self {
        Self { target, directory }
    }

    pub fn prepare(&self) -> Result<()> {
        self.validate_access()?;
        self.run_script(&format!(
            "umask 077\nmkdir -p {root}/data/newapi {root}/data/postgres {root}/data/redis {root}/data/uptime-kuma\nchmod 700 {root} {root}/data {root}/data/newapi {root}/data/postgres {root}/data/redis {root}/data/uptime-kuma",
            root = quote_path(&self.directory)
        ))?;
        Ok(())
    }

    pub fn validate_access(&self) -> Result<()> {
        let directory = quote_path(&self.directory);
        let script = format!(
            r#"set -eu
if [ "$(id -u)" -eq 0 ]; then
    exit 0
fi
if command -v sudo >/dev/null 2>&1 && sudo -n sh -c true >/dev/null 2>&1; then
    exit 0
fi
path={directory}
while [ ! -e "$path" ] && [ "$path" != / ]; do
    path=$(dirname "$path")
done
if [ -d "$path" ] && [ -w "$path" ] && docker info >/dev/null 2>&1; then
    exit 0
fi
printf '%s\n' '当前用户不是 root、没有可用的 sudo，且无法写入部署目录并使用 Docker' >&2
exit 1"#,
        );
        let output = match &self.target {
            Target::Local => {
                let direct =
                    Command::new("sh")
                        .args(["-c", &script])
                        .output()
                        .map_err(|error| {
                            AppError::Target(format!("failed to validate local access: {error}"))
                        })?;
                if direct.status.success() {
                    return Ok(());
                }
                Command::new("sudo")
                    .arg("-v")
                    .status()
                    .map_err(|error| {
                        AppError::Target(format!("本机部署目录需要提权，但无法启动 sudo: {error}"))
                    })
                    .and_then(|status| {
                        if status.success() {
                            Ok(())
                        } else {
                            Err(AppError::Target(format!("sudo 身份验证失败（{status}）")))
                        }
                    })?;
                return Ok(());
            }
            Target::Ssh { destination } => Command::new("ssh")
                .args(["-o", "ConnectTimeout=10"])
                .arg(destination)
                .arg(script)
                .output()
                .map_err(|error| AppError::Target(format!("failed to start ssh: {error}")))?,
        };
        require_success("验证 SSH 连接和部署权限", output)?;
        Ok(())
    }

    pub fn fingerprint(&self) -> Result<String> {
        let output = self.run_script(
            "host=$(uname -n 2>/dev/null || hostname)\nif [ -r /etc/machine-id ]; then machine=$(cat /etc/machine-id); else machine=unknown; fi\nprintf '%s|%s' \"$host\" \"$machine\"",
        )?;
        let identity = format!(
            "{}|{}",
            self.label(),
            String::from_utf8_lossy(&output.stdout)
        );
        Ok(sha256_hex(identity.as_bytes()))
    }

    pub fn label(&self) -> String {
        match &self.target {
            Target::Local => "local".to_owned(),
            Target::Ssh { destination } => format!("ssh:{destination}"),
        }
    }

    pub fn write_file(&self, relative: &str, content: &[u8], private: bool) -> Result<()> {
        validate_relative_name(relative)?;
        let destination = self.directory.join(relative);
        match &self.target {
            Target::Local => {
                let temporary = tempfile::NamedTempFile::new().map_err(|error| {
                    AppError::Target(format!("create local upload file: {error}"))
                })?;
                write_private_file(temporary.path(), content)?;
                let mode = if private { "600" } else { "644" };
                self.run_script(&format!(
                    "install -m {mode} {temporary} {destination}",
                    temporary = quote_path(temporary.path()),
                    destination = quote_path(&destination),
                ))?;
                Ok(())
            }
            Target::Ssh { destination: host } => {
                let temporary = tempfile::NamedTempFile::new()
                    .map_err(|error| AppError::Target(format!("create upload file: {error}")))?;
                fs::write(temporary.path(), content)
                    .map_err(|error| AppError::Target(format!("write upload file: {error}")))?;
                let remote_temporary = remote_upload_path(relative, temporary.path());
                let remote_spec = format!("{host}:{remote_temporary}");
                let output = Command::new("scp")
                    .args(["-q", "-p"])
                    .arg(temporary.path())
                    .arg(&remote_spec)
                    .output()
                    .map_err(|error| AppError::Target(format!("failed to start scp: {error}")))?;
                require_success("scp upload", output)?;
                let mode = if private { "600" } else { "644" };
                self.run_script(&format!(
                    "temporary={temporary}\ntrap 'rm -f \"$temporary\"' EXIT HUP INT TERM\nchmod {mode} \"$temporary\"\nmv \"$temporary\" {destination}",
                    temporary = quote(&remote_temporary),
                    destination = quote_path(&destination)
                ))?;
                Ok(())
            }
        }
    }

    pub fn allocate_port(&self, requested: u16, excluded: &[u16]) -> Result<u16> {
        for candidate in requested..=u16::MAX {
            if excluded.contains(&candidate) {
                continue;
            }
            if self.port_available(candidate)? {
                return Ok(candidate);
            }
        }
        Err(AppError::Target(format!(
            "no available TCP port at or above {requested}"
        )))
    }

    fn port_available(&self, port: u16) -> Result<bool> {
        if matches!(self.target, Target::Local) {
            let loopback = SocketAddr::from(([127, 0, 0, 1], port));
            if TcpStream::connect_timeout(&loopback, Duration::from_millis(100)).is_ok() {
                return Ok(false);
            }
            return Ok(TcpListener::bind(("0.0.0.0", port)).is_ok());
        }
        let script = format!(
            "if command -v ss >/dev/null 2>&1; then ss -H -ltn | awk '{{print $4}}' | grep -Eq '[:.]{}$' && exit 1; fi\ndocker ps --format '{{{{.Ports}}}}' 2>/dev/null | grep -Eq '[:.]{}->' && exit 1\nexit 0",
            port, port
        );
        let output = self.run_script_raw(&script)?;
        match output.status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(target_output_error("check remote port", &output)),
        }
    }

    pub fn compose(&self, project: &str, args: &[&str]) -> Result<Output> {
        let arguments = args
            .iter()
            .map(|value| quote(value))
            .collect::<Vec<_>>()
            .join(" ");
        self.run_script(&format!(
            "cd {directory}\ndocker compose --env-file secrets.env -p {project} {arguments}",
            directory = quote_path(&self.directory),
            project = quote(project),
        ))
    }

    pub fn pull_image_with_registry_credentials(
        &self,
        image: &str,
        registry: &str,
        credentials: &RegistryCredentials,
    ) -> Result<Output> {
        tracing::debug!(
            registry,
            target = %self.label(),
            "pulling image with temporary registry credentials"
        );
        let script = format!(
            r#"set -eu
registry_config=$(mktemp -d)
trap 'rm -rf "$registry_config"' EXIT HUP INT TERM
printf '%s' {password} | docker --config "$registry_config" login {registry} --username {username} --password-stdin >/dev/null
docker --config "$registry_config" pull --platform linux/amd64 {image}"#,
            password = quote(credentials.password()),
            registry = quote(registry),
            username = quote(credentials.username()),
            image = quote(image),
        );
        self.run_script(&script)
    }

    pub fn endpoint(&self, target_port: u16) -> Result<TargetEndpoint> {
        match &self.target {
            Target::Local => Ok(TargetEndpoint {
                base_url: format!("http://127.0.0.1:{target_port}"),
                tunnel: None,
            }),
            Target::Ssh { destination } => {
                let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| {
                    AppError::Target(format!("reserve SSH tunnel port: {error}"))
                })?;
                let local_port = listener
                    .local_addr()
                    .map_err(|error| AppError::Target(format!("read tunnel port: {error}")))?
                    .port();
                drop(listener);
                let mut child = Command::new("ssh")
                    .args(["-o", "ExitOnForwardFailure=yes", "-N", "-L"])
                    .arg(format!("127.0.0.1:{local_port}:127.0.0.1:{target_port}"))
                    .arg(destination)
                    .spawn()
                    .map_err(|error| AppError::Target(format!("open SSH tunnel: {error}")))?;
                let tunnel_address = SocketAddr::from(([127, 0, 0, 1], local_port));
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    if let Some(status) = child
                        .try_wait()
                        .map_err(|error| AppError::Target(format!("check SSH tunnel: {error}")))?
                    {
                        return Err(AppError::Target(format!(
                            "SSH tunnel exited early with {status}"
                        )));
                    }
                    if TcpStream::connect_timeout(&tunnel_address, Duration::from_millis(100))
                        .is_ok()
                    {
                        break;
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(AppError::Target(
                            "SSH tunnel did not become ready within 10 seconds".to_owned(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                Ok(TargetEndpoint {
                    base_url: format!("http://127.0.0.1:{local_port}"),
                    tunnel: Some(child),
                })
            }
        }
    }

    pub fn run_script(&self, script: &str) -> Result<Output> {
        let output = self.run_script_raw(script)?;
        require_success("target script", output)
    }

    pub fn run_script_streaming<F>(&self, script: &str, mut on_stdout: F) -> Result<Output>
    where
        F: FnMut(&str),
    {
        let mut child = self.spawn_script(script)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| AppError::Target("target shell stdout unavailable".to_owned()))?;
        let mut stderr = child
            .stderr
            .take()
            .ok_or_else(|| AppError::Target("target shell stderr unavailable".to_owned()))?;
        let stderr_reader = thread::spawn(move || {
            let mut bytes = Vec::new();
            stderr.read_to_end(&mut bytes)?;
            Ok::<Vec<u8>, std::io::Error>(bytes)
        });

        let mut stdout_bytes = Vec::new();
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = Vec::new();
            let read = match reader.read_until(b'\n', &mut line) {
                Ok(read) => read,
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let _ = stderr_reader.join();
                    return Err(AppError::Target(format!("read target output: {error}")));
                }
            };
            if read == 0 {
                break;
            }
            stdout_bytes.extend_from_slice(&line);
            let text = String::from_utf8_lossy(&line);
            let text = text.trim_end_matches(['\r', '\n']);
            if !text.is_empty() {
                on_stdout(text);
            }
        }
        let status = child
            .wait()
            .map_err(|error| AppError::Target(format!("wait for target shell: {error}")))?;
        let stderr = stderr_reader
            .join()
            .map_err(|_| AppError::Target("target stderr reader panicked".to_owned()))?
            .map_err(|error| AppError::Target(format!("read target error output: {error}")))?;
        require_success(
            "target script",
            Output {
                status,
                stdout: stdout_bytes,
                stderr,
            },
        )
    }

    pub fn run_in_directory(&self, script: &str) -> Result<Output> {
        self.run_script(&format!(
            "set -eu\ncd {}\n{}",
            quote_path(&self.directory),
            script
        ))
    }

    fn run_script_raw(&self, script: &str) -> Result<Output> {
        self.spawn_script(script)?
            .wait_with_output()
            .map_err(|error| AppError::Target(format!("wait for target shell: {error}")))
    }

    fn spawn_script(&self, script: &str) -> Result<Child> {
        match &self.target {
            Target::Local => {
                let mut child = Command::new("sh")
                    .args(["-c", PRIVILEGED_SCRIPT_RUNNER])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|error| AppError::Target(format!("failed to start shell: {error}")))?;
                let mut stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| AppError::Target("target shell stdin unavailable".to_owned()))?;
                stdin
                    .write_all(script.as_bytes())
                    .map_err(|error| AppError::Target(format!("write shell input: {error}")))?;
                drop(stdin);
                Ok(child)
            }
            Target::Ssh { destination } => {
                let mut child = Command::new("ssh")
                    .arg(destination)
                    .arg(PRIVILEGED_SCRIPT_RUNNER)
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|error| AppError::Target(format!("failed to start ssh: {error}")))?;
                let mut stdin = child
                    .stdin
                    .take()
                    .ok_or_else(|| AppError::Target("ssh stdin unavailable".to_owned()))?;
                stdin
                    .write_all(script.as_bytes())
                    .map_err(|error| AppError::Target(format!("write ssh input: {error}")))?;
                drop(stdin);
                Ok(child)
            }
        }
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

fn validate_relative_name(relative: &str) -> Result<()> {
    let path = Path::new(relative);
    if relative.is_empty()
        || path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::RootDir
            )
        })
    {
        return Err(AppError::Target(format!(
            "unsafe deployment file name: {relative}"
        )));
    }
    Ok(())
}

fn quote_path(path: &Path) -> String {
    quote(&path.to_string_lossy())
}

fn quote(value: &str) -> String {
    escape(Cow::Borrowed(value)).into_owned()
}

fn remote_upload_path(relative: &str, local_temporary: &Path) -> String {
    let identity = format!(
        "{}:{relative}:{}",
        std::process::id(),
        local_temporary.display()
    );
    format!(
        "/tmp/meowai-deploy-upload-{}-{}",
        std::process::id(),
        &sha256_hex(identity.as_bytes())[..16]
    )
}

fn require_success(operation: &str, output: Output) -> Result<Output> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(target_output_error(operation, &output))
    }
}

fn target_output_error(operation: &str, output: &Output) -> AppError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(24)
        .map(|line| format!("  {line}"))
        .collect::<Vec<_>>()
        .join("\n");
    AppError::Target(format!(
        "{operation} exited with {}{}",
        output.status,
        if detail.is_empty() {
            String::new()
        } else {
            format!("\n{detail}")
        }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn occupied_local_port_is_not_returned() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind occupied port");
        let occupied = listener.local_addr().expect("read occupied port").port();
        if occupied == u16::MAX {
            return;
        }
        let executor = TargetExecutor::new(
            Target::Local,
            tempfile::tempdir()
                .expect("create temporary directory")
                .path()
                .to_owned(),
        );
        let selected = executor
            .allocate_port(occupied, &[])
            .expect("find the next available port");
        assert_ne!(selected, occupied);
    }

    #[test]
    fn target_scripts_support_root_passwordless_sudo_and_unprivileged_users() {
        assert!(PRIVILEGED_SCRIPT_RUNNER.contains("id -u"));
        assert!(PRIVILEGED_SCRIPT_RUNNER.contains("sudo -n sh -c true"));
        assert!(PRIVILEGED_SCRIPT_RUNNER.contains("sudo -n sh -s"));
        assert!(PRIVILEGED_SCRIPT_RUNNER.contains("exec sh -s"));
    }

    #[test]
    fn remote_uploads_use_a_temporary_directory_writable_by_the_ssh_user() {
        let path = remote_upload_path("docker-compose.yml", Path::new("/tmp/local-a"));
        assert!(path.starts_with("/tmp/meowai-deploy-upload-"));
        assert!(!path.contains("docker-compose.yml"));
        assert_eq!(
            path,
            remote_upload_path("docker-compose.yml", Path::new("/tmp/local-a"))
        );
        assert_ne!(
            path,
            remote_upload_path("secrets.env", Path::new("/tmp/local-a"))
        );
        assert_ne!(
            path,
            remote_upload_path("docker-compose.yml", Path::new("/tmp/local-b"))
        );
    }

    #[test]
    fn streaming_scripts_report_stdout_lines() {
        let executor = TargetExecutor::new(
            Target::Local,
            tempfile::tempdir()
                .expect("create temporary directory")
                .path()
                .to_owned(),
        );
        let mut lines = Vec::new();
        let output = executor
            .run_script_streaming("printf 'starting\\nhealthy\\n'", |line| {
                lines.push(line.to_owned())
            })
            .expect("run streaming script");
        assert_eq!(lines, ["starting", "healthy"]);
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            "starting\nhealthy\n"
        );
    }

    #[test]
    fn target_errors_keep_diagnostics_on_separate_lines() {
        let output = Command::new("sh")
            .args(["-c", "printf 'first\\nsecond\\n' >&2; exit 1"])
            .output()
            .expect("run failing command");
        let error = target_output_error("probe", &output).to_string();
        assert!(error.contains("probe exited with exit status: 1"));
        assert!(error.contains("\n  first\n  second"));
    }
}
