pub mod compose;
pub mod kuma;
pub mod newapi;

use std::{
    borrow::Cow,
    fs,
    io::Write,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::Duration,
};

use shell_escape::escape;

use crate::{
    config::Target,
    error::{AppError, Result},
    security::{sha256_hex, write_private_file},
};

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
        if let Target::Ssh { destination } = &self.target {
            let status = Command::new("ssh")
                .args(["-o", "ConnectTimeout=10", destination, "true"])
                .status()
                .map_err(|error| AppError::Target(format!("failed to start ssh: {error}")))?;
            if !status.success() {
                return Err(AppError::Target(format!(
                    "SSH connection to {destination} failed"
                )));
            }
        }
        self.run_script(&format!(
            "umask 077\nmkdir -p {root}/data/newapi {root}/data/postgres {root}/data/redis {root}/data/uptime-kuma\nchmod 700 {root} {root}/data {root}/data/newapi {root}/data/postgres {root}/data/redis {root}/data/uptime-kuma",
            root = quote_path(&self.directory)
        ))?;
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
                if private {
                    write_private_file(&destination, content)
                } else {
                    fs::write(&destination, content).map_err(|source| AppError::WriteFile {
                        path: destination,
                        source,
                    })?;
                    Ok(())
                }
            }
            Target::Ssh { destination: host } => {
                let temporary = tempfile::NamedTempFile::new()
                    .map_err(|error| AppError::Target(format!("create upload file: {error}")))?;
                fs::write(temporary.path(), content)
                    .map_err(|error| AppError::Target(format!("write upload file: {error}")))?;
                let remote_temporary = format!(
                    "{}.tmp-{}",
                    destination.to_string_lossy(),
                    std::process::id()
                );
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
                    "chmod {mode} {temporary}\nmv {temporary} {destination}",
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
                std::thread::sleep(std::time::Duration::from_millis(350));
                if let Some(status) = child
                    .try_wait()
                    .map_err(|error| AppError::Target(format!("check SSH tunnel: {error}")))?
                {
                    return Err(AppError::Target(format!(
                        "SSH tunnel exited early with {status}"
                    )));
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

    pub fn run_in_directory(&self, script: &str) -> Result<Output> {
        self.run_script(&format!(
            "set -eu\ncd {}\n{}",
            quote_path(&self.directory),
            script
        ))
    }

    fn run_script_raw(&self, script: &str) -> Result<Output> {
        match &self.target {
            Target::Local => {
                let mut child = Command::new("sh")
                    .arg("-s")
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|error| AppError::Target(format!("failed to start shell: {error}")))?;
                child
                    .stdin
                    .as_mut()
                    .ok_or_else(|| AppError::Target("target shell stdin unavailable".to_owned()))?
                    .write_all(script.as_bytes())
                    .map_err(|error| AppError::Target(format!("write shell input: {error}")))?;
                child
                    .wait_with_output()
                    .map_err(|error| AppError::Target(format!("wait for shell: {error}")))
            }
            Target::Ssh { destination } => {
                let mut child = Command::new("ssh")
                    .arg(destination)
                    .args(["sh", "-s"])
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .map_err(|error| AppError::Target(format!("failed to start ssh: {error}")))?;
                child
                    .stdin
                    .as_mut()
                    .ok_or_else(|| AppError::Target("ssh stdin unavailable".to_owned()))?
                    .write_all(script.as_bytes())
                    .map_err(|error| AppError::Target(format!("write ssh input: {error}")))?;
                child
                    .wait_with_output()
                    .map_err(|error| AppError::Target(format!("wait for ssh: {error}")))
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

fn require_success(operation: &str, output: Output) -> Result<Output> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(target_output_error(operation, &output))
    }
}

fn target_output_error(operation: &str, output: &Output) -> AppError {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.lines().take(8).collect::<Vec<_>>().join(" | ");
    AppError::Target(format!(
        "{operation} exited with {}{}",
        output.status,
        if detail.is_empty() {
            String::new()
        } else {
            format!(": {detail}")
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
}
