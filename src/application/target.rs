use std::path::PathBuf;

use secrecy::SecretString;

use super::{
    error::{ApplicationError, ApplicationResult, ErrorCategory},
    input::{self, DeploymentTargetInput, InputField},
    operation::CancellationToken,
};
use crate::{
    config::Target, error::AppError, registry::latest_image_metadata, target::TargetExecutor,
};

#[derive(Clone, Debug)]
pub struct DeploymentTargetProbeRequest {
    pub target: DeploymentTargetInput,
    pub directory: PathBuf,
    pub newapi_port: u16,
    pub kuma_port: u16,
    pub ssh_password: Option<SecretString>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentTargetProbe {
    pub fingerprint: String,
    pub newapi_port: u16,
    pub kuma_port: u16,
}

pub fn probe_deployment_connection(
    target: DeploymentTargetInput,
    ssh_password: Option<SecretString>,
    cancellation: &CancellationToken,
) -> ApplicationResult<String> {
    let target = match target {
        DeploymentTargetInput::Local => Target::Local,
        DeploymentTargetInput::Ssh { destination } => {
            input::validate_ssh_destination(&destination).map_err(validation_error)?;
            Target::Ssh { destination }
        }
    };
    check_cancellation(cancellation)?;
    TargetExecutor::new(target, PathBuf::new())
        .with_ssh_password(ssh_password)
        .fingerprint()
        .map_err(target_error)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePortRequest {
    pub destination: String,
    pub directory: PathBuf,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageResolutionRequest {
    pub image: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImageResolution {
    pub image: String,
    pub immutable_ref: String,
    pub updated_at: Option<String>,
}

pub fn probe_ssh_target(
    destination: &str,
    directory: PathBuf,
    cancellation: &CancellationToken,
) -> ApplicationResult<String> {
    input::validate_ssh_destination(destination).map_err(validation_error)?;
    input::validate_remote_directory(&directory).map_err(validation_error)?;
    check_cancellation(cancellation)?;
    let executor = TargetExecutor::new(
        Target::Ssh {
            destination: destination.to_owned(),
        },
        directory,
    );
    executor.validate_access().map_err(target_error)?;
    check_cancellation(cancellation)?;
    executor.fingerprint().map_err(target_error)
}

pub fn validate_remote_directory(
    destination: &str,
    directory: PathBuf,
    cancellation: &CancellationToken,
) -> ApplicationResult<()> {
    probe_ssh_target(destination, directory, cancellation).map(|_| ())
}

pub fn check_remote_port(
    request: RemotePortRequest,
    cancellation: &CancellationToken,
) -> ApplicationResult<bool> {
    input::validate_ssh_destination(&request.destination).map_err(validation_error)?;
    input::validate_remote_directory(&request.directory).map_err(validation_error)?;
    if request.port == 0 {
        return Err(ApplicationError::new(
            ErrorCategory::Validation,
            "INVALID_PORT",
            "端口必须在 1 到 65535 之间",
            true,
        )
        .with_field(InputField::NewApiPort));
    }
    check_cancellation(cancellation)?;
    let executor = TargetExecutor::new(
        Target::Ssh {
            destination: request.destination,
        },
        request.directory,
    );
    let available = executor
        .is_port_available(request.port)
        .map_err(target_error)?;
    check_cancellation(cancellation)?;
    Ok(available)
}

pub fn probe_deployment_target(
    request: DeploymentTargetProbeRequest,
    cancellation: &CancellationToken,
) -> ApplicationResult<DeploymentTargetProbe> {
    input::validate_ports(request.newapi_port, request.kuma_port).map_err(validation_error)?;
    let target = match request.target {
        DeploymentTargetInput::Local => {
            input::validate_directory(&request.directory).map_err(validation_error)?;
            Target::Local
        }
        DeploymentTargetInput::Ssh { destination } => {
            input::validate_ssh_destination(&destination).map_err(validation_error)?;
            input::validate_remote_directory(&request.directory).map_err(validation_error)?;
            Target::Ssh { destination }
        }
    };
    check_cancellation(cancellation)?;
    let executor =
        TargetExecutor::new(target, request.directory).with_ssh_password(request.ssh_password);
    executor.validate_access().map_err(target_error)?;
    check_cancellation(cancellation)?;
    let fingerprint = executor.fingerprint().map_err(target_error)?;
    require_requested_ports(&executor, request.newapi_port, request.kuma_port)?;
    check_cancellation(cancellation)?;
    Ok(DeploymentTargetProbe {
        fingerprint,
        newapi_port: request.newapi_port,
        kuma_port: request.kuma_port,
    })
}

fn require_requested_ports(
    executor: &TargetExecutor,
    newapi_port: u16,
    kuma_port: u16,
) -> ApplicationResult<()> {
    let newapi_available = executor
        .is_port_available(newapi_port)
        .map_err(target_error)?;
    let kuma_available = executor
        .is_port_available(kuma_port)
        .map_err(target_error)?;
    if newapi_available && kuma_available {
        return Ok(());
    }

    let mut conflicts = Vec::new();
    let suggested_newapi = if newapi_available {
        newapi_port
    } else {
        let suggestion = executor
            .allocate_port(newapi_port, &[kuma_port])
            .map_err(target_error)?;
        conflicts.push(format!(
            "New API 端口 {newapi_port} 已被占用，可改用 {suggestion}"
        ));
        suggestion
    };
    if !kuma_available {
        let suggestion = executor
            .allocate_port(kuma_port, &[suggested_newapi])
            .map_err(target_error)?;
        conflicts.push(format!(
            "Uptime Kuma 端口 {kuma_port} 已被占用，可改用 {suggestion}"
        ));
    }

    Err(ApplicationError::new(
        ErrorCategory::Conflict,
        "DEPLOYMENT_PORT_OCCUPIED",
        conflicts.join("；"),
        true,
    ))
}

pub async fn resolve_latest_image(
    request: ImageResolutionRequest,
    cancellation: &CancellationToken,
) -> ApplicationResult<ImageResolution> {
    if request.image.trim().is_empty() {
        return Err(ApplicationError::new(
            ErrorCategory::Validation,
            "EMPTY_IMAGE",
            "镜像名称不能为空",
            true,
        )
        .with_field(InputField::Image));
    }
    check_cancellation(cancellation)?;
    let metadata = latest_image_metadata(&request.image)
        .await
        .map_err(|error| {
            ApplicationError::new(
                ErrorCategory::Target,
                "IMAGE_RESOLUTION_FAILED",
                "无法解析镜像 digest，请检查镜像名称和仓库访问权限",
                true,
            )
            .with_diagnostic(error.to_string())
        })?;
    check_cancellation(cancellation)?;
    input::validate_image_ref(&metadata.digest).map_err(validation_error)?;
    Ok(ImageResolution {
        image: request.image,
        immutable_ref: metadata.digest,
        updated_at: metadata.updated_at,
    })
}

fn check_cancellation(cancellation: &CancellationToken) -> ApplicationResult<()> {
    if cancellation.is_cancelled() {
        Err(ApplicationError::new(
            ErrorCategory::Cancelled,
            "OPERATION_CANCELLED",
            "操作已取消",
            false,
        ))
    } else {
        Ok(())
    }
}

fn validation_error(error: input::ValidationError) -> ApplicationError {
    ApplicationError::new(
        ErrorCategory::Validation,
        error.code.as_str(),
        error.message,
        error.retryable,
    )
    .with_field(error.field)
}

fn target_error(error: AppError) -> ApplicationError {
    if matches!(&error, AppError::Target(message) if message.starts_with("SSH 认证失败")) {
        return ApplicationError::new(
            ErrorCategory::Authentication,
            "SSH_AUTHENTICATION_FAILED",
            "SSH 认证失败，请检查密码、密钥或 ssh-agent。",
            true,
        );
    }
    ApplicationError::new(
        ErrorCategory::Target,
        "TARGET_PROBE_FAILED",
        "无法连接部署目标，或目录权限、端口、Docker 检查未通过",
        true,
    )
    .with_diagnostic(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn cancelled_target_probe_does_not_start_a_process() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let error = probe_ssh_target(
            "deploy@127.0.0.1",
            PathBuf::from("/opt/meowai-deploy/newapi"),
            &cancellation,
        )
        .expect_err("cancelled probe");
        assert_eq!(error.category, ErrorCategory::Cancelled);
        assert_eq!(error.code, "OPERATION_CANCELLED");
    }

    #[test]
    fn occupied_requested_ports_return_distinct_suggestions_without_rewriting_values() {
        let newapi = TcpListener::bind(("127.0.0.1", 0)).expect("bind New API port");
        let newapi_port = newapi.local_addr().expect("New API address").port();
        let kuma = TcpListener::bind(("127.0.0.1", 0)).expect("bind Kuma port");
        let kuma_port = kuma.local_addr().expect("Kuma address").port();
        let executor = TargetExecutor::new(
            Target::Local,
            tempfile::tempdir()
                .expect("temporary directory")
                .path()
                .to_owned(),
        );

        let error = require_requested_ports(&executor, newapi_port, kuma_port)
            .expect_err("occupied ports must fail");

        assert_eq!(error.code, "DEPLOYMENT_PORT_OCCUPIED");
        assert!(
            error
                .message
                .contains(&format!("New API 端口 {newapi_port}"))
        );
        assert!(
            error
                .message
                .contains(&format!("Uptime Kuma 端口 {kuma_port}"))
        );
        let suggestions = error
            .message
            .split("可改用 ")
            .skip(1)
            .filter_map(|part| {
                part.split(|character: char| !character.is_ascii_digit())
                    .next()
            })
            .collect::<Vec<_>>();
        assert_eq!(suggestions.len(), 2);
        assert_ne!(suggestions[0], suggestions[1]);
    }

    #[tokio::test]
    async fn cancelled_image_resolution_does_not_access_a_registry() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let error = resolve_latest_image(
            ImageResolutionRequest {
                image: "registry.invalid/newapi".to_owned(),
            },
            &cancellation,
        )
        .await
        .expect_err("cancelled image resolution");
        assert_eq!(error.category, ErrorCategory::Cancelled);
    }
}
