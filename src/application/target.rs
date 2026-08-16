use std::path::PathBuf;

use super::{
    error::{ApplicationError, ApplicationResult, ErrorCategory},
    input::{self, DeploymentTargetInput, InputField},
    operation::CancellationToken,
};
use crate::{
    config::Target, error::AppError, registry::latest_image_digest, target::TargetExecutor,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentTargetProbeRequest {
    pub target: DeploymentTargetInput,
    pub directory: PathBuf,
    pub newapi_port: u16,
    pub kuma_port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentTargetProbe {
    pub fingerprint: String,
    pub newapi_port: u16,
    pub kuma_port: u16,
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
    let executor = TargetExecutor::new(target, request.directory);
    executor.validate_access().map_err(target_error)?;
    check_cancellation(cancellation)?;
    let fingerprint = executor.fingerprint().map_err(target_error)?;
    let newapi_port = executor
        .allocate_port(request.newapi_port, &[])
        .map_err(target_error)?;
    let kuma_port = executor
        .allocate_port(request.kuma_port, &[newapi_port])
        .map_err(target_error)?;
    check_cancellation(cancellation)?;
    Ok(DeploymentTargetProbe {
        fingerprint,
        newapi_port,
        kuma_port,
    })
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
    let immutable_ref = latest_image_digest(&request.image)
        .await
        .map_err(target_error)?;
    check_cancellation(cancellation)?;
    input::validate_image_ref(&immutable_ref).map_err(validation_error)?;
    Ok(ImageResolution {
        image: request.image,
        immutable_ref,
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
    ApplicationError::new(
        ErrorCategory::Target,
        "TARGET_PROBE_FAILED",
        "无法验证下游目标",
        true,
    )
    .with_diagnostic(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
