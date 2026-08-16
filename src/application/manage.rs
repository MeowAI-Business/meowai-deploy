use std::collections::BTreeMap;

use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use super::{
    deployment_control,
    error::{ApplicationError, ApplicationResult, ErrorCategory, app_error, source_error},
    operation::CancellationToken,
};
use crate::{
    config::DeploymentConfig,
    source::SourceClient,
    source_key_store,
    state::{DOWNSTREAM_CLEANUP_PHASE, DeploymentState, ResourcePhase},
    storage::{self, CREDENTIALS_FILE, STATE_FILE},
    target::{
        TargetExecutor,
        compose::{DeploymentRuntime, DeploymentSecrets},
    },
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ContainerStatus {
    pub name: String,
    pub state: String,
    pub health: String,
    pub ports: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeploymentStatus {
    pub directory: String,
    pub newapi_bind: String,
    pub newapi_port: u16,
    pub kuma_bind: String,
    pub kuma_port: u16,
    pub image: String,
    pub image_ref: String,
    pub last_sync_at: i64,
    pub last_sync_success: bool,
    pub phases: BTreeMap<String, ResourcePhase>,
    pub containers: Vec<ContainerStatus>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CleanDeploymentOutcome {
    pub state_preserved: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RollbackDeploymentOutcome {
    pub source_tokens_revoked: usize,
    pub source_status_key_revoked: bool,
}

pub fn read_deployment_status(
    config: &DeploymentConfig,
    cancellation: &CancellationToken,
) -> ApplicationResult<DeploymentStatus> {
    check_cancellation(cancellation)?;
    let deployment = DeploymentRuntime::prepare(config, 0, "", 0, None).map_err(app_error)?;
    let compose = deployment
        .executor
        .compose(&config.container_name, &["ps", "--format", "json"])
        .map_err(app_error)?;
    check_cancellation(cancellation)?;
    Ok(DeploymentStatus {
        directory: deployment.state.directory.clone(),
        newapi_bind: config.newapi_bind.clone(),
        newapi_port: deployment.state.newapi_port,
        kuma_bind: config.kuma_bind.clone(),
        kuma_port: deployment.state.kuma_port,
        image: deployment.state.image.clone(),
        image_ref: deployment.state.image_ref.clone(),
        last_sync_at: deployment.state.last_sync_at,
        last_sync_success: deployment.state.last_sync_success,
        phases: deployment.state.phases.clone(),
        containers: parse_compose_status(&compose.stdout)?,
    })
}

pub async fn clean_deployment(
    config: &DeploymentConfig,
    cancellation: &CancellationToken,
) -> ApplicationResult<CleanDeploymentOutcome> {
    clean_deployment_with_ssh_password(config, cancellation, None).await
}

pub async fn clean_deployment_with_ssh_password(
    config: &DeploymentConfig,
    cancellation: &CancellationToken,
    ssh_password: Option<SecretString>,
) -> ApplicationResult<CleanDeploymentOutcome> {
    check_cancellation(cancellation)?;
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone())
        .with_ssh_password(ssh_password);
    executor.validate_access().map_err(app_error)?;
    let mut state = load_saved_deployment_state()?;
    if let Some(state) = &state {
        validate_cleanup_state(config, &executor, state)?;
    }
    let registration = deployment_control::load_registration()?;
    if let Some(registration) = &registration {
        let _ = deployment_control::queue_lifecycle(
            registration,
            "cleanup_started",
            "cleanup_started",
            "clean started",
        )
        .await?;
    }
    clean_downstream(config, &executor)?;
    check_cancellation(cancellation)?;
    if let Some(state) = &mut state {
        state.mark_phase(
            DOWNSTREAM_CLEANUP_PHASE,
            "DONE",
            "downstream resources removed",
        );
        persist_deployment_state(state)?;
    }
    if let Some(registration) = &registration {
        let _ = deployment_control::queue_lifecycle(
            registration,
            "removed",
            "removed",
            "clean completed",
        )
        .await?;
    }
    Ok(CleanDeploymentOutcome {
        state_preserved: state.is_some(),
    })
}

pub async fn rollback_deployment(
    config: &DeploymentConfig,
    source: Option<&mut SourceClient>,
    revoke_source: bool,
    cancellation: &CancellationToken,
) -> ApplicationResult<RollbackDeploymentOutcome> {
    rollback_deployment_with_ssh_password(config, source, revoke_source, cancellation, None).await
}

pub async fn rollback_deployment_with_ssh_password(
    config: &DeploymentConfig,
    source: Option<&mut SourceClient>,
    revoke_source: bool,
    cancellation: &CancellationToken,
    ssh_password: Option<SecretString>,
) -> ApplicationResult<RollbackDeploymentOutcome> {
    check_cancellation(cancellation)?;
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone())
        .with_ssh_password(ssh_password);
    executor.validate_access().map_err(app_error)?;
    let state = load_saved_deployment_state()?;
    if let Some(state) = &state {
        validate_cleanup_state(config, &executor, state)?;
    }

    let registration = deployment_control::load_registration()?;
    if let Some(registration) = &registration {
        let _ = deployment_control::queue_lifecycle(
            registration,
            "cleanup_started",
            "cleanup_started",
            "rollback started",
        )
        .await?;
    }
    let mut source_tokens_revoked = 0;
    let mut source_status_key_revoked = false;
    if revoke_source {
        let source = source.ok_or_else(|| {
            ApplicationError::new(
                ErrorCategory::Authentication,
                "SOURCE_SESSION_REQUIRED",
                "撤销源站资源需要有效登录会话",
                true,
            )
        })?;
        let identity = source.identity().cloned().ok_or_else(|| {
            ApplicationError::new(
                ErrorCategory::Authentication,
                "SOURCE_IDENTITY_MISSING",
                "源站会话没有用户身份",
                true,
            )
        })?;
        if state.as_ref().is_some_and(|state| {
            state.source_user_id != 0 && state.source_user_id != identity.user_id
        }) {
            return Err(ApplicationError::new(
                ErrorCategory::Conflict,
                "SOURCE_ACCOUNT_MISMATCH",
                "当前源站账号不属于这个部署",
                false,
            ));
        }
        source_tokens_revoked = source
            .revoke_account_group_tokens()
            .await
            .map_err(source_error)?;
        source
            .revoke_onboard_status_key()
            .await
            .map_err(source_error)?;
        source_key_store::remove(&config.source_url, identity.user_id).map_err(app_error)?;
        source_status_key_revoked = true;
    } else if let (Some(state), Some(content)) = (
        state.as_ref(),
        storage::read(CREDENTIALS_FILE).map_err(app_error)?,
    ) && state.source_user_id > 0
        && state.status_key_id > 0
    {
        let secrets = DeploymentSecrets::parse(&content).map_err(app_error)?;
        source_key_store::save(
            &config.source_url,
            state.source_user_id,
            state.status_key_id,
            &secrets.public_status_source_key,
        )
        .map_err(app_error)?;
    }
    check_cancellation(cancellation)?;
    clean_downstream(config, &executor)?;
    storage::clear_deployment().map_err(app_error)?;
    if let Some(registration) = &registration {
        let _ = deployment_control::queue_lifecycle(
            registration,
            "removed",
            "removed",
            "rollback completed",
        )
        .await?;
    }
    deployment_control::remove_registration()?;
    Ok(RollbackDeploymentOutcome {
        source_tokens_revoked,
        source_status_key_revoked,
    })
}

fn parse_compose_status(raw: &[u8]) -> ApplicationResult<Vec<ContainerStatus>> {
    let raw = String::from_utf8_lossy(raw);
    raw.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).map_err(|error| {
                ApplicationError::new(
                    ErrorCategory::Target,
                    "COMPOSE_STATUS_INVALID",
                    "Docker Compose 返回了无法识别的状态",
                    true,
                )
                .with_diagnostic(error.to_string())
            })?;
            Ok(ContainerStatus {
                name: string_field(&value, "Name", "unknown"),
                state: string_field(&value, "State", "unknown"),
                health: string_field(&value, "Health", ""),
                ports: string_field(&value, "Ports", ""),
            })
        })
        .collect()
}

fn string_field(value: &serde_json::Value, name: &str, default: &str) -> String {
    value
        .get(name)
        .and_then(serde_json::Value::as_str)
        .unwrap_or(default)
        .to_owned()
}

fn clean_downstream(config: &DeploymentConfig, executor: &TargetExecutor) -> ApplicationResult<()> {
    executor
        .remove_compose_project(&config.container_name)
        .map_err(app_error)?;
    executor
        .run_script(&format!(
            r#"directory={directory}
if command -v systemctl >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
  systemctl disable --now meowai-deploy-updater.timer 2>/dev/null || true
  rm -f /etc/systemd/system/meowai-deploy-updater.service /etc/systemd/system/meowai-deploy-updater.timer
  systemctl daemon-reload || true
fi
if [ -d "$directory" ]; then
  cd "$directory"
  rm -f secrets.env downstream-credentials.env updater-credentials.env docker-compose.yml docker-compose.updater.yml kuma-helper.js meowai-deploy-updater.sh meowai-deploy-updater.service meowai-deploy-updater.timer
  rm -rf data run backups
fi"#,
            directory = shell_escape::escape(config.directory.to_string_lossy())
        ))
        .map_err(app_error)?;
    Ok(())
}

fn load_saved_deployment_state() -> ApplicationResult<Option<DeploymentState>> {
    storage::read(STATE_FILE)
        .map_err(app_error)?
        .map(|content| {
            serde_json::from_slice(&content).map_err(|error| {
                ApplicationError::new(
                    ErrorCategory::Persistence,
                    "DEPLOYMENT_STATE_INVALID",
                    "无法读取已保存的部署状态",
                    false,
                )
                .with_diagnostic(error.to_string())
            })
        })
        .transpose()
}

fn persist_deployment_state(state: &DeploymentState) -> ApplicationResult<()> {
    let content = serde_json::to_vec_pretty(state).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Persistence,
            "DEPLOYMENT_STATE_SERIALIZE_FAILED",
            "无法保存部署状态",
            true,
        )
        .with_diagnostic(error.to_string())
    })?;
    storage::write(STATE_FILE, &content).map_err(app_error)
}

fn validate_cleanup_state(
    config: &DeploymentConfig,
    executor: &TargetExecutor,
    state: &DeploymentState,
) -> ApplicationResult<()> {
    if state.deployment_id != config.deployment_id()
        || state.container_name != config.container_name
        || state.directory != config.directory.to_string_lossy()
    {
        return Err(ApplicationError::new(
            ErrorCategory::Conflict,
            "DEPLOYMENT_IDENTITY_MISMATCH",
            "已保存的状态属于另一个部署",
            false,
        ));
    }
    if state.target_fingerprint != executor.fingerprint().map_err(app_error)? {
        return Err(ApplicationError::new(
            ErrorCategory::Conflict,
            "TARGET_FINGERPRINT_MISMATCH",
            "目标主机与上次部署时不一致",
            false,
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compose_status_is_parsed_into_typed_rows() {
        let status = parse_compose_status(
            br#"{"Name":"newapi","State":"running","Health":"healthy","Ports":"0.0.0.0:3000->3000/tcp"}
{"Name":"redis","State":"running"}
"#,
        )
        .expect("compose status");
        assert_eq!(status.len(), 2);
        assert_eq!(status[0].name, "newapi");
        assert_eq!(status[1].health, "");
    }

    #[test]
    fn cancelled_management_use_case_stops_before_target_access() {
        let cancellation = CancellationToken::default();
        cancellation.cancel();
        let error = read_deployment_status(&DeploymentConfig::default(), &cancellation)
            .expect_err("cancelled status");
        assert_eq!(error.category, ErrorCategory::Cancelled);
    }
}
