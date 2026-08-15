use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::{
    error::{ApplicationError, ApplicationResult, ErrorCategory, app_error, source_error},
    operation::CancellationToken,
    source::persist_source_session,
};
use crate::{
    config::DeploymentConfig,
    source::SourceClient,
    source_key_store,
    state::{DOWNSTREAM_CLEANUP_PHASE, DeploymentState, ResourcePhase, unix_timestamp},
    storage::{self, CREDENTIALS_FILE, STATE_FILE},
    target::{
        TargetExecutor,
        compose::{DeploymentRuntime, DeploymentSecrets},
        kuma,
        newapi::NewApiClient,
    },
};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SyncDeploymentRequest {
    pub include_pricing: bool,
    pub force: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SyncDeploymentOutcome {
    pub group_count: usize,
    pub channels_created: usize,
    pub channels_updated: usize,
    pub channels_reused: usize,
    pub channels_disabled: usize,
    pub source_tokens_disabled: usize,
    pub kuma_monitor_count: usize,
}

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

pub async fn sync_deployment(
    config: &DeploymentConfig,
    source: &mut SourceClient,
    request: SyncDeploymentRequest,
    cancellation: &CancellationToken,
) -> ApplicationResult<SyncDeploymentOutcome> {
    check_cancellation(cancellation)?;
    let mut deployment = DeploymentRuntime::prepare(config, 0, "", 0, None).map_err(app_error)?;
    let result =
        sync_deployment_inner(config, &mut deployment, source, request, cancellation).await;
    deployment.state.last_sync_at = unix_timestamp();
    deployment.state.last_sync_success = result.is_ok();
    let persist_result = deployment.persist_state().map_err(app_error);
    match (result, persist_result) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

async fn sync_deployment_inner(
    config: &DeploymentConfig,
    deployment: &mut DeploymentRuntime,
    source: &mut SourceClient,
    request: SyncDeploymentRequest,
    cancellation: &CancellationToken,
) -> ApplicationResult<SyncDeploymentOutcome> {
    deployment.deploy_base_stack(config).map_err(app_error)?;
    check_cancellation(cancellation)?;
    let identity = source.identity().cloned().ok_or_else(|| {
        ApplicationError::new(
            ErrorCategory::Authentication,
            "SOURCE_IDENTITY_MISSING",
            "源站会话没有用户身份",
            true,
        )
    })?;
    if deployment.state.source_user_id != 0 && deployment.state.source_user_id != identity.user_id {
        return Err(ApplicationError::new(
            ErrorCategory::Conflict,
            "SOURCE_ACCOUNT_MISMATCH",
            "当前源站账号不属于这个部署",
            false,
        ));
    }

    let catalog = source.groups().await.map_err(source_error)?;
    check_cancellation(cancellation)?;
    let source_pricing = if request.include_pricing {
        Some(source.pricing().await.map_err(source_error)?)
    } else {
        None
    };
    let active_group_ids = catalog
        .groups
        .iter()
        .map(|group| group.group_id.clone())
        .collect::<BTreeSet<_>>();
    let source_tokens_disabled = source
        .disable_removed_group_tokens(&active_group_ids)
        .await
        .map_err(source_error)?;
    let token_sync = source
        .ensure_group_tokens(&catalog)
        .await
        .map_err(source_error)?;
    let status_key = source
        .ensure_onboard_status_key()
        .await
        .map_err(source_error)?;
    if let Some(key) = status_key.key() {
        deployment.secrets.public_status_source_key = key.clone();
    } else if deployment.state.status_key_id != 0
        && deployment.state.status_key_id != status_key.metadata.id
    {
        deployment.secrets.public_status_source_key =
            source_key_store::load(&config.source_url, identity.user_id, status_key.metadata.id)
                .map_err(app_error)?
                .ok_or_else(|| {
                    ApplicationError::new(
                        ErrorCategory::Conflict,
                        "STATUS_KEY_CONTENT_UNAVAILABLE",
                        "源站公共状态密钥已更换，但当前控制端没有保存新密钥内容",
                        false,
                    )
                })?;
    }
    source_key_store::save(
        &config.source_url,
        identity.user_id,
        status_key.metadata.id,
        &deployment.secrets.public_status_source_key,
    )
    .map_err(app_error)?;
    deployment.state.source_user_id = identity.user_id;
    deployment.state.source_group_sha256 = catalog.response_sha256.clone();
    deployment.state.status_key_id = status_key.metadata.id;
    deployment.persist(config).map_err(app_error)?;
    persist_source_session(source)?;
    check_cancellation(cancellation)?;

    let mut downstream = NewApiClient::connect(&deployment.executor, deployment.state.newapi_port)
        .map_err(app_error)?;
    downstream
        .initialize_and_login(config, &deployment.secrets.newapi_admin_password)
        .await
        .map_err(app_error)?;
    let previous_channels = deployment.state.channels.clone();
    let (channel_result, mut channels) = downstream
        .sync_channels(
            config,
            &deployment.container_source_url,
            &catalog,
            &token_sync.bindings,
            &previous_channels,
            request.force,
        )
        .await
        .map_err(app_error)?;
    let channels_disabled = downstream
        .disable_removed_channels(&previous_channels, &mut channels)
        .await
        .map_err(app_error)?;
    deployment.state.channels = channels;
    if let Some(source_pricing) = &source_pricing {
        deployment.state.pricing_sha256 = downstream
            .import_pricing(source_pricing)
            .await
            .map_err(app_error)?;
        deployment.state.mark_phase(
            "pricing",
            "DONE",
            "价格表、Seedance 和市场配置已重新导入并回读一致",
        );
    }
    check_cancellation(cancellation)?;

    deployment.deploy_kuma(config).map_err(app_error)?;
    let manifest = source
        .onboard_status_manifest(&deployment.secrets.public_status_source_key)
        .await
        .map_err(source_error)?;
    let deployment_id = config.deployment_id();
    let kuma_sync = kuma::sync_status_page(kuma::KumaSyncOptions {
        executor: &deployment.executor,
        container_name: &config.container_name,
        deployment_id: &deployment_id,
        website_name: &config.website_name,
        source_base_url: &deployment.container_source_url,
        status_key: &deployment.secrets.public_status_source_key,
        kuma_username: &config.kuma_admin_username,
        kuma_password: &deployment.secrets.kuma_admin_password,
        force: request.force,
        manifest: &manifest,
    })
    .map_err(app_error)?;
    deployment.state.manifest_sha256 = kuma_sync.manifest_sha256;
    deployment.state.kuma_monitors = kuma_sync.monitors;
    let public_status_url = kuma::internal_status_page_url(&kuma_sync.page_slug);
    downstream
        .configure_public_status_url(&public_status_url)
        .await
        .map_err(app_error)?;
    let kuma_monitor_count = deployment.state.kuma_monitors.len();
    deployment.state.mark_phase(
        "kuma",
        "DONE",
        format!("status page {} synchronized", kuma_sync.page_slug),
    );
    deployment.state.mark_phase(
        "sync",
        "DONE",
        format!(
            "groups {}, channels created {}, updated {}, reused {}, disabled {}, source tokens disabled {}, Kuma monitors {}",
            catalog.groups.len(),
            channel_result.created,
            channel_result.updated,
            channel_result.reused,
            channels_disabled,
            source_tokens_disabled,
            kuma_monitor_count
        ),
    );
    deployment.persist(config).map_err(app_error)?;
    check_cancellation(cancellation)?;
    Ok(SyncDeploymentOutcome {
        group_count: catalog.groups.len(),
        channels_created: channel_result.created,
        channels_updated: channel_result.updated,
        channels_reused: channel_result.reused,
        channels_disabled,
        source_tokens_disabled,
        kuma_monitor_count,
    })
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

pub fn clean_deployment(
    config: &DeploymentConfig,
    cancellation: &CancellationToken,
) -> ApplicationResult<CleanDeploymentOutcome> {
    check_cancellation(cancellation)?;
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
    executor.validate_access().map_err(app_error)?;
    let mut state = load_saved_deployment_state()?;
    if let Some(state) = &state {
        validate_cleanup_state(config, &executor, state)?;
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
    check_cancellation(cancellation)?;
    let executor = TargetExecutor::new(config.target.clone(), config.directory.clone());
    executor.validate_access().map_err(app_error)?;
    let state = load_saved_deployment_state()?;
    if let Some(state) = &state {
        validate_cleanup_state(config, &executor, state)?;
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
        .compose(&config.container_name, &["down", "--remove-orphans"])
        .map_err(app_error)?;
    executor
        .run_in_directory("rm -f secrets.env docker-compose.yml kuma-helper.js\nrm -rf data")
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
