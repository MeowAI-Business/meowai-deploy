use std::time::Duration;
use std::{collections::BTreeMap, fs, path::Path};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::{
    application::deployment_control,
    cli::{AgentArgs, UpgradeArgs},
    config::{DeploymentConfig, Target},
    error::{AppError, Result},
    lifecycle_outbox,
    state::DeploymentState,
    storage::{self, CONFIG_FILE, STATE_FILE},
};

use crate::source::DeploymentRegistration;

const CURRENT_UPGRADER_SCHEMA: &str = "2";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UpgradeDecision {
    None,
    ImageOnly,
    UpgradeRequired,
    Blocked,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UpgradePolicy {
    #[serde(default)]
    pub decision: Option<UpgradeDecision>,
    #[serde(default)]
    pub reason_code: String,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub release_id: String,
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub image_repository: String,
    #[serde(default)]
    pub image_digest: String,
    #[serde(default)]
    pub silent_updates_enabled: bool,
    #[serde(default)]
    pub minimum_updater_schema: String,
    #[serde(default)]
    pub minimum_deployment_schema: String,
    #[serde(default)]
    pub minimum_cli_schema: String,
    #[serde(default)]
    pub minimum_data_schema: String,
    #[serde(default)]
    pub upgrade_kind: String,
    #[serde(default)]
    pub data_rollback_required: bool,
    #[serde(default)]
    #[serde(alias = "manifest_url")]
    pub upgrade_manifest_url: String,
    #[serde(default)]
    #[serde(alias = "manifest_sha256")]
    pub upgrade_manifest_sha256: String,
    #[serde(default)]
    pub execution_authorized: bool,
    #[serde(default)]
    pub upgrade_authorization_id: String,
    #[serde(default)]
    pub upgrade_operation_id: String,
    #[serde(default)]
    pub upgrade_authorization_expires_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestArtifact {
    pub name: String,
    pub url: String,
    pub sha256: String,
    pub size: u64,
    pub os: String,
    pub arch: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestMigrationPlan {
    pub from: u32,
    pub to: u32,
    pub steps: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestHealthPolicy {
    pub newapi_timeout_seconds: u32,
    pub dependency_timeout_seconds: u32,
    pub updater_heartbeat_max_age_seconds: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManifestRollback {
    pub supported: bool,
    pub retained_backup_count: u32,
    pub data_rollback_required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReleaseManifest {
    pub manifest_schema: u32,
    pub release_id: String,
    pub channel: String,
    pub newapi_version: String,
    pub image_repository: String,
    pub image_digest: String,
    pub deployment_schema: u32,
    pub minimum_deployment_schema: u32,
    pub minimum_updater_schema: u32,
    pub minimum_cli_schema: u32,
    pub minimum_data_schema: u32,
    pub upgrade_kind: String,
    pub required_capabilities: Vec<String>,
    pub artifacts: Vec<ManifestArtifact>,
    pub migration_plan: ManifestMigrationPlan,
    pub health_policy: ManifestHealthPolicy,
    pub rollback: ManifestRollback,
    pub created_at: i64,
    pub expires_at: i64,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct UpgradePlan {
    pub fingerprint: String,
    pub decision: UpgradeDecision,
    pub reason_code: String,
    pub reason: String,
    pub current: BTreeMap<String, String>,
    pub target: BTreeMap<String, String>,
    pub release_id: String,
    pub version: String,
    pub upgrade_kind: String,
    pub data_rollback_required: bool,
    pub image_digest: String,
    pub manifest_url: String,
    pub manifest_sha256: String,
    pub manifest_verified: bool,
    pub selected_artifact: Option<ManifestArtifact>,
    pub required_action: String,
    #[serde(skip_serializing)]
    pub execution_authorized: bool,
    #[serde(skip_serializing)]
    pub upgrade_authorization_id: String,
    #[serde(skip_serializing)]
    pub upgrade_operation_id: String,
    #[serde(skip_serializing)]
    pub upgrade_authorization_expires_at: i64,
}

/// Internal target-host entrypoint used by the installed systemd updater.
pub async fn run_agent(args: &AgentArgs) -> Result<()> {
    if !args.auto {
        return Err(AppError::InvalidConfig(
            "目标机 agent 必须使用 --auto".to_owned(),
        ));
    }
    let root = fs::canonicalize(&args.root)
        .map_err(|error| AppError::State(format!("无法定位目标 deployment 目录：{error}")))?;
    let values = read_target_env(&root)?;
    // Automatic target execution is strict about release trust metadata.
    let registration = registration_from_target_env(&values)?;
    crate::lifecycle_outbox::flush().await.map_err(|error| {
        AppError::State(format!(
            "目标机仍有未送达的控制面状态，停止自动升级：{error}"
        ))
    })?;
    let mut config = DeploymentConfig::default();
    config.directory = root.clone();
    config.target = Target::Local;
    config.container_name = required_env(&values, "MEOWAI_CONTAINER_NAME")?;
    config.image = required_env(&values, "MEOWAI_ALLOWED_IMAGE_REPOSITORY")?;
    config.image_ref = values
        .get("MEOWAI_CURRENT_IMAGE_DIGEST")
        .cloned()
        .unwrap_or_default();
    config.newapi_port = parse_u16(&values, "MEOWAI_NEWAPI_PORT", 3000)?;
    config.kuma_port = parse_u16(&values, "MEOWAI_KUMA_PORT", 3001)?;

    let mut state: DeploymentState = serde_json::from_value(serde_json::json!({
        "schema_version": 1,
        "deployment_id": values.get("MEOWAI_DEPLOYMENT_ID").cloned().unwrap_or_default(),
        "target_fingerprint": format!("agent:{}", root.display()),
        "container_name": config.container_name,
        "directory": root.display().to_string(),
        "newapi_port": config.newapi_port,
        "kuma_port": config.kuma_port,
        "image": config.image,
        "image_ref": config.image_ref,
        "deployment_schema": values.get("MEOWAI_DEPLOYMENT_SCHEMA").cloned().unwrap_or_else(|| "1".to_owned()),
        "updater_schema": values.get("MEOWAI_UPDATER_SCHEMA").cloned().unwrap_or_else(|| "1".to_owned()),
        "data_schema": values.get("MEOWAI_DATA_SCHEMA").cloned().unwrap_or_else(|| "1".to_owned()),
        "cli_schema": values.get("MEOWAI_CLI_SCHEMA").cloned().unwrap_or_else(|| "1".to_owned()),
        "target_os": "linux",
        "target_arch": values.get("MEOWAI_TARGET_ARCH").cloned().unwrap_or_else(|| host_arch()),
        "systemd_available": true,
        "compose_v2_available": true,
        "image_digest": values.get("MEOWAI_CURRENT_IMAGE_DIGEST").cloned().unwrap_or_default(),
        "newapi_version": values.get("MEOWAI_NEWAPI_VERSION").cloned().unwrap_or_default(),
    }))
    .map_err(|error| AppError::State(format!("目标 deployment 状态无效：{error}")))?;

    if registration.release_manifest_public_key.is_empty()
        || registration.release_artifact_allowed_hosts.is_empty()
    {
        return Err(AppError::State(
            "目标机缺少 release manifest 信任元数据，请先执行 bootstrap".to_owned(),
        ));
    }
    let policy = fetch_policy(
        &registration.control_plane_url,
        &registration.report_credential,
    )
    .await?;
    let decision = policy.decision.clone().unwrap_or(UpgradeDecision::None);
    if decision != UpgradeDecision::UpgradeRequired {
        return Err(AppError::State(format!(
            "目标机 agent 只处理结构性 release，当前决策为 {:?}",
            decision
        )));
    }
    if policy.data_rollback_required {
        return Err(AppError::State(
            "该 release 包含真实数据迁移，不能由 updater timer 静默执行；请使用 CLI plan 和显式确认".to_owned(),
        ));
    }
    let manifest = fetch_and_verify_manifest(&policy, &registration).await?;
    let plan = build_plan(&state, &policy, Some(&manifest));
    let artifact = plan.selected_artifact.as_ref().ok_or_else(|| {
        AppError::State("manifest 没有当前目标架构对应的 upgrade artifact".to_owned())
    })?;
    let artifact_bytes = download_artifact(artifact, &registration).await?;
    let result = crate::target::upgrade_agent::apply(
        &config,
        &state,
        &registration,
        &manifest,
        artifact,
        &artifact_bytes,
        &plan,
        false,
        true,
    )
    .await?;
    state.deployment_schema = manifest.deployment_schema.to_string();
    state.updater_schema = manifest.minimum_updater_schema.to_string();
    state.cli_schema = manifest.minimum_cli_schema.to_string();
    state.data_schema = state
        .data_schema
        .parse::<u32>()
        .unwrap_or(0)
        .max(manifest.minimum_data_schema)
        .to_string();
    state.last_upgrade_release_id = manifest.release_id.clone();
    state.last_upgrade_state = "committed".to_owned();
    state.image_digest = result.image_digest;
    let executor =
        crate::target::TargetExecutor::new(config.target.clone(), config.directory.clone());
    state.newapi_version = executor.newapi_version(config.newapi_port)?;
    report_capability(&state, &registration).await?;
    println!(
        "{}",
        serde_json::json!({
            "success": true,
            "operation_id": result.operation_id,
            "release_id": manifest.release_id,
            "state": "COMMITTED"
        })
    );
    Ok(())
}

fn read_target_env(root: &Path) -> Result<BTreeMap<String, String>> {
    let path = root.join("downstream-credentials.env");
    let content = fs::read_to_string(&path)
        .map_err(|error| AppError::State(format!("无法读取目标 deployment 凭证环境：{error}")))?;
    parse_target_env(&content)
}

fn parse_target_env(content: &str) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| AppError::State("目标 deployment 环境文件包含无效行".to_owned()))?;
        if key.is_empty()
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
            || values.insert(key.to_owned(), value.to_owned()).is_some()
        {
            return Err(AppError::State(
                "目标 deployment 环境文件包含重复或无效 key".to_owned(),
            ));
        }
    }
    Ok(values)
}

fn registration_from_executor(
    config: &DeploymentConfig,
    allow_missing_release_trust: bool,
) -> Result<DeploymentRegistration> {
    let executor =
        crate::target::TargetExecutor::new(config.target.clone(), config.directory.clone());
    let output = executor.run_in_directory("cat downstream-credentials.env")?;
    let content = String::from_utf8(output.stdout)
        .map_err(|_| AppError::State("目标 deployment 凭证环境不是 UTF-8".to_owned()))?;
    registration_from_target_env_with_trust(
        &parse_target_env(&content)?,
        !allow_missing_release_trust,
    )
}

fn registration_from_target_env(
    values: &BTreeMap<String, String>,
) -> Result<DeploymentRegistration> {
    registration_from_target_env_with_trust(values, true)
}

fn registration_from_target_env_with_trust(
    values: &BTreeMap<String, String>,
    require_release_trust: bool,
) -> Result<DeploymentRegistration> {
    let hosts = values
        .get("MEOWAI_RELEASE_ARTIFACT_ALLOWED_HOSTS")
        .cloned()
        .unwrap_or_default()
        .split(',')
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.trim().to_ascii_lowercase())
        .collect::<Vec<_>>();
    let release_manifest_public_key = values
        .get("MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY")
        .cloned()
        .unwrap_or_default();
    if require_release_trust && (release_manifest_public_key.trim().is_empty() || hosts.is_empty())
    {
        return Err(AppError::State(
            "目标机缺少 release manifest 信任元数据，请先执行 bootstrap".to_owned(),
        ));
    }
    Ok(DeploymentRegistration {
        deployment_id: required_env(values, "MEOWAI_DEPLOYMENT_ID")?,
        installation_generation: parse_u32(values, "MEOWAI_INSTALLATION_GENERATION", 0)?,
        control_plane_url: required_env(values, "MEOWAI_CONTROL_PLANE_URL")?,
        report_credential: SecretString::from(required_env(values, "MEOWAI_REPORT_CREDENTIAL")?),
        pull_credential: SecretString::from(required_env(values, "MEOWAI_PULL_CREDENTIAL")?),
        heartbeat_interval_seconds: parse_u32(values, "MEOWAI_HEARTBEAT_INTERVAL_SECONDS", 300)?,
        snapshot_interval_seconds: parse_u32(values, "MEOWAI_SNAPSHOT_INTERVAL_SECONDS", 3600)?,
        silent_updates_enabled: false,
        release_schema_version: values
            .get("MEOWAI_RELEASE_SCHEMA_VERSION")
            .cloned()
            .unwrap_or_else(|| "1".to_owned()),
        release_manifest_public_key,
        release_artifact_allowed_hosts: hosts,
    })
}

fn required_env(values: &BTreeMap<String, String>, key: &str) -> Result<String> {
    values
        .get(key)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| AppError::State(format!("目标 deployment 缺少 {key}")))
}

fn parse_u32(values: &BTreeMap<String, String>, key: &str, default: u32) -> Result<u32> {
    values
        .get(key)
        .map(|value| {
            value
                .parse::<u32>()
                .map_err(|_| AppError::State(format!("目标 deployment 的 {key} 无效")))
        })
        .unwrap_or(Ok(default))
}

fn parse_u16(values: &BTreeMap<String, String>, key: &str, default: u16) -> Result<u16> {
    values
        .get(key)
        .map(|value| {
            value
                .parse::<u16>()
                .map_err(|_| AppError::State(format!("目标 deployment 的 {key} 无效")))
        })
        .unwrap_or(Ok(default))
}

fn host_arch() -> String {
    match std::env::consts::ARCH {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
    .to_owned()
}

pub async fn run(args: &UpgradeArgs) -> Result<()> {
    let _operation_lock = storage::acquire_operation_lock()?;
    let config = load_config()?;
    let mut state = load_state()?;
    observe_target_capability(&config, &mut state)?;
    let mut registration = deployment_control::load_registration()
        .map_err(|error| AppError::State(error.message))?
        .ok_or_else(|| AppError::State("尚未登记控制面 deployment，无法检查升级".to_owned()))?;
    if args.bootstrap || args.repair_updater {
        // Legacy targets do not have release trust fields yet. Bootstrap must
        // read their registration first, fetch trust metadata from the control
        // plane, and only then persist the new trust fields.
        let target_registration = registration_from_executor(&config, true)?;
        if target_registration.deployment_id != registration.deployment_id
            || target_registration.installation_generation != registration.installation_generation
        {
            return Err(AppError::State(
                "目标 deployment registration 与本地控制面身份不一致".to_owned(),
            ));
        }
        registration = target_registration;
        deployment_control::persist_registration_locally(
            &config,
            state.source_user_id,
            &registration,
        )
        .map_err(|error| AppError::State(error.message))?;
        let discarded = lifecycle_outbox::discard_stale_registration(&registration)?;
        if discarded > 0 {
            eprintln!("已丢弃 {discarded} 条使用旧 report credential 的待发送控制面事件");
        }
        if args.bootstrap {
            let discarded = lifecycle_outbox::discard_pending_for_bootstrap()?;
            if discarded > 0 {
                eprintln!("bootstrap 已清除 {discarded} 条已由目标机恢复的过期控制面事件");
            }
        }
    }
    if let Some(operation_id) = args.rollback.as_deref() {
        let backup_id =
            crate::target::upgrade_agent::rollback_recorded(&config, &registration, operation_id)
                .await?;
        observe_target_capability(&config, &mut state)?;
        state.last_upgrade_state = "rolled_back".to_owned();
        storage::write(
            STATE_FILE,
            &serde_json::to_vec_pretty(&state).map_err(|error| {
                AppError::State(format!("serialize rolled back state: {error}"))
            })?,
        )?;
        report_capability(&state, &registration).await?;
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "operation_id": operation_id,
                "backup_id": backup_id,
                "state": "ROLLED_BACK"
            }))
            .map_err(|error| AppError::State(format!("serialize rollback result: {error}")))?
        );
        return Ok(());
    }
    report_capability(&state, &registration).await?;
    let policy = fetch_policy(
        &registration.control_plane_url,
        &registration.report_credential,
    )
    .await?;
    if !policy.upgrade_manifest_url.is_empty() {
        refresh_release_trust(&config, &state, &mut registration).await?;
    }
    let manifest = if !policy.upgrade_manifest_url.is_empty() {
        Some(fetch_and_verify_manifest(&policy, &registration).await?)
    } else {
        None
    };
    let plan = build_plan(&state, &policy, manifest.as_ref());

    if let Some(release) = args.release.as_deref()
        && release != plan.release_id
    {
        return Err(AppError::State(format!(
            "控制面当前批准 release 为 {}，不是请求的 {release}",
            plan.release_id
        )));
    }

    if args.check || args.plan {
        println!(
            "{}",
            serde_json::to_string_pretty(&plan)
                .map_err(|error| AppError::State(format!("serialize upgrade plan: {error}")))?
        );
        return Ok(());
    }

    if !args.yes {
        return Err(AppError::InvalidConfig(
            "执行升级必须显式传入 --yes；请先运行 upgrade --plan 并核对 fingerprint".to_owned(),
        ));
    }
    let expected = args.plan_fingerprint.as_deref().ok_or_else(|| {
        AppError::InvalidConfig("非交互升级必须同时传入 --yes 和 --plan-fingerprint".to_owned())
    })?;
    if expected != plan.fingerprint {
        return Err(AppError::State(
            "升级计划已经过期；请重新运行 `meowai-deploy upgrade --plan`".to_owned(),
        ));
    }
    let bootstrap = args.bootstrap || args.repair_updater;
    if plan.decision == UpgradeDecision::Blocked && !bootstrap {
        return Err(AppError::State(format!(
            "当前部署被控制面阻断：{}；请先完成 updater/bootstrap 修复",
            if plan.reason.is_empty() {
                "控制面要求完整部署升级"
            } else {
                plan.reason.as_str()
            }
        )));
    }
    if bootstrap
        && plan.decision != UpgradeDecision::UpgradeRequired
        && plan.decision != UpgradeDecision::Blocked
    {
        return Err(AppError::State(
            "当前 release 不需要修复 upgrade agent".to_owned(),
        ));
    }
    if plan.decision == UpgradeDecision::ImageOnly {
        return Err(AppError::State(
            "image-only 发布仍由批准 digest updater 执行，不需要 deployment upgrade".to_owned(),
        ));
    }
    let manifest =
        manifest.ok_or_else(|| AppError::State("结构性发布缺少已验证 manifest".to_owned()))?;
    let artifact = plan.selected_artifact.as_ref().ok_or_else(|| {
        AppError::State("manifest 没有当前控制端架构对应的 Linux upgrade artifact".to_owned())
    })?;
    let artifact_bytes = download_artifact(artifact, &registration).await?;
    let result = crate::target::upgrade_agent::apply(
        &config,
        &state,
        &registration,
        &manifest,
        artifact,
        &artifact_bytes,
        &plan,
        bootstrap,
        false,
    )
    .await?;
    state.deployment_schema = manifest.deployment_schema.to_string();
    state.updater_schema = manifest.minimum_updater_schema.to_string();
    state.cli_schema = manifest.minimum_cli_schema.to_string();
    let current_data_schema = state.data_schema.parse::<u32>().unwrap_or(0);
    state.data_schema = current_data_schema
        .max(manifest.minimum_data_schema)
        .to_string();
    state.last_upgrade_release_id = manifest.release_id.clone();
    state.last_upgrade_state = "committed".to_owned();
    state.image_digest = result.image_digest;
    observe_target_capability(&config, &mut state)?;
    storage::write(
        STATE_FILE,
        &serde_json::to_vec_pretty(&state)
            .map_err(|error| AppError::State(format!("serialize upgraded state: {error}")))?,
    )?;
    report_capability(&state, &registration).await?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "success": true,
            "operation_id": result.operation_id,
            "backup_id": result.backup_id,
            "release_id": manifest.release_id,
            "state": "COMMITTED"
        }))
        .map_err(|error| AppError::State(format!("serialize upgrade result: {error}")))?
    );
    Ok(())
}

async fn refresh_release_trust(
    config: &DeploymentConfig,
    state: &DeploymentState,
    registration: &mut crate::source::DeploymentRegistration,
) -> Result<()> {
    if !registration.release_manifest_public_key.is_empty()
        && !registration.release_artifact_allowed_hosts.is_empty()
    {
        return Ok(());
    }
    let trust = crate::source::control_plane_client(registration)?
        .release_trust_metadata(registration)
        .await?;
    if trust.release_manifest_public_key.trim().is_empty()
        || trust.release_artifact_allowed_hosts.is_empty()
    {
        return Err(AppError::State(
            "控制面没有提供结构性 release 信任元数据".to_owned(),
        ));
    }
    registration.release_manifest_public_key = trust.release_manifest_public_key;
    registration.release_artifact_allowed_hosts = trust.release_artifact_allowed_hosts;
    deployment_control::persist_registration_locally(config, state.source_user_id, registration)
        .map_err(|error| AppError::State(error.message))?;
    Ok(())
}

async fn report_capability(
    state: &DeploymentState,
    registration: &crate::source::DeploymentRegistration,
) -> Result<()> {
    let receipt = crate::source::control_plane_client(registration)?
        .report_capability(
            registration,
            serde_json::json!({
                "newapi_version": state.newapi_version,
                "image_repository": state.image,
                "image_digest": state.image_digest,
                "deployment_schema": state.deployment_schema,
                "updater_schema": state.updater_schema,
                "cli_schema": state.cli_schema,
                "data_schema": state.data_schema,
                "target_os": state.target_os,
                "target_arch": state.target_arch,
                "systemd": state.systemd_available,
                "compose_v2": state.compose_v2_available,
                "last_upgrade_release_id": state.last_upgrade_release_id,
                "last_upgrade_state": state.last_upgrade_state,
            }),
        )
        .await?;
    let capability = &receipt.capability;
    if !receipt.accepted
        || receipt.deployment_id != registration.deployment_id
        || receipt.installation_generation != registration.installation_generation
        || receipt.observed_at <= 0
        || capability.image_repository != state.image
        || capability.image_digest != state.image_digest
        || (!state.newapi_version.is_empty() && capability.newapi_version != state.newapi_version)
        || capability.deployment_schema != state.deployment_schema
        || capability.updater_schema != state.updater_schema
        || capability.cli_schema != state.cli_schema
        || capability.data_schema != state.data_schema
        || capability.last_upgrade_release_id != state.last_upgrade_release_id
        || capability.last_upgrade_state != state.last_upgrade_state
    {
        return Err(AppError::State(
            "控制面 capability 回读与目标机实际状态不一致".to_owned(),
        ));
    }
    Ok(())
}

fn load_config() -> Result<DeploymentConfig> {
    let path = storage::directory()?.join(CONFIG_FILE);
    let mut config = DeploymentConfig::from_file(&path)?;
    config.normalize();
    config.validate()?;
    Ok(config)
}

fn load_state() -> Result<DeploymentState> {
    let content = storage::read(STATE_FILE)?
        .ok_or_else(|| AppError::State("尚未找到部署状态，请先完成 onboard".to_owned()))?;
    serde_json::from_slice(&content)
        .map_err(|error| AppError::State(format!("parse deployment state: {error}")))
}

fn observe_target_capability(config: &DeploymentConfig, state: &mut DeploymentState) -> Result<()> {
    let executor =
        crate::target::TargetExecutor::new(config.target.clone(), config.directory.clone());
    state.systemd_available = false;
    state.compose_v2_available = false;
    let output = executor.remote_diagnostics()?;
    let diagnostics = String::from_utf8_lossy(&output.stdout);
    for line in diagnostics.lines() {
        if let Some(value) = line.strip_prefix("os=") {
            state.target_os = value.trim().to_ascii_lowercase();
        } else if let Some(value) = line.strip_prefix("arch=") {
            state.target_arch = match value.trim() {
                "x86_64" | "amd64" => "amd64",
                "aarch64" | "arm64" => "arm64",
                other => other,
            }
            .to_owned();
        } else if line == "compose=pass" {
            state.compose_v2_available = true;
        } else if line == "systemd=pass" {
            state.systemd_available = true;
        }
    }
    state.newapi_version = executor.newapi_version(config.newapi_port)?;
    let deployment = executor.run_in_directory(&format!(
        r#"set -eu
for key in MEOWAI_DEPLOYMENT_SCHEMA MEOWAI_UPDATER_SCHEMA MEOWAI_CLI_SCHEMA MEOWAI_DATA_SCHEMA MEOWAI_CURRENT_IMAGE_DIGEST; do
  value=$(sed -n "s/^${{key}}=//p" downstream-credentials.env 2>/dev/null | tail -n 1 || true)
  printf '%s=%s\n' "$key" "$value"
done
if command -v docker >/dev/null 2>&1 && docker inspect {container} >/dev/null 2>&1; then
  docker inspect --format '{{{{range .Config.Env}}}}{{{{println .}}}}{{{{end}}}}' {container} | sed -n 's/^MEOWAI_CURRENT_IMAGE_DIGEST=//p' | tail -n 1 | sed 's/^/MEOWAI_CURRENT_IMAGE_DIGEST=/'
fi"#,
        container = shell_quote(&config.container_name)
    ))?;
    for line in String::from_utf8_lossy(&deployment.stdout).lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key {
            "MEOWAI_DEPLOYMENT_SCHEMA" if valid_schema(value) => {
                state.deployment_schema = value.to_owned()
            }
            "MEOWAI_UPDATER_SCHEMA" if valid_schema(value) => {
                state.updater_schema = value.to_owned()
            }
            "MEOWAI_CLI_SCHEMA" if valid_schema(value) => state.cli_schema = value.to_owned(),
            "MEOWAI_DATA_SCHEMA" if valid_schema(value) => state.data_schema = value.to_owned(),
            "MEOWAI_CURRENT_IMAGE_DIGEST" if valid_digest(value) => {
                state.image_digest = value.to_owned()
            }
            _ => {}
        }
    }
    // The target journal is the source of truth once the service switch has
    // committed.  This also repairs a controlling CLI that lost its final
    // response after a successful target-side commit: report the completed
    // release on the next check instead of planning a duplicate upgrade.
    let journal = executor.run_in_directory(
        "set -eu\nif [ -f run/upgrade-status.json ]; then cat run/upgrade-status.json; fi",
    )?;
    if !journal.stdout.is_empty() {
        let journal: serde_json::Value = serde_json::from_slice(&journal.stdout)
            .map_err(|error| AppError::State(format!("parse target upgrade journal: {error}")))?;
        let release_id = journal
            .get("release_id")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let status = journal
            .get("state")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if status == "COMMITTED" && !release_id.is_empty() {
            state.last_upgrade_release_id = release_id.to_owned();
            state.last_upgrade_state = "committed".to_owned();
        } else if status == "ROLLED_BACK" {
            state.last_upgrade_state = "rolled_back".to_owned();
        }
    }
    Ok(())
}

fn valid_schema(value: &str) -> bool {
    !value.is_empty() && value.len() <= 16 && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn shell_quote(value: &str) -> String {
    shell_escape::escape(value.into()).into_owned()
}

async fn fetch_and_verify_manifest(
    policy: &UpgradePolicy,
    registration: &crate::source::DeploymentRegistration,
) -> Result<ReleaseManifest> {
    if registration.release_manifest_public_key.is_empty() {
        return Err(AppError::State(
            "结构性发布需要先通过 registration 获取 manifest 公钥；请运行 repair-updater"
                .to_owned(),
        ));
    }
    let url = Url::parse(&policy.upgrade_manifest_url)
        .map_err(|error| AppError::State(format!("升级清单 URL 无效：{error}")))?;
    if url.scheme() != "https" || url.username() != "" || url.fragment().is_some() {
        return Err(AppError::State(
            "升级清单 URL 必须使用 HTTPS 且不能带用户信息或 fragment".to_owned(),
        ));
    }
    let control_plane = Url::parse(&registration.control_plane_url)
        .map_err(|error| AppError::State(format!("控制面 URL 无效：{error}")))?;
    if !url.host_str().is_some_and(|host| {
        control_plane
            .host_str()
            .is_some_and(|control| host.eq_ignore_ascii_case(control))
    }) {
        return Err(AppError::State(
            "升级清单 URL 必须与已登记控制面同源".to_owned(),
        ));
    }
    let response = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| AppError::State(format!("创建升级清单客户端失败：{error}")))?
        .get(url)
        .bearer_auth(registration.report_credential.expose_secret())
        .send()
        .await
        .map_err(|error| AppError::State(format!("下载升级清单失败：{error}")))?;
    if !response.status().is_success() {
        return Err(AppError::State(format!(
            "控制面拒绝升级清单：HTTP {}",
            response.status()
        )));
    }
    if response
        .content_length()
        .is_some_and(|size| size > 256 << 10)
    {
        return Err(AppError::State("升级清单超过 256 KiB 限制".to_owned()));
    }
    let body = download_limited(response, 256 << 10, "升级清单").await?;
    if body.len() > 256 << 10
        || crate::security::sha256_hex(&body) != policy.upgrade_manifest_sha256
    {
        return Err(AppError::State("升级清单 SHA256 校验失败".to_owned()));
    }
    let manifest: ReleaseManifest = serde_json::from_slice(&body)
        .map_err(|error| AppError::State(format!("升级清单 JSON 无效：{error}")))?;
    verify_manifest(&manifest, policy, registration, state_timestamp())?;
    Ok(manifest)
}

fn verify_manifest(
    manifest: &ReleaseManifest,
    policy: &UpgradePolicy,
    registration: &crate::source::DeploymentRegistration,
    now: i64,
) -> Result<()> {
    if manifest.manifest_schema != 1
        || manifest.release_id != policy.release_id
        || (!policy.image_digest.is_empty() && manifest.image_digest != policy.image_digest)
        || (!policy.image_repository.is_empty()
            && manifest.image_repository != policy.image_repository)
        || manifest.upgrade_kind != policy.upgrade_kind
        || manifest.expires_at <= now
        || manifest.created_at > now + 300
        || manifest.minimum_updater_schema.to_string() != policy.minimum_updater_schema
        || manifest.minimum_deployment_schema.to_string() != policy.minimum_deployment_schema
        || manifest.minimum_cli_schema.to_string() != policy.minimum_cli_schema
        || manifest.minimum_data_schema.to_string() != policy.minimum_data_schema
    {
        return Err(AppError::State(
            "升级清单与控制面 release policy 不一致或已过期".to_owned(),
        ));
    }
    let public_key_bytes = BASE64_STANDARD
        .decode(&registration.release_manifest_public_key)
        .map_err(|_| AppError::State("manifest 公钥不是有效 base64".to_owned()))?;
    let public_key = VerifyingKey::from_bytes(
        &public_key_bytes
            .try_into()
            .map_err(|_| AppError::State("manifest 公钥长度无效".to_owned()))?,
    )
    .map_err(|_| AppError::State("manifest 公钥无效".to_owned()))?;
    let signature_bytes = BASE64_STANDARD
        .decode(&manifest.signature)
        .map_err(|_| AppError::State("manifest signature 不是有效 base64".to_owned()))?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| AppError::State("manifest signature 长度无效".to_owned()))?;
    let mut unsigned = manifest.clone();
    unsigned.signature.clear();
    let payload = serde_json::to_vec(&unsigned)
        .map_err(|error| AppError::State(format!("manifest canonical JSON 失败：{error}")))?;
    public_key
        .verify(&payload, &signature)
        .map_err(|_| AppError::State("manifest signature 校验失败".to_owned()))?;
    if !manifest.rollback.supported
        || manifest.rollback.retained_backup_count == 0
        || manifest.artifacts.is_empty()
    {
        return Err(AppError::State(
            "manifest rollback 或 artifact policy 无效".to_owned(),
        ));
    }
    if !manifest
        .required_capabilities
        .iter()
        .any(|item| item == "linux")
        || !manifest
            .required_capabilities
            .iter()
            .any(|item| item == "compose_v2")
        || !manifest
            .required_capabilities
            .iter()
            .any(|item| item == "systemd")
    {
        return Err(AppError::State(
            "当前 upgrade agent 要求 manifest 明确声明 Linux、Compose v2 和 systemd".to_owned(),
        ));
    }
    Ok(())
}

async fn download_artifact(
    artifact: &ManifestArtifact,
    registration: &crate::source::DeploymentRegistration,
) -> Result<Vec<u8>> {
    const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024;
    if artifact.size == 0 || artifact.size > MAX_ARTIFACT_BYTES {
        return Err(AppError::State(
            "upgrade artifact 超出允许的 256 MiB 大小上限".to_owned(),
        ));
    }
    let url = Url::parse(&artifact.url)
        .map_err(|error| AppError::State(format!("upgrade artifact URL 无效：{error}")))?;
    if url.scheme() != "https" || url.username() != "" || url.fragment().is_some() {
        return Err(AppError::State(
            "upgrade artifact 必须使用 HTTPS".to_owned(),
        ));
    }
    if !registration
        .release_artifact_allowed_hosts
        .iter()
        .any(|allowed| {
            url.host_str()
                .is_some_and(|host| host.eq_ignore_ascii_case(allowed))
        })
    {
        return Err(AppError::State(
            "upgrade artifact host 不在 registration allow-list 中".to_owned(),
        ));
    }
    let allowed_hosts = registration
        .release_artifact_allowed_hosts
        .iter()
        .map(|host| host.to_ascii_lowercase())
        .collect::<std::collections::BTreeSet<_>>();
    let redirect_hosts = allowed_hosts.clone();
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= 5 {
                return attempt.error("upgrade artifact redirect limit exceeded");
            }
            if attempt
                .url()
                .host_str()
                .is_some_and(|host| redirect_hosts.contains(&host.to_ascii_lowercase()))
            {
                attempt.follow()
            } else {
                attempt.error("upgrade artifact redirect host is not allow-listed")
            }
        }))
        .timeout(Duration::from_secs(600))
        .build()
        .map_err(|error| AppError::State(format!("创建 artifact 客户端失败：{error}")))?;
    let response = client
        .get(url)
        .send()
        .await
        .map_err(|error| AppError::State(format!("下载 upgrade artifact 失败：{error}")))?;
    if !response.status().is_success() {
        return Err(AppError::State(format!(
            "artifact 服务拒绝下载：HTTP {}",
            response.status()
        )));
    }
    if !response
        .url()
        .host_str()
        .is_some_and(|host| allowed_hosts.contains(&host.to_ascii_lowercase()))
    {
        return Err(AppError::State(
            "upgrade artifact 最终下载 host 不在 allow-list 中".to_owned(),
        ));
    }
    if response
        .content_length()
        .is_some_and(|size| size != artifact.size)
    {
        return Err(AppError::State(
            "upgrade artifact Content-Length 不匹配".to_owned(),
        ));
    }
    let bytes = download_limited(response, MAX_ARTIFACT_BYTES, "upgrade artifact").await?;
    if bytes.len() as u64 != artifact.size || crate::security::sha256_hex(&bytes) != artifact.sha256
    {
        return Err(AppError::State(
            "upgrade artifact size 或 SHA256 校验失败".to_owned(),
        ));
    }
    Ok(bytes.to_vec())
}

async fn download_limited(response: reqwest::Response, limit: u64, label: &str) -> Result<Vec<u8>> {
    let mut response = response;
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| AppError::State(format!("读取 {label} 失败：{error}")))?
    {
        let next_len = body
            .len()
            .checked_add(chunk.len())
            .filter(|length| *length as u64 <= limit)
            .ok_or_else(|| AppError::State(format!("{label} 超过允许的大小上限")))?;
        body.reserve(next_len.saturating_sub(body.len()));
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn state_timestamp() -> i64 {
    crate::state::unix_timestamp()
}

async fn fetch_policy(
    control_plane_url: &str,
    report_credential: &secrecy::SecretString,
) -> Result<UpgradePolicy> {
    let endpoint = format!(
        "{}/onboard/releases/current",
        control_plane_url.trim_end_matches('/')
    );
    let response = Client::new()
        .get(endpoint)
        .bearer_auth(report_credential.expose_secret())
        .header("X-MeowAI-Updater-Schema", CURRENT_UPGRADER_SCHEMA)
        .send()
        .await
        .map_err(|source| {
            AppError::Source(crate::source::SourceError::Transport {
                endpoint: "downstream release policy".to_owned(),
                source,
            })
        })?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| AppError::State(format!("读取升级策略失败：{error}")))?;
    if !status.is_success() {
        return Err(AppError::State(format!(
            "控制面拒绝升级策略：HTTP {status}"
        )));
    }
    let envelope: serde_json::Value = serde_json::from_str(&body)
        .map_err(|error| AppError::State(format!("升级策略不是有效 JSON：{error}")))?;
    if envelope.get("success").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(AppError::State("控制面返回了失败的升级策略".to_owned()));
    }
    serde_json::from_value(envelope.get("data").cloned().unwrap_or_default())
        .map_err(|error| AppError::State(format!("升级策略字段无效：{error}")))
}

fn build_plan(
    state: &DeploymentState,
    policy: &UpgradePolicy,
    manifest: Option<&ReleaseManifest>,
) -> UpgradePlan {
    let decision = policy.decision.clone().unwrap_or_else(|| {
        if policy.image_digest.is_empty() {
            if policy.release_id.is_empty() {
                UpgradeDecision::None
            } else {
                UpgradeDecision::UpgradeRequired
            }
        } else {
            UpgradeDecision::ImageOnly
        }
    });
    let mut current = BTreeMap::new();
    current.insert(
        "deployment_schema".to_owned(),
        state.deployment_schema.clone(),
    );
    current.insert("updater_schema".to_owned(), state.updater_schema.clone());
    current.insert("data_schema".to_owned(), state.data_schema.clone());
    current.insert("cli_schema".to_owned(), state.cli_schema.clone());
    current.insert("image_digest".to_owned(), state.image_digest.clone());
    current.insert("target_os".to_owned(), state.target_os.clone());
    current.insert("target_arch".to_owned(), state.target_arch.clone());
    let mut target = BTreeMap::new();
    target.insert(
        "deployment_schema".to_owned(),
        policy.minimum_deployment_schema.clone(),
    );
    target.insert(
        "updater_schema".to_owned(),
        policy.minimum_updater_schema.clone(),
    );
    target.insert("data_schema".to_owned(), policy.minimum_data_schema.clone());
    target.insert("cli_schema".to_owned(), policy.minimum_cli_schema.clone());
    let selected_artifact = manifest.and_then(|manifest| {
        manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.os == state.target_os && artifact.arch == state.target_arch)
            .cloned()
    });
    let manifest_verified = manifest.is_some();
    let required_action = match decision {
        UpgradeDecision::None => "none",
        UpgradeDecision::ImageOnly => "apply_image_only",
        UpgradeDecision::UpgradeRequired => "bootstrap_or_apply_upgrade_agent",
        UpgradeDecision::Blocked => "repair_updater_or_manual_intervention",
    }
    .to_owned();
    let canonical = serde_json::json!({
        "decision": decision,
        "reason_code": policy.reason_code,
        "release_id": policy.release_id,
        "version": policy.version,
        "upgrade_kind": policy.upgrade_kind,
        "data_rollback_required": manifest
            .map(|value| value.rollback.data_rollback_required)
            .unwrap_or(policy.data_rollback_required),
        "current": current,
        "target": target,
        "image_digest": policy.image_digest,
        "manifest_url": policy.upgrade_manifest_url,
        "manifest_sha256": policy.upgrade_manifest_sha256,
        "manifest_verified": manifest_verified,
        "selected_artifact": selected_artifact,
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&canonical).unwrap_or_default());
    let fingerprint = format!("sha256:{:x}", hasher.finalize());
    UpgradePlan {
        fingerprint,
        decision,
        reason_code: policy.reason_code.clone(),
        reason: policy.reason.clone(),
        current,
        target,
        release_id: policy.release_id.clone(),
        version: policy.version.clone(),
        upgrade_kind: policy.upgrade_kind.clone(),
        data_rollback_required: manifest
            .map(|value| value.rollback.data_rollback_required)
            .unwrap_or(policy.data_rollback_required),
        image_digest: manifest
            .map(|value| value.image_digest.clone())
            .unwrap_or_else(|| policy.image_digest.clone()),
        manifest_url: policy.upgrade_manifest_url.clone(),
        manifest_sha256: policy.upgrade_manifest_sha256.clone(),
        manifest_verified,
        selected_artifact,
        required_action,
        execution_authorized: policy.execution_authorized,
        upgrade_authorization_id: policy.upgrade_authorization_id.clone(),
        upgrade_operation_id: policy.upgrade_operation_id.clone(),
        upgrade_authorization_expires_at: policy.upgrade_authorization_expires_at,
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs, process::Command};

    use ed25519_dalek::{Signer, SigningKey};
    use secrecy::SecretString;

    use super::*;

    fn structural_policy() -> UpgradePolicy {
        UpgradePolicy {
            decision: Some(UpgradeDecision::UpgradeRequired),
            reason_code: "UPGRADE_REQUIRED".to_owned(),
            reason: "deployment schema upgrade".to_owned(),
            release_id: "rel_test".to_owned(),
            version: "2.0.0".to_owned(),
            image_repository: "ghcr.io/moorcorpa/new-api-outgap".to_owned(),
            image_digest: "sha256:target".to_owned(),
            silent_updates_enabled: false,
            minimum_updater_schema: "2".to_owned(),
            minimum_deployment_schema: "2".to_owned(),
            minimum_cli_schema: "2".to_owned(),
            minimum_data_schema: "1".to_owned(),
            upgrade_kind: "deployment_and_image".to_owned(),
            data_rollback_required: false,
            upgrade_manifest_url: "https://control.example/api/onboard/releases/rel_test/manifest"
                .to_owned(),
            upgrade_manifest_sha256: "manifest-sha".to_owned(),
            execution_authorized: false,
            upgrade_authorization_id: String::new(),
            upgrade_operation_id: String::new(),
            upgrade_authorization_expires_at: 0,
        }
    }

    fn structural_manifest() -> ReleaseManifest {
        ReleaseManifest {
            manifest_schema: 1,
            release_id: "rel_test".to_owned(),
            channel: "stable".to_owned(),
            newapi_version: "2.0.0".to_owned(),
            image_repository: "ghcr.io/moorcorpa/new-api-outgap".to_owned(),
            image_digest: "sha256:target".to_owned(),
            deployment_schema: 2,
            minimum_deployment_schema: 2,
            minimum_updater_schema: 2,
            minimum_cli_schema: 2,
            minimum_data_schema: 1,
            upgrade_kind: "deployment_and_image".to_owned(),
            required_capabilities: vec![
                "linux".to_owned(),
                "compose_v2".to_owned(),
                "systemd".to_owned(),
            ],
            artifacts: vec![
                ManifestArtifact {
                    name: "upgrade-amd64.tar.zst".to_owned(),
                    url: "https://artifacts.example/upgrade-amd64.tar.zst".to_owned(),
                    sha256: "amd64-sha".to_owned(),
                    size: 100,
                    os: "linux".to_owned(),
                    arch: "amd64".to_owned(),
                },
                ManifestArtifact {
                    name: "upgrade-arm64.tar.zst".to_owned(),
                    url: "https://artifacts.example/upgrade-arm64.tar.zst".to_owned(),
                    sha256: "arm64-sha".to_owned(),
                    size: 101,
                    os: "linux".to_owned(),
                    arch: "arm64".to_owned(),
                },
            ],
            migration_plan: ManifestMigrationPlan {
                from: 1,
                to: 2,
                steps: vec!["deployment-1-to-2".to_owned()],
            },
            health_policy: ManifestHealthPolicy {
                newapi_timeout_seconds: 120,
                dependency_timeout_seconds: 120,
                updater_heartbeat_max_age_seconds: 180,
            },
            rollback: ManifestRollback {
                supported: true,
                retained_backup_count: 3,
                data_rollback_required: false,
            },
            created_at: 1_000,
            expires_at: 2_000,
            signature: String::new(),
        }
    }

    fn registration(public_key: String) -> crate::source::DeploymentRegistration {
        crate::source::DeploymentRegistration {
            deployment_id: "dep_test".to_owned(),
            installation_generation: 1,
            control_plane_url: "https://control.example/api".to_owned(),
            report_credential: SecretString::from("report".to_owned()),
            pull_credential: SecretString::from("pull".to_owned()),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: false,
            release_schema_version: "1".to_owned(),
            release_manifest_public_key: public_key,
            release_artifact_allowed_hosts: vec!["artifacts.example".to_owned()],
        }
    }

    #[test]
    fn legacy_target_registration_can_bootstrap_without_release_trust() {
        let values = BTreeMap::from([
            ("MEOWAI_DEPLOYMENT_ID".to_owned(), "dep_legacy".to_owned()),
            ("MEOWAI_INSTALLATION_GENERATION".to_owned(), "4".to_owned()),
            (
                "MEOWAI_CONTROL_PLANE_URL".to_owned(),
                "https://control.example/api".to_owned(),
            ),
            ("MEOWAI_REPORT_CREDENTIAL".to_owned(), "report".to_owned()),
            ("MEOWAI_PULL_CREDENTIAL".to_owned(), "pull".to_owned()),
        ]);

        let legacy = registration_from_target_env_with_trust(&values, false)
            .expect("legacy registration must be readable during bootstrap");
        assert_eq!(legacy.deployment_id, "dep_legacy");
        assert!(legacy.release_manifest_public_key.is_empty());
        assert!(legacy.release_artifact_allowed_hosts.is_empty());
        assert!(registration_from_target_env(&values).is_err());
    }

    #[tokio::test]
    async fn live_github_release_redirect_requires_every_host_in_allow_list() {
        if std::env::var("MEOWAI_LIVE_GITHUB_RELEASE_REDIRECT_TEST").as_deref() != Ok("1") {
            return;
        }
        let artifact = ManifestArtifact {
            name: "meowai-deploy-linux-amd64.tar.gz".to_owned(),
            url: "https://github.com/MeowAI-Business/meowai-deploy/releases/download/v1.2.2/meowai-deploy-linux-amd64.tar.gz".to_owned(),
            sha256: "08f1220b34798ab9e55e4dcc52c9266f56093a52a6f292e3511a5c849bb9d0cc".to_owned(),
            size: 7_434_008,
            os: "linux".to_owned(),
            arch: "amd64".to_owned(),
        };
        let mut trusted = registration(String::new());
        trusted.release_artifact_allowed_hosts = vec![
            "github.com".to_owned(),
            "release-assets.githubusercontent.com".to_owned(),
        ];
        let bytes = download_artifact(&artifact, &trusted)
            .await
            .expect("allow-listed GitHub Release redirect");
        assert_eq!(bytes.len() as u64, artifact.size);

        trusted.release_artifact_allowed_hosts = vec!["github.com".to_owned()];
        let error = download_artifact(&artifact, &trusted)
            .await
            .expect_err("redirect target outside the allow-list must be rejected");
        assert!(error.to_string().contains("下载 upgrade artifact 失败"));
    }

    #[test]
    fn node_release_signer_produces_a_rust_verifiable_manifest() {
        let signing_key = SigningKey::from_bytes(&[42; 32]);
        let mut pkcs8 = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        pkcs8.extend_from_slice(&signing_key.to_bytes());
        let public_key = BASE64_STANDARD.encode(signing_key.verifying_key());
        let temporary = tempfile::tempdir().expect("temporary signer directory");
        let unsigned = temporary.path().join("unsigned.json");
        let signed = temporary.path().join("signed.json");
        fs::write(
            &unsigned,
            serde_json::to_vec(&structural_manifest()).expect("serialize unsigned manifest"),
        )
        .expect("write unsigned manifest");
        let output = Command::new("node")
            .arg(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts/sign-upgrade-manifest.mjs"),
            )
            .arg(&unsigned)
            .arg(&signed)
            .env(
                "MEOWAI_RELEASE_MANIFEST_PRIVATE_KEY",
                BASE64_STANDARD.encode(pkcs8),
            )
            .env("MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY", &public_key)
            .output()
            .expect("run Node manifest signer");
        assert!(
            output.status.success(),
            "signer stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let signed_bytes = fs::read(signed).expect("read signed manifest");
        assert!(!signed_bytes.ends_with(b"\n"));
        let manifest: ReleaseManifest =
            serde_json::from_slice(&signed_bytes).expect("parse signed manifest");
        verify_manifest(
            &manifest,
            &structural_policy(),
            &registration(public_key),
            1_500,
        )
        .expect("verify Node signature in Rust");
    }

    #[test]
    fn legacy_policy_with_digest_is_image_only() {
        let state = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "deployment_id": "d", "target_fingerprint": "t",
            "container_name": "newapi", "directory": "/tmp/newapi", "newapi_port": 3000,
            "kuma_port": 3001, "image": "image", "image_ref": "sha256:x"
        }))
        .unwrap();
        let plan = build_plan(
            &state,
            &UpgradePolicy {
                decision: None,
                reason_code: String::new(),
                reason: String::new(),
                release_id: "rel".into(),
                version: "1".into(),
                image_repository: "image".into(),
                image_digest: "sha256:d".into(),
                silent_updates_enabled: true,
                minimum_updater_schema: "1".into(),
                minimum_deployment_schema: String::new(),
                minimum_cli_schema: String::new(),
                minimum_data_schema: String::new(),
                upgrade_kind: String::new(),
                data_rollback_required: false,
                upgrade_manifest_url: String::new(),
                upgrade_manifest_sha256: String::new(),
                execution_authorized: false,
                upgrade_authorization_id: String::new(),
                upgrade_operation_id: String::new(),
                upgrade_authorization_expires_at: 0,
            },
            None,
        );
        assert_eq!(plan.decision, UpgradeDecision::ImageOnly);
        assert!(plan.fingerprint.starts_with("sha256:"));
    }

    #[test]
    fn signed_manifest_verifies_and_tampering_is_rejected() {
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let mut manifest = structural_manifest();
        let payload = serde_json::to_vec(&manifest).expect("serialize unsigned manifest");
        manifest.signature = BASE64_STANDARD.encode(signing_key.sign(&payload).to_bytes());
        let registration = registration(BASE64_STANDARD.encode(signing_key.verifying_key()));

        verify_manifest(&manifest, &structural_policy(), &registration, 1_500)
            .expect("valid signed manifest");

        manifest.deployment_schema = 3;
        assert!(verify_manifest(&manifest, &structural_policy(), &registration, 1_500).is_err());
    }

    #[test]
    fn plan_selects_artifact_for_observed_target_architecture() {
        let mut state: DeploymentState = serde_json::from_value(serde_json::json!({
            "schema_version": 1, "deployment_id": "d", "target_fingerprint": "t",
            "container_name": "newapi", "directory": "/tmp/newapi", "newapi_port": 3000,
            "kuma_port": 3001, "image": "image", "image_ref": "sha256:x",
            "target_os": "linux", "target_arch": "arm64"
        }))
        .expect("deployment state");
        state.target_arch = "arm64".to_owned();

        let plan = build_plan(&state, &structural_policy(), Some(&structural_manifest()));

        assert_eq!(
            plan.selected_artifact
                .expect("matching target artifact")
                .arch,
            "arm64"
        );
    }
}
