use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::error::{ApplicationError, ApplicationResult, ErrorCategory, app_error};
use crate::{
    config::DeploymentConfig,
    lifecycle_outbox,
    security::validate_env_value,
    source::{DeploymentRegistration, LifecycleReport, UpgradeTransitionReport},
    state::DeploymentState,
    storage::{self, DOWNSTREAM_CREDENTIALS_FILE},
    target::{TargetExecutor, updater},
};

#[derive(Serialize, Deserialize)]
struct PersistedDownstreamCredentials {
    #[serde(default)]
    local_deployment_id: String,
    #[serde(default)]
    source_user_id: i64,
    deployment_id: String,
    installation_generation: u32,
    control_plane_url: String,
    report_credential: String,
    pull_credential: String,
    heartbeat_interval_seconds: u32,
    snapshot_interval_seconds: u32,
    silent_updates_enabled: bool,
    release_schema_version: String,
    #[serde(default)]
    release_manifest_public_key: String,
    #[serde(default)]
    release_artifact_allowed_hosts: Vec<String>,
}

pub fn load_registration() -> ApplicationResult<Option<DeploymentRegistration>> {
    load_persisted_registration().map(|value| value.map(|(_, registration)| registration))
}

pub fn load_registration_for(
    config: &DeploymentConfig,
    source_user_id: i64,
) -> ApplicationResult<Option<DeploymentRegistration>> {
    let Some((stored, registration)) = load_persisted_registration()? else {
        return Ok(None);
    };
    if !registration_context_matches(&stored, config, source_user_id) {
        return Err(ApplicationError::new(
            ErrorCategory::Conflict,
            "CONTROL_PLANE_CONTEXT_MISMATCH",
            "已保存的控制面 registration 属于另一套部署配置",
            false,
        ));
    }
    Ok(Some(registration))
}

fn registration_context_matches(
    stored: &PersistedDownstreamCredentials,
    config: &DeploymentConfig,
    source_user_id: i64,
) -> bool {
    (stored.local_deployment_id.is_empty() || stored.local_deployment_id == config.deployment_id())
        && (stored.source_user_id == 0 || stored.source_user_id == source_user_id)
}

fn load_persisted_registration()
-> ApplicationResult<Option<(PersistedDownstreamCredentials, DeploymentRegistration)>> {
    let Some(content) = storage::read(DOWNSTREAM_CREDENTIALS_FILE).map_err(app_error)? else {
        return Ok(None);
    };
    let stored: PersistedDownstreamCredentials =
        serde_json::from_slice(&content).map_err(|error| {
            ApplicationError::new(
                ErrorCategory::Persistence,
                "DOWNSTREAM_CREDENTIALS_INVALID",
                "无法读取已保存的控制面凭证",
                false,
            )
            .with_diagnostic(error.to_string())
        })?;
    let registration = DeploymentRegistration {
        deployment_id: stored.deployment_id.clone(),
        installation_generation: stored.installation_generation,
        control_plane_url: stored.control_plane_url.clone(),
        report_credential: SecretString::from(stored.report_credential.clone()),
        pull_credential: SecretString::from(stored.pull_credential.clone()),
        heartbeat_interval_seconds: stored.heartbeat_interval_seconds,
        snapshot_interval_seconds: stored.snapshot_interval_seconds,
        silent_updates_enabled: stored.silent_updates_enabled,
        release_schema_version: stored.release_schema_version.clone(),
        release_manifest_public_key: stored.release_manifest_public_key.clone(),
        release_artifact_allowed_hosts: stored.release_artifact_allowed_hosts.clone(),
    };
    Ok(Some((stored, registration)))
}

pub fn apply_registration(
    state: &mut DeploymentState,
    registration: &DeploymentRegistration,
) -> ApplicationResult<()> {
    if !state.upstream_deployment_id.is_empty()
        && state.upstream_deployment_id != registration.deployment_id
    {
        return Err(ApplicationError::new(
            ErrorCategory::Conflict,
            "CONTROL_PLANE_IDENTITY_MISMATCH",
            "已保存的部署状态与控制面 registration 不一致",
            false,
        ));
    }
    state.upstream_deployment_id = registration.deployment_id.clone();
    state.installation_generation = registration.installation_generation;
    state.control_plane_url = registration.control_plane_url.clone();
    Ok(())
}

pub fn persist_registration(
    config: &DeploymentConfig,
    executor: &TargetExecutor,
    registration: &DeploymentRegistration,
) -> ApplicationResult<()> {
    for (name, value) in [
        ("MEOWAI_DEPLOYMENT_ID", registration.deployment_id.as_str()),
        (
            "MEOWAI_CONTROL_PLANE_URL",
            registration.control_plane_url.as_str(),
        ),
        (
            "MEOWAI_REPORT_CREDENTIAL",
            registration.report_credential.expose_secret(),
        ),
        (
            "MEOWAI_PULL_CREDENTIAL",
            registration.pull_credential.expose_secret(),
        ),
        ("MEOWAI_CURRENT_IMAGE_DIGEST", config.image_ref.as_str()),
        ("MEOWAI_ALLOWED_IMAGE_REPOSITORY", config.image.as_str()),
        ("MEOWAI_CONTAINER_NAME", config.container_name.as_str()),
    ] {
        validate_env_value(name, value).map_err(app_error)?;
    }
    if !registration.release_manifest_public_key.is_empty() {
        validate_env_value(
            "MEOWAI_RELEASE_MANIFEST_PUBLIC_KEY",
            &registration.release_manifest_public_key,
        )
        .map_err(app_error)?;
    }
    for host in &registration.release_artifact_allowed_hosts {
        validate_env_value("MEOWAI_RELEASE_ARTIFACT_ALLOWED_HOST", host).map_err(app_error)?;
        if host.contains(',') {
            return Err(app_error(crate::error::AppError::State(
                "release artifact host must not contain commas".to_owned(),
            )));
        }
    }
    let target_content = format!(
        "MEOWAI_DEPLOYMENT_ID={}\nMEOWAI_INSTALLATION_GENERATION={}\nMEOWAI_CONTROL_PLANE_URL={}\nMEOWAI_REPORT_CREDENTIAL={}\nMEOWAI_PULL_CREDENTIAL={}\nMEOWAI_HEARTBEAT_INTERVAL_SECONDS={}\nMEOWAI_SNAPSHOT_INTERVAL_SECONDS={}\nMEOWAI_CURRENT_IMAGE_DIGEST={}\nMEOWAI_DEPLOYMENT_SCHEMA=1\nMEOWAI_UPDATER_SCHEMA=1\nMEOWAI_DATA_SCHEMA=1\nMEOWAI_CLI_SCHEMA=1\nMEOWAI_ALLOWED_IMAGE_REPOSITORY={}\nMEOWAI_CONTAINER_NAME={}\nMEOWAI_NEWAPI_PORT={}\nMEOWAI_KUMA_PORT={}\nMEOWAI_RELEASE_SCHEMA_VERSION={}\nMEOWAI_RELEASE_MANIFEST_PUBLIC_KEY={}\nMEOWAI_RELEASE_ARTIFACT_ALLOWED_HOSTS={}\nMEOWAI_UPDATER_SOCKET_PATH=/run/meowai/updater.sock\n",
        registration.deployment_id,
        registration.installation_generation,
        registration.control_plane_url,
        registration.report_credential.expose_secret(),
        registration.pull_credential.expose_secret(),
        registration.heartbeat_interval_seconds,
        registration.snapshot_interval_seconds,
        config.image_ref,
        config.image,
        config.container_name,
        config.newapi_port,
        config.kuma_port,
        registration.release_schema_version,
        registration.release_manifest_public_key,
        registration.release_artifact_allowed_hosts.join(",")
    );
    executor
        .write_file(
            "downstream-credentials.env",
            target_content.as_bytes(),
            true,
        )
        .map_err(app_error)?;
    executor.run_in_directory(r#"set -eu
file=downstream-credentials.env
test -s "$file"
mode=$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file")
test "$mode" = 600
for key in MEOWAI_DEPLOYMENT_ID MEOWAI_INSTALLATION_GENERATION MEOWAI_CONTROL_PLANE_URL MEOWAI_REPORT_CREDENTIAL MEOWAI_PULL_CREDENTIAL MEOWAI_HEARTBEAT_INTERVAL_SECONDS MEOWAI_SNAPSHOT_INTERVAL_SECONDS MEOWAI_CURRENT_IMAGE_DIGEST MEOWAI_DEPLOYMENT_SCHEMA MEOWAI_UPDATER_SCHEMA MEOWAI_DATA_SCHEMA MEOWAI_CLI_SCHEMA MEOWAI_ALLOWED_IMAGE_REPOSITORY MEOWAI_CONTAINER_NAME MEOWAI_NEWAPI_PORT MEOWAI_KUMA_PORT MEOWAI_RELEASE_SCHEMA_VERSION MEOWAI_UPDATER_SOCKET_PATH; do
  count=$(grep -c "^${key}=..*" "$file" || true)
  test "$count" = 1
done"#).map_err(app_error)?;
    updater::prepare_credentials(executor).map_err(app_error)
}

pub fn persist_registration_locally(
    config: &DeploymentConfig,
    source_user_id: i64,
    registration: &DeploymentRegistration,
) -> ApplicationResult<()> {
    let stored = PersistedDownstreamCredentials {
        local_deployment_id: config.deployment_id(),
        source_user_id,
        deployment_id: registration.deployment_id.clone(),
        installation_generation: registration.installation_generation,
        control_plane_url: registration.control_plane_url.clone(),
        report_credential: registration.report_credential.expose_secret().to_owned(),
        pull_credential: registration.pull_credential.expose_secret().to_owned(),
        heartbeat_interval_seconds: registration.heartbeat_interval_seconds,
        snapshot_interval_seconds: registration.snapshot_interval_seconds,
        silent_updates_enabled: registration.silent_updates_enabled,
        release_schema_version: registration.release_schema_version.clone(),
        release_manifest_public_key: registration.release_manifest_public_key.clone(),
        release_artifact_allowed_hosts: registration.release_artifact_allowed_hosts.clone(),
    };
    let content = serde_json::to_vec_pretty(&stored).map_err(|error| {
        ApplicationError::new(
            ErrorCategory::Persistence,
            "DOWNSTREAM_CREDENTIALS_SERIALIZE_FAILED",
            "无法保存控制面凭证",
            true,
        )
        .with_diagnostic(error.to_string())
    })?;
    storage::write(DOWNSTREAM_CREDENTIALS_FILE, &content).map_err(app_error)
}

pub async fn queue_lifecycle(
    registration: &DeploymentRegistration,
    event_type: &str,
    state: &str,
    reason: &str,
) -> ApplicationResult<bool> {
    lifecycle_outbox::enqueue(
        registration,
        LifecycleReport::new(event_type, state, reason),
    )
    .map_err(app_error)?;
    match lifecycle_outbox::flush().await {
        Ok(_) => Ok(true),
        Err(error) => {
            tracing::warn!(event_type, error = %error, "lifecycle event queued for retry");
            Ok(false)
        }
    }
}

pub async fn queue_upgrade_transition(
    registration: &DeploymentRegistration,
    report: UpgradeTransitionReport,
) -> ApplicationResult<bool> {
    lifecycle_outbox::enqueue_upgrade_transition(registration, report).map_err(app_error)?;
    match lifecycle_outbox::flush().await {
        Ok(_) => Ok(true),
        Err(error) => {
            tracing::warn!(error = %error, "upgrade transition queued for retry");
            Ok(false)
        }
    }
}

pub fn remove_registration() -> ApplicationResult<()> {
    storage::remove(DOWNSTREAM_CREDENTIALS_FILE)
        .map(|_| ())
        .map_err(app_error)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stored(local_deployment_id: String, source_user_id: i64) -> PersistedDownstreamCredentials {
        PersistedDownstreamCredentials {
            local_deployment_id,
            source_user_id,
            deployment_id: "dep_test".to_owned(),
            installation_generation: 1,
            control_plane_url: "https://control.example.test/api".to_owned(),
            report_credential: "report".to_owned(),
            pull_credential: "pull".to_owned(),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: true,
            release_schema_version: "1".to_owned(),
            release_manifest_public_key: String::new(),
            release_artifact_allowed_hosts: Vec::new(),
        }
    }

    #[test]
    fn persisted_registration_is_scoped_to_source_and_local_deployment() {
        let config = DeploymentConfig::default();
        let local_id = config.deployment_id();

        assert!(registration_context_matches(
            &stored(local_id.clone(), 42),
            &config,
            42
        ));
        assert!(!registration_context_matches(
            &stored("another-deployment".to_owned(), 42),
            &config,
            42
        ));
        assert!(!registration_context_matches(
            &stored(local_id, 7),
            &config,
            42
        ));
    }
}
