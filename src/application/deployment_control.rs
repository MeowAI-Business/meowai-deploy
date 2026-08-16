use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use super::error::{ApplicationError, ApplicationResult, ErrorCategory, app_error};
use crate::{
    config::DeploymentConfig,
    lifecycle_outbox,
    security::validate_env_value,
    source::{DeploymentRegistration, LifecycleReport},
    state::DeploymentState,
    storage::{self, DOWNSTREAM_CREDENTIALS_FILE},
    target::{TargetExecutor, updater},
};

#[derive(Serialize, Deserialize)]
struct PersistedDownstreamCredentials {
    deployment_id: String,
    installation_generation: u32,
    control_plane_url: String,
    report_credential: String,
    pull_credential: String,
    heartbeat_interval_seconds: u32,
    snapshot_interval_seconds: u32,
    silent_updates_enabled: bool,
    release_schema_version: String,
}

pub fn load_registration() -> ApplicationResult<Option<DeploymentRegistration>> {
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
    Ok(Some(DeploymentRegistration {
        deployment_id: stored.deployment_id,
        installation_generation: stored.installation_generation,
        control_plane_url: stored.control_plane_url,
        report_credential: SecretString::from(stored.report_credential),
        pull_credential: SecretString::from(stored.pull_credential),
        heartbeat_interval_seconds: stored.heartbeat_interval_seconds,
        snapshot_interval_seconds: stored.snapshot_interval_seconds,
        silent_updates_enabled: stored.silent_updates_enabled,
        release_schema_version: stored.release_schema_version,
    }))
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
    let stored = PersistedDownstreamCredentials {
        deployment_id: registration.deployment_id.clone(),
        installation_generation: registration.installation_generation,
        control_plane_url: registration.control_plane_url.clone(),
        report_credential: registration.report_credential.expose_secret().to_owned(),
        pull_credential: registration.pull_credential.expose_secret().to_owned(),
        heartbeat_interval_seconds: registration.heartbeat_interval_seconds,
        snapshot_interval_seconds: registration.snapshot_interval_seconds,
        silent_updates_enabled: registration.silent_updates_enabled,
        release_schema_version: registration.release_schema_version.clone(),
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
    storage::write(DOWNSTREAM_CREDENTIALS_FILE, &content).map_err(app_error)?;
    let target_content = format!(
        "MEOWAI_DEPLOYMENT_ID={}\nMEOWAI_INSTALLATION_GENERATION={}\nMEOWAI_CONTROL_PLANE_URL={}\nMEOWAI_REPORT_CREDENTIAL={}\nMEOWAI_PULL_CREDENTIAL={}\nMEOWAI_HEARTBEAT_INTERVAL_SECONDS={}\nMEOWAI_SNAPSHOT_INTERVAL_SECONDS={}\nMEOWAI_CURRENT_IMAGE_DIGEST={}\nMEOWAI_ALLOWED_IMAGE_REPOSITORY={}\nMEOWAI_CONTAINER_NAME={}\nMEOWAI_UPDATER_SOCKET_PATH=/run/meowai/updater.sock\n",
        registration.deployment_id,
        registration.installation_generation,
        registration.control_plane_url,
        registration.report_credential.expose_secret(),
        registration.pull_credential.expose_secret(),
        registration.heartbeat_interval_seconds,
        registration.snapshot_interval_seconds,
        config.image_ref,
        config.image,
        config.container_name
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
for key in MEOWAI_DEPLOYMENT_ID MEOWAI_INSTALLATION_GENERATION MEOWAI_CONTROL_PLANE_URL MEOWAI_REPORT_CREDENTIAL MEOWAI_PULL_CREDENTIAL MEOWAI_HEARTBEAT_INTERVAL_SECONDS MEOWAI_SNAPSHOT_INTERVAL_SECONDS MEOWAI_CURRENT_IMAGE_DIGEST MEOWAI_ALLOWED_IMAGE_REPOSITORY MEOWAI_CONTAINER_NAME MEOWAI_UPDATER_SOCKET_PATH; do
  count=$(grep -c "^${key}=..*" "$file" || true)
  test "$count" = 1
done"#).map_err(app_error)?;
    updater::prepare_credentials(executor).map_err(app_error)
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

pub fn remove_registration() -> ApplicationResult<()> {
    storage::remove(DOWNSTREAM_CREDENTIALS_FILE)
        .map(|_| ())
        .map_err(app_error)
}
