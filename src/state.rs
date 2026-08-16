use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{error::Result, storage};

pub const DOWNSTREAM_CLEANUP_PHASE: &str = "downstream_cleanup";
pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct SnapshotModule {
    pub fingerprint: String,
    pub data: Value,
    pub observed_at: i64,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
pub struct SyncSnapshot {
    pub schema_version: u32,
    pub captured_at: i64,
    #[serde(default)]
    pub modules: BTreeMap<String, SnapshotModule>,
}

impl SyncSnapshot {
    pub fn new() -> Self {
        Self {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            captured_at: unix_timestamp(),
            modules: BTreeMap::new(),
        }
    }

    pub fn set_module(
        &mut self,
        module: impl Into<String>,
        data: Value,
        fingerprint: impl Into<String>,
    ) {
        self.modules.insert(
            module.into(),
            SnapshotModule {
                fingerprint: fingerprint.into(),
                data,
                observed_at: unix_timestamp(),
            },
        );
        self.captured_at = unix_timestamp();
    }
}

pub fn load_snapshot(name: &str) -> Result<Option<SyncSnapshot>> {
    storage::read_snapshot(name)?.map_or(Ok(None), |content| {
        serde_json::from_slice(&content).map(Some).map_err(|error| {
            crate::error::AppError::State(format!("invalid sync snapshot: {error}"))
        })
    })
}

pub fn save_snapshot(name: &str, snapshot: &SyncSnapshot) -> Result<()> {
    let content = serde_json::to_vec_pretty(snapshot).map_err(|error| {
        crate::error::AppError::State(format!("serialize sync snapshot: {error}"))
    })?;
    storage::write_snapshot(name, &content)
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ResourcePhase {
    pub status: String,
    pub updated_at: i64,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ChannelState {
    pub group_id: String,
    pub group_name: String,
    pub token_id: i64,
    pub token_name: String,
    pub channel_id: i64,
    pub key_sha256: String,
    pub config_sha256: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct KumaMonitorState {
    pub source_monitor_id: String,
    pub kuma_monitor_id: i64,
    pub config_sha256: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct DeploymentState {
    pub schema_version: u32,
    pub deployment_id: String,
    pub target_fingerprint: String,
    pub container_name: String,
    pub directory: String,
    pub newapi_port: u16,
    pub kuma_port: u16,
    pub image: String,
    pub image_ref: String,
    #[serde(default)]
    pub image_digest: String,
    #[serde(default)]
    pub source_user_id: i64,
    #[serde(default)]
    pub source_group_sha256: String,
    #[serde(default)]
    pub status_key_id: i64,
    #[serde(default)]
    pub manifest_sha256: String,
    #[serde(default)]
    pub pricing_sha256: BTreeMap<String, String>,
    #[serde(default)]
    pub channels: BTreeMap<String, ChannelState>,
    #[serde(default)]
    pub kuma_monitors: BTreeMap<String, KumaMonitorState>,
    #[serde(default)]
    pub phases: BTreeMap<String, ResourcePhase>,
    #[serde(default)]
    pub last_sync_at: i64,
    #[serde(default)]
    pub last_sync_success: bool,
    #[serde(default)]
    pub snapshot_schema_version: u32,
    #[serde(default)]
    pub last_applied_at: BTreeMap<String, i64>,
}

impl DeploymentState {
    pub fn mark_phase(&mut self, name: &str, status: &str, detail: impl Into<String>) {
        self.phases.insert(
            name.to_owned(),
            ResourcePhase {
                status: status.to_owned(),
                updated_at: unix_timestamp(),
                detail: detail.into(),
            },
        );
    }

    pub fn downstream_is_initialized(&self) -> bool {
        self.snapshot_schema_version > 0
            || ["newapi", "pricing", "channels", "kuma", "onboard"]
                .into_iter()
                .any(|name| {
                    self.phases
                        .get(name)
                        .is_some_and(|phase| phase.status == "DONE")
                })
    }
}

pub fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn legacy_state_deserializes_with_snapshot_defaults() {
        let legacy = json!({
            "schema_version": 1,
            "deployment_id": "legacy",
            "target_fingerprint": "host",
            "container_name": "newapi",
            "directory": "/opt/newapi",
            "newapi_port": 3000,
            "kuma_port": 3001,
            "image": "image",
            "image_ref": "sha256:abc",
            "image_digest": "",
            "source_user_id": 7,
            "source_group_sha256": "group",
            "status_key_id": 1,
            "manifest_sha256": "",
            "pricing_sha256": {},
            "channels": {},
            "kuma_monitors": {},
            "phases": {},
            "last_sync_at": 0,
            "last_sync_success": false
        });
        let state: DeploymentState = serde_json::from_value(legacy).expect("legacy state");
        assert_eq!(state.snapshot_schema_version, 0);
        assert!(state.last_applied_at.is_empty());
        assert!(!state.downstream_is_initialized());
    }

    #[test]
    fn completed_downstream_phase_marks_deployment_initialized() {
        let mut state: DeploymentState = serde_json::from_value(json!({
            "schema_version": 1,
            "deployment_id": "deployment",
            "target_fingerprint": "host",
            "container_name": "newapi",
            "directory": "/opt/newapi",
            "newapi_port": 3000,
            "kuma_port": 3001,
            "image": "image",
            "image_ref": "sha256:abc"
        }))
        .expect("state");
        assert!(!state.downstream_is_initialized());
        state.mark_phase("newapi", "DONE", "initialized");
        assert!(state.downstream_is_initialized());
    }
}
