use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
}

pub fn unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or_default()
}
