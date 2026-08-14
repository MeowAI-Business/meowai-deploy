use reqwest::{Method, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, de::DeserializeOwned};

use super::{SourceClient, SourceError, SourceResult, require_data};

const STATUS_KEY_PATH: &str = "/api/onboard/status-key";
const STATUS_MANIFEST_PATH: &str = "/api/onboard/status/manifest";
const STATUS_SNAPSHOT_PATH: &str = "/api/onboard/status/snapshot";

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct StatusKeyMetadata {
    pub id: i64,
    pub created_at: i64,
    pub last_used_at: i64,
    pub revoked_at: i64,
}

#[derive(Debug)]
pub struct StatusKeyProvision {
    pub metadata: StatusKeyMetadata,
    pub created: bool,
    key: Option<SecretString>,
}

impl StatusKeyProvision {
    pub fn key(&self) -> Option<&SecretString> {
        self.key.as_ref()
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct StatusMonitorManifest {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub monitor_type: String,
    pub sort_order: i32,
    pub group_id: String,
    pub group: String,
    pub interval: i32,
    pub timeout: i32,
    pub retries: i32,
    pub notifications_enabled: bool,
    pub display_enabled: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct StatusManifest {
    pub success: bool,
    pub schema_version: String,
    pub page_name: String,
    pub page_slug: String,
    pub page_description: String,
    pub theme: String,
    pub public: bool,
    pub generated_at: String,
    pub monitors: Vec<StatusMonitorManifest>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct StatusPage {
    pub name: String,
    pub slug: String,
    pub description: String,
    pub theme: String,
    pub public: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct StatusMonitorSnapshot {
    pub success: bool,
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub monitor_type: String,
    pub sort_order: i32,
    pub group_id: String,
    pub group: String,
    pub interval: i32,
    pub timeout: i32,
    pub retries: i32,
    pub notifications_enabled: bool,
    pub display_enabled: bool,
    pub status: String,
    pub message: String,
    pub checked_at: String,
    pub uptime: f64,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
pub struct StatusSnapshot {
    pub success: bool,
    pub schema_version: String,
    pub page: StatusPage,
    pub generated_at: String,
    pub monitors: Vec<StatusMonitorSnapshot>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct StatusMonitorResponse {
    pub success: bool,
    pub monitor_id: String,
    pub status: String,
    pub message: String,
    pub checked_at: String,
}

#[derive(Debug, Deserialize)]
struct StatusKeyResponse {
    #[serde(default)]
    key: Option<String>,
    #[serde(default)]
    created: bool,
    id: i64,
    created_at: i64,
    last_used_at: i64,
    revoked_at: i64,
}

impl SourceClient {
    pub async fn ensure_onboard_status_key(&mut self) -> SourceResult<StatusKeyProvision> {
        let envelope = self
            .authenticated_request::<StatusKeyResponse>(
                Method::POST,
                STATUS_KEY_PATH,
                Some(serde_json::json!({})),
            )
            .await?;
        let response = require_data(envelope, STATUS_KEY_PATH)?;
        let key = match response.key {
            Some(value) if !value.trim().is_empty() => Some(SecretString::from(value)),
            Some(_) => {
                return Err(SourceError::InvalidResponse {
                    endpoint: STATUS_KEY_PATH.to_owned(),
                    message: "status key is empty".to_owned(),
                });
            }
            None => None,
        };
        if response.created && key.is_none() {
            return Err(SourceError::InvalidResponse {
                endpoint: STATUS_KEY_PATH.to_owned(),
                message: "new status key was not returned".to_owned(),
            });
        }
        Ok(StatusKeyProvision {
            metadata: StatusKeyMetadata {
                id: response.id,
                created_at: response.created_at,
                last_used_at: response.last_used_at,
                revoked_at: response.revoked_at,
            },
            created: response.created,
            key,
        })
    }

    pub async fn revoke_onboard_status_key(&mut self) -> SourceResult<StatusKeyMetadata> {
        let envelope = self
            .authenticated_request::<StatusKeyResponse>(Method::DELETE, STATUS_KEY_PATH, None)
            .await?;
        let response = require_data(envelope, STATUS_KEY_PATH)?;
        Ok(StatusKeyMetadata {
            id: response.id,
            created_at: response.created_at,
            last_used_at: response.last_used_at,
            revoked_at: response.revoked_at,
        })
    }

    pub async fn onboard_status_manifest(
        &self,
        status_key: &SecretString,
    ) -> SourceResult<StatusManifest> {
        self.status_request(Method::GET, STATUS_MANIFEST_PATH, status_key)
            .await
    }

    pub async fn onboard_status_snapshot(
        &self,
        status_key: &SecretString,
    ) -> SourceResult<StatusSnapshot> {
        self.status_request(Method::GET, STATUS_SNAPSHOT_PATH, status_key)
            .await
    }

    pub async fn onboard_status_monitor(
        &self,
        status_key: &SecretString,
        monitor_id: &str,
    ) -> SourceResult<StatusMonitorResponse> {
        if monitor_id.is_empty()
            || !monitor_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        {
            return Err(SourceError::InvalidResponse {
                endpoint: "/api/onboard/status/monitors/:monitor_id".to_owned(),
                message: "monitor id contains unsupported characters".to_owned(),
            });
        }
        let path = format!("/api/onboard/status/monitors/{monitor_id}");
        self.status_request(Method::GET, &path, status_key).await
    }

    async fn status_request<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        status_key: &SecretString,
    ) -> SourceResult<T> {
        if status_key.expose_secret().trim().is_empty() {
            return Err(SourceError::StatusKeyRequired);
        }
        let endpoint = self.endpoint(path)?;
        let response = self
            .http
            .request(method, endpoint)
            .bearer_auth(status_key.expose_secret())
            .send()
            .await
            .map_err(|source| SourceError::Transport {
                endpoint: path.to_owned(),
                source,
            })?;
        parse_status_response(response, path).await
    }
}

async fn parse_status_response<T: DeserializeOwned>(
    response: reqwest::Response,
    endpoint: &str,
) -> SourceResult<T> {
    let status = response.status();
    if status == StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        return Err(SourceError::RateLimited {
            endpoint: endpoint.to_owned(),
            retry_after,
        });
    }
    if !status.is_success() {
        return Err(SourceError::HttpStatus {
            endpoint: endpoint.to_owned(),
            status,
        });
    }
    response
        .json::<T>()
        .await
        .map_err(|source| SourceError::Transport {
            endpoint: endpoint.to_owned(),
            source,
        })
}
