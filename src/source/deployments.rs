use reqwest::Method;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_json::json;

use super::{SourceClient, SourceError, SourceResult, require_data};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DeploymentRegistration {
    pub deployment_id: String,
    pub installation_generation: u32,
    pub control_plane_url: String,
    #[serde(skip)]
    pub report_credential: SecretString,
    #[serde(skip)]
    pub pull_credential: SecretString,
    pub heartbeat_interval_seconds: u32,
    pub snapshot_interval_seconds: u32,
    pub silent_updates_enabled: bool,
    pub release_schema_version: String,
}

#[derive(Debug, Deserialize)]
struct RegistrationData {
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

#[derive(Clone, Debug, Serialize)]
pub struct DeploymentMetadata<'a> {
    pub site_name: &'a str,
    pub container_name: &'a str,
    pub target_type: &'a str,
    pub verified_primary_endpoint: &'a str,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LifecycleReport {
    pub event_id: String,
    pub event_type: String,
    pub state: String,
    pub reason: String,
    pub occurred_at: i64,
}

impl LifecycleReport {
    pub fn new(event_type: &str, state: &str, reason: &str) -> Self {
        Self {
            event_id: format!("evt_{}", crate::security::random_secret(32)),
            event_type: event_type.to_owned(),
            state: state.to_owned(),
            reason: reason.to_owned(),
            occurred_at: crate::state::unix_timestamp(),
        }
    }
}

impl SourceClient {
    pub async fn register_deployment(
        &mut self,
        idempotency_key: &str,
    ) -> SourceResult<DeploymentRegistration> {
        if idempotency_key.trim().is_empty() {
            return Err(SourceError::InvalidDeployment(
                "missing registration idempotency key".to_owned(),
            ));
        }
        let envelope = self
            .authenticated_request_with_headers::<RegistrationData>(
                Method::POST,
                "/api/onboard/deployments/register",
                Some(json!({"schema_version": "1"})),
                &[("Idempotency-Key", idempotency_key)],
            )
            .await?;
        let data = require_data(envelope, "/api/onboard/deployments/register")?;
        if data.deployment_id.trim().is_empty()
            || data.control_plane_url.trim().is_empty()
            || data.report_credential.trim().is_empty()
            || data.pull_credential.trim().is_empty()
        {
            return Err(SourceError::InvalidDeployment(
                "registration response is missing credentials".to_owned(),
            ));
        }
        if !data.deployment_id.starts_with("dep_")
            || !data
                .deployment_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            || data.installation_generation == 0
            || !(30..=3600).contains(&data.heartbeat_interval_seconds)
            || !(60..=86_400).contains(&data.snapshot_interval_seconds)
        {
            return Err(SourceError::InvalidDeployment(
                "registration response contains invalid deployment metadata".to_owned(),
            ));
        }
        super::control_plane_endpoint(&data.control_plane_url, "/api/status")?;
        Ok(DeploymentRegistration {
            deployment_id: data.deployment_id,
            installation_generation: data.installation_generation,
            control_plane_url: data.control_plane_url,
            report_credential: SecretString::from(data.report_credential),
            pull_credential: SecretString::from(data.pull_credential),
            heartbeat_interval_seconds: data.heartbeat_interval_seconds,
            snapshot_interval_seconds: data.snapshot_interval_seconds,
            silent_updates_enabled: data.silent_updates_enabled,
            release_schema_version: data.release_schema_version,
        })
    }

    pub async fn update_deployment_metadata(
        &mut self,
        registration: &DeploymentRegistration,
        metadata: &DeploymentMetadata<'_>,
    ) -> SourceResult<()> {
        let path = format!(
            "/api/onboard/deployments/{}/metadata",
            registration.deployment_id
        );
        self.report_request(
            Method::PATCH,
            &path,
            Some(
                serde_json::to_value(metadata).map_err(|error| SourceError::InvalidResponse {
                    endpoint: path.clone(),
                    message: error.to_string(),
                })?,
            ),
            registration,
        )
        .await
    }

    pub async fn report_lifecycle(
        &mut self,
        registration: &DeploymentRegistration,
        event_type: &str,
        state: &str,
        reason: &str,
    ) -> SourceResult<()> {
        self.report_lifecycle_event(
            registration,
            &LifecycleReport::new(event_type, state, reason),
        )
        .await
    }

    async fn report_lifecycle_event(
        &self,
        registration: &DeploymentRegistration,
        report: &LifecycleReport,
    ) -> SourceResult<()> {
        let path = format!(
            "/api/onboard/deployments/{}/lifecycle",
            registration.deployment_id
        );
        self.report_request(
            Method::POST,
            &path,
            Some(json!({
                "type": report.event_type,
                "state": report.state,
                "reason": report.reason,
                "occurred_at": report.occurred_at,
                "installation_generation": registration.installation_generation,
                "event_id": report.event_id,
            })),
            registration,
        )
        .await
    }

    async fn report_request(
        &self,
        method: Method,
        path: &str,
        body: Option<serde_json::Value>,
        registration: &DeploymentRegistration,
    ) -> SourceResult<()> {
        let envelope = self
            .signed_request_with_credential::<serde_json::Value>(
                method,
                path,
                &registration.control_plane_url,
                body,
                &registration.report_credential,
                registration.installation_generation,
            )
            .await?;
        let _ = require_data(envelope, path)?;
        Ok(())
    }
}

pub async fn send_lifecycle_report(
    registration: &DeploymentRegistration,
    report: &LifecycleReport,
) -> SourceResult<()> {
    let mut root = super::control_plane_endpoint(&registration.control_plane_url, "/")?;
    root.set_path("/");
    let client = SourceClient::new(root.as_str())?;
    client.report_lifecycle_event(registration, report).await
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac};
    use secrecy::SecretString;
    use serde_json::{Value, json};
    use sha2::Sha256;
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::{DeploymentMetadata, DeploymentRegistration, SourceClient};

    #[tokio::test]
    async fn report_request_carries_generation_sequence_and_valid_hmac() {
        let server = MockServer::start().await;
        Mock::given(method("PATCH"))
            .and(path("/api/onboard/deployments/dep_signed/metadata"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "success": true,
                "code": "",
                "message": "",
                "data": {}
            })))
            .mount(&server)
            .await;

        let mut client = SourceClient::new(&server.uri()).expect("source client");
        let registration = DeploymentRegistration {
            deployment_id: "dep_signed".to_owned(),
            installation_generation: 4,
            control_plane_url: format!("{}/api", server.uri()),
            report_credential: SecretString::from("report-signing-secret"),
            pull_credential: SecretString::from("pull-secret"),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: true,
            release_schema_version: "1".to_owned(),
        };
        client
            .update_deployment_metadata(
                &registration,
                &DeploymentMetadata {
                    site_name: "Example",
                    container_name: "example-newapi",
                    target_type: "local",
                    verified_primary_endpoint: "",
                },
            )
            .await
            .expect("signed metadata report");

        let requests = server.received_requests().await.expect("record requests");
        let request = requests.first().expect("metadata request");
        let body: Value = serde_json::from_slice(&request.body).expect("JSON body");
        assert_eq!(body["installation_generation"], 4);
        let sequence = body["sequence"].as_i64().expect("sequence");
        let timestamp = request.headers["x-meowai-timestamp"]
            .to_str()
            .expect("timestamp");
        let nonce = request.headers["x-meowai-nonce"].to_str().expect("nonce");
        assert_eq!(
            request.headers["x-meowai-sequence"]
                .to_str()
                .expect("header sequence"),
            sequence.to_string()
        );
        let canonical = format!(
            "PATCH\n/api/onboard/deployments/dep_signed/metadata\n{timestamp}\n{nonce}\n{sequence}\n{}",
            String::from_utf8_lossy(&request.body)
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(b"report-signing-secret").expect("HMAC key");
        mac.update(canonical.as_bytes());
        assert_eq!(
            request.headers["x-meowai-signature"]
                .to_str()
                .expect("signature"),
            crate::source::encode_hex(&mac.finalize().into_bytes())
        );
    }
}
