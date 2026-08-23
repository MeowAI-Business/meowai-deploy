use reqwest::Method;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{DeploymentRegistration, SourceClient, SourceError, SourceResult, require_data};

#[derive(Clone, Debug, Serialize)]
pub struct RepairObservationRequest {
    pub schema_version: u32,
    pub cli_schema: String,
    pub deployment_id: String,
    pub local_generation: u32,
    pub target_generation: u32,
    pub file_fingerprints: Value,
    pub services: Value,
    pub capabilities: Value,
    pub requested_actions: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RepairDiagnostic {
    pub code: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub recommended_action: Option<String>,
    #[serde(default)]
    pub automatic: bool,
    #[serde(default)]
    pub evidence: Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RepairDiagnoseReceipt {
    pub schema_version: u32,
    pub deployment_id: String,
    pub installation_generation: u32,
    #[serde(default)]
    pub diagnostics: Vec<RepairDiagnostic>,
    pub observation_fingerprint: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct RepairOperationRequest {
    pub plan_fingerprint: String,
    pub observation_fingerprint: String,
    pub diagnostics: Value,
    pub actions: Value,
    pub backup_level: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RepairOperationReceipt {
    pub operation_id: String,
    pub deployment_id: String,
    pub base_installation_generation: u32,
    pub target_installation_generation: u32,
    pub plan_fingerprint: String,
    pub observation_fingerprint: String,
    pub state: String,
    pub backup_level: String,
    pub expires_at: i64,
    pub created_at: i64,
    pub updated_at: i64,
    pub activated_at: i64,
    pub completed_at: i64,
    pub aborted_at: i64,
    pub last_error_code: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RepairProbeReceipt {
    pub state: String,
    #[serde(default)]
    pub failure_code: String,
    #[serde(default)]
    pub candidates: Value,
}

pub struct PreparedRepairCredentials {
    pub operation_id: String,
    pub installation_generation: u32,
    pub report_credential: SecretString,
    pub pull_credential: SecretString,
    pub target_challenge: String,
    pub state: String,
}

impl std::fmt::Debug for PreparedRepairCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedRepairCredentials")
            .field("operation_id", &self.operation_id)
            .field("installation_generation", &self.installation_generation)
            .field("report_credential", &"<redacted>")
            .field("pull_credential", &"<redacted>")
            .field("target_challenge", &"<redacted>")
            .field("state", &self.state)
            .finish()
    }
}

#[derive(Debug, Deserialize)]
struct PreparedRepairCredentialsData {
    operation_id: String,
    installation_generation: u32,
    report_credential: String,
    pull_credential: String,
    target_challenge: String,
    state: String,
}

impl SourceClient {
    pub async fn repair_probe(
        &mut self,
        registration: &DeploymentRegistration,
    ) -> SourceResult<RepairProbeReceipt> {
        let path = format!(
            "/api/onboard/deployments/{}/probe",
            registration.deployment_id
        );
        let envelope = self
            .authenticated_request(Method::POST, &path, Some(json!({})))
            .await?;
        require_data(envelope, &path)
    }

    /// Ask a compatible downstream agent for an immediate report. Older
    /// agents return an explicit unsupported response; callers must then use
    /// the normal heartbeat/snapshot polling fallback.
    pub async fn repair_request_report(
        &mut self,
        registration: &DeploymentRegistration,
        operation_id: &str,
    ) -> SourceResult<()> {
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations/{}/report",
            registration.deployment_id, operation_id
        );
        let envelope = self
            .authenticated_request(Method::POST, &path, Some(json!({})))
            .await?;
        let _: Value = require_data(envelope, &path)?;
        Ok(())
    }
    pub async fn repair_diagnose(
        &mut self,
        registration: &DeploymentRegistration,
        observation: &RepairObservationRequest,
    ) -> SourceResult<RepairDiagnoseReceipt> {
        let path = format!(
            "/api/onboard/deployments/{}/repair/diagnose",
            registration.deployment_id
        );
        let body =
            serde_json::to_value(observation).map_err(|error| SourceError::InvalidResponse {
                endpoint: path.clone(),
                message: error.to_string(),
            })?;
        let envelope = self
            .authenticated_request(Method::POST, &path, Some(body))
            .await?;
        require_data(envelope, &path)
    }

    pub async fn repair_create_operation(
        &mut self,
        registration: &DeploymentRegistration,
        idempotency_key: &str,
        request: &RepairOperationRequest,
    ) -> SourceResult<RepairOperationReceipt> {
        if idempotency_key.trim().is_empty() {
            return Err(SourceError::InvalidDeployment(
                "missing repair idempotency key".to_owned(),
            ));
        }
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations",
            registration.deployment_id
        );
        let body = serde_json::to_value(request).map_err(|error| SourceError::InvalidResponse {
            endpoint: path.clone(),
            message: error.to_string(),
        })?;
        let envelope = self
            .authenticated_request_with_headers(
                Method::POST,
                &path,
                Some(body),
                &[("Idempotency-Key", idempotency_key)],
            )
            .await?;
        require_data(envelope, &path)
    }

    pub async fn repair_get_operation(
        &mut self,
        registration: &DeploymentRegistration,
        operation_id: &str,
    ) -> SourceResult<RepairOperationReceipt> {
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations/{}",
            registration.deployment_id, operation_id
        );
        let envelope = self.authenticated_request(Method::GET, &path, None).await?;
        require_data(envelope, &path)
    }

    /// List recent repair operations. Used to adopt a live pending operation
    /// after the local journal was lost, instead of failing on a create
    /// conflict.
    pub async fn repair_list_operations(
        &mut self,
        registration: &DeploymentRegistration,
    ) -> SourceResult<Vec<RepairOperationReceipt>> {
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations",
            registration.deployment_id
        );
        let envelope = self.authenticated_request(Method::GET, &path, None).await?;
        #[derive(Deserialize)]
        struct OperationsData {
            #[serde(default)]
            operations: Vec<RepairOperationReceipt>,
        }
        let data: OperationsData = require_data(envelope, &path)?;
        Ok(data.operations)
    }

    pub async fn repair_prepare(
        &mut self,
        registration: &DeploymentRegistration,
        operation_id: &str,
    ) -> SourceResult<PreparedRepairCredentials> {
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations/{}/prepare",
            registration.deployment_id, operation_id
        );
        let envelope = self
            .authenticated_request(Method::POST, &path, Some(json!({})))
            .await?;
        let data: PreparedRepairCredentialsData = require_data(envelope, &path)?;
        if data.report_credential.trim().is_empty() || data.pull_credential.trim().is_empty() {
            return Err(SourceError::InvalidDeployment(
                "repair prepare returned empty credentials".to_owned(),
            ));
        }
        Ok(PreparedRepairCredentials {
            operation_id: data.operation_id,
            installation_generation: data.installation_generation,
            report_credential: SecretString::from(data.report_credential),
            pull_credential: SecretString::from(data.pull_credential),
            target_challenge: data.target_challenge,
            state: data.state,
        })
    }

    pub async fn repair_activate(
        &mut self,
        registration: &DeploymentRegistration,
        operation_id: &str,
        target_challenge: &str,
        target_applied_proof: &str,
        target_observation_fingerprint: &str,
    ) -> SourceResult<RepairOperationReceipt> {
        if target_applied_proof.trim().is_empty() || target_challenge.trim().is_empty() {
            return Err(SourceError::InvalidDeployment(
                "missing target-applied proof".to_owned(),
            ));
        }
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations/{}/activate",
            registration.deployment_id, operation_id
        );
        let envelope = self.authenticated_request(Method::POST, &path, Some(json!({"target_challenge": target_challenge, "target_applied_proof": target_applied_proof, "target_observation_fingerprint": target_observation_fingerprint}))).await?;
        require_data(envelope, &path)
    }

    pub async fn repair_abort(
        &mut self,
        registration: &DeploymentRegistration,
        operation_id: &str,
        error_code: &str,
    ) -> SourceResult<()> {
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations/{}/abort",
            registration.deployment_id, operation_id
        );
        let envelope = self
            .authenticated_request(Method::POST, &path, Some(json!({"error_code": error_code})))
            .await?;
        let _: Value = require_data(envelope, &path)?;
        Ok(())
    }

    pub async fn repair_complete(
        &mut self,
        registration: &DeploymentRegistration,
        operation_id: &str,
        state: &str,
        error_code: &str,
    ) -> SourceResult<RepairOperationReceipt> {
        let path = format!(
            "/api/onboard/deployments/{}/repair/operations/{}/complete",
            registration.deployment_id, operation_id
        );
        let envelope = self
            .authenticated_request(
                Method::POST,
                &path,
                Some(json!({"state": state, "error_code": error_code})),
            )
            .await?;
        require_data(envelope, &path)
    }
}

#[allow(dead_code)]
fn _secret_is_not_serialized_in_debug(credentials: &PreparedRepairCredentials) -> bool {
    !format!("{credentials:?}").contains(credentials.report_credential.expose_secret())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_credentials_debug_output_is_redacted() {
        let credentials = PreparedRepairCredentials {
            operation_id: "repair_test".to_owned(),
            installation_generation: 2,
            report_credential: SecretString::from("report-secret-value"),
            pull_credential: SecretString::from("pull-secret-value"),
            target_challenge: "challenge-secret-value".to_owned(),
            state: "credentials_prepared".to_owned(),
        };
        let debug = format!("{credentials:?}");
        assert!(!debug.contains("report-secret-value"));
        assert!(!debug.contains("pull-secret-value"));
        assert!(!debug.contains("challenge-secret-value"));
        assert!(debug.contains("<redacted>"));
    }
}
