use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    error::{AppError, Result},
    source::{
        DeploymentRegistration, LifecycleReport, UpgradeTransitionReport, send_lifecycle_report,
        send_upgrade_transition,
    },
    storage::{self, LIFECYCLE_OUTBOX_FILE, LIFECYCLE_OUTBOX_KEY_FILE},
};

const OUTBOX_VERSION: u32 = 1;
const MAX_PENDING_EVENTS: usize = 64;
const OUTBOX_AAD: &[u8] = b"meowai-deploy/lifecycle-outbox/v1";

#[derive(Debug, Deserialize, Serialize)]
struct EncryptedOutbox {
    version: u32,
    nonce: String,
    ciphertext: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PersistedRegistration {
    deployment_id: String,
    installation_generation: u32,
    control_plane_url: String,
    report_credential: String,
}

impl PersistedRegistration {
    fn from_registration(registration: &DeploymentRegistration) -> Self {
        Self {
            deployment_id: registration.deployment_id.clone(),
            installation_generation: registration.installation_generation,
            control_plane_url: registration.control_plane_url.clone(),
            report_credential: registration.report_credential.expose_secret().to_owned(),
        }
    }

    fn registration(&self) -> DeploymentRegistration {
        DeploymentRegistration {
            deployment_id: self.deployment_id.clone(),
            installation_generation: self.installation_generation,
            control_plane_url: self.control_plane_url.clone(),
            report_credential: SecretString::from(self.report_credential.clone()),
            pull_credential: SecretString::from(String::new()),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: true,
            release_schema_version: "1".to_owned(),
            release_manifest_public_key: String::new(),
            release_artifact_allowed_hosts: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PendingControlPlaneReport {
    Lifecycle {
        registration: PersistedRegistration,
        report: LifecycleReport,
    },
    UpgradeTransition {
        registration: PersistedRegistration,
        report: UpgradeTransitionReport,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LegacyPendingLifecycleReport {
    deployment_id: String,
    installation_generation: u32,
    control_plane_url: String,
    report_credential: String,
    report: LifecycleReport,
}

impl LegacyPendingLifecycleReport {
    fn migrate(self) -> PendingControlPlaneReport {
        PendingControlPlaneReport::Lifecycle {
            registration: PersistedRegistration {
                deployment_id: self.deployment_id,
                installation_generation: self.installation_generation,
                control_plane_url: self.control_plane_url,
                report_credential: self.report_credential,
            },
            report: self.report,
        }
    }
}

pub fn enqueue(registration: &DeploymentRegistration, report: LifecycleReport) -> Result<String> {
    let event_id = report.event_id.clone();
    let mut pending = load()?;
    if pending
        .iter()
        .any(|existing| matches!(existing, PendingControlPlaneReport::Lifecycle { report, .. } if report.event_id == event_id))
    {
        return Ok(event_id);
    }
    if pending.len() >= MAX_PENDING_EVENTS {
        return Err(AppError::State(
            "lifecycle outbox is full; retry pending reports before continuing".to_owned(),
        ));
    }
    pending.push(PendingControlPlaneReport::Lifecycle {
        registration: PersistedRegistration::from_registration(registration),
        report,
    });
    save(&pending)?;
    Ok(event_id)
}

pub fn enqueue_upgrade_transition(
    registration: &DeploymentRegistration,
    report: UpgradeTransitionReport,
) -> Result<()> {
    let mut pending = load()?;
    if pending.iter().any(|existing| {
        matches!(existing, PendingControlPlaneReport::UpgradeTransition { report: queued, .. }
            if queued.operation_id == report.operation_id && queued.state == report.state)
    }) {
        return Ok(());
    }
    if pending.len() >= MAX_PENDING_EVENTS {
        return Err(AppError::State(
            "control-plane report outbox is full; retry pending reports before continuing"
                .to_owned(),
        ));
    }
    pending.push(PendingControlPlaneReport::UpgradeTransition {
        registration: PersistedRegistration::from_registration(registration),
        report,
    });
    save(&pending)
}

pub async fn flush() -> Result<usize> {
    let mut pending = load()?;
    if pending.is_empty() {
        clear()?;
        return Ok(0);
    }
    let mut sent = 0;
    while let Some(current) = pending.first().cloned() {
        let result = match &current {
            PendingControlPlaneReport::Lifecycle {
                registration,
                report,
            } => send_lifecycle_report(&registration.registration(), report).await,
            PendingControlPlaneReport::UpgradeTransition {
                registration,
                report,
            } => send_upgrade_transition(&registration.registration(), report).await,
        };
        if let Err(error) = result {
            save(&pending)?;
            return Err(AppError::Source(error));
        }
        pending.remove(0);
        sent += 1;
        save(&pending)?;
    }
    Ok(sent)
}

/// An explicit legacy bootstrap replaces the target's report credential.  Reports
/// encrypted under an older credential can never be accepted and, if retained at
/// the head of the FIFO, would prevent the new upgrade operation from reporting
/// its own durable transitions.  Remove only records that do not belong to the
/// freshly read target registration; matching records remain ordered and retry.
pub fn discard_stale_registration(registration: &DeploymentRegistration) -> Result<usize> {
    let mut pending = load()?;
    let before = pending.len();
    pending.retain(|entry| {
        let stored = match entry {
            PendingControlPlaneReport::Lifecycle { registration, .. }
            | PendingControlPlaneReport::UpgradeTransition { registration, .. } => registration,
        };
        stored.deployment_id == registration.deployment_id
            && stored.installation_generation == registration.installation_generation
            && stored.control_plane_url == registration.control_plane_url
            && stored.report_credential == registration.report_credential.expose_secret()
    });
    let removed = before - pending.len();
    if removed > 0 {
        save(&pending)?;
    }
    Ok(removed)
}

/// `upgrade --bootstrap` is an explicit operator-approved recovery boundary.
/// An interrupted legacy operation may have transitions that cannot be accepted
/// after the target has already restored its verified backup.  They must not
/// starve the newly requested operation in the FIFO outbox.
pub fn discard_pending_for_bootstrap() -> Result<usize> {
    let pending = load()?;
    let removed = pending.len();
    if removed > 0 {
        clear()?;
    }
    Ok(removed)
}

fn load() -> Result<Vec<PendingControlPlaneReport>> {
    let Some(content) = storage::read(LIFECYCLE_OUTBOX_FILE)? else {
        return Ok(Vec::new());
    };
    let key = load_key(false)?;
    decrypt(&content, &key)
}

fn save(pending: &[PendingControlPlaneReport]) -> Result<()> {
    if pending.is_empty() {
        return clear();
    }
    let key = load_key(true)?;
    let content = encrypt(pending, &key)?;
    storage::write(LIFECYCLE_OUTBOX_FILE, &content)
}

fn clear() -> Result<()> {
    storage::remove(LIFECYCLE_OUTBOX_FILE)?;
    storage::remove(LIFECYCLE_OUTBOX_KEY_FILE)?;
    Ok(())
}

fn load_key(create: bool) -> Result<[u8; 32]> {
    if let Some(content) = storage::read(LIFECYCLE_OUTBOX_KEY_FILE)? {
        return content
            .try_into()
            .map_err(|_| AppError::State("lifecycle outbox encryption key is invalid".to_owned()));
    }
    if !create {
        return Err(AppError::State(
            "lifecycle outbox encryption key is missing".to_owned(),
        ));
    }
    let mut key = [0_u8; 32];
    OsRng.fill_bytes(&mut key);
    storage::write(LIFECYCLE_OUTBOX_KEY_FILE, &key)?;
    Ok(key)
}

fn encrypt(pending: &[PendingControlPlaneReport], key: &[u8; 32]) -> Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(pending)
        .map_err(|error| AppError::State(format!("serialize lifecycle outbox: {error}")))?;
    let mut nonce = [0_u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &plaintext,
                aad: OUTBOX_AAD,
            },
        )
        .map_err(|_| AppError::State("encrypt lifecycle outbox failed".to_owned()))?;
    serde_json::to_vec(&EncryptedOutbox {
        version: OUTBOX_VERSION,
        nonce: BASE64.encode(nonce),
        ciphertext: BASE64.encode(ciphertext),
    })
    .map_err(|error| AppError::State(format!("serialize encrypted lifecycle outbox: {error}")))
}

fn decrypt(content: &[u8], key: &[u8; 32]) -> Result<Vec<PendingControlPlaneReport>> {
    let envelope: EncryptedOutbox = serde_json::from_slice(content)
        .map_err(|error| AppError::State(format!("parse lifecycle outbox: {error}")))?;
    if envelope.version != OUTBOX_VERSION {
        return Err(AppError::State(
            "unsupported lifecycle outbox version".to_owned(),
        ));
    }
    let nonce = BASE64
        .decode(envelope.nonce)
        .map_err(|_| AppError::State("lifecycle outbox nonce is invalid".to_owned()))?;
    let nonce: [u8; 24] = nonce
        .try_into()
        .map_err(|_| AppError::State("lifecycle outbox nonce is invalid".to_owned()))?;
    let ciphertext = BASE64
        .decode(envelope.ciphertext)
        .map_err(|_| AppError::State("lifecycle outbox ciphertext is invalid".to_owned()))?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            chacha20poly1305::aead::Payload {
                msg: &ciphertext,
                aad: OUTBOX_AAD,
            },
        )
        .map_err(|_| AppError::State("decrypt lifecycle outbox failed".to_owned()))?;
    let value: Value = serde_json::from_slice(&plaintext)
        .map_err(|error| AppError::State(format!("parse decrypted lifecycle outbox: {error}")))?;
    if let Ok(pending) = serde_json::from_value::<Vec<PendingControlPlaneReport>>(value.clone()) {
        return Ok(pending);
    }
    serde_json::from_value::<Vec<LegacyPendingLifecycleReport>>(value)
        .map(|pending| {
            pending
                .into_iter()
                .map(LegacyPendingLifecycleReport::migrate)
                .collect()
        })
        .map_err(|error| AppError::State(format!("parse decrypted lifecycle outbox: {error}")))
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn pending_report(secret: &str) -> PendingControlPlaneReport {
        PendingControlPlaneReport::Lifecycle {
            registration: PersistedRegistration::from_registration(&DeploymentRegistration {
                deployment_id: "dep_outbox".to_owned(),
                installation_generation: 2,
                control_plane_url: "https://control.example/api".to_owned(),
                report_credential: SecretString::from(secret.to_owned()),
                pull_credential: SecretString::from(String::new()),
                heartbeat_interval_seconds: 60,
                snapshot_interval_seconds: 300,
                silent_updates_enabled: true,
                release_schema_version: "1".to_owned(),
                release_manifest_public_key: String::new(),
                release_artifact_allowed_hosts: Vec::new(),
            }),
            report: LifecycleReport::new("removed", "removed", "cleanup completed"),
        }
    }

    #[test]
    fn encrypted_outbox_round_trips_without_plaintext_credential() {
        let key = [7_u8; 32];
        let pending = vec![pending_report("report-credential-must-not-leak")];
        let encrypted = encrypt(&pending, &key).expect("encrypt outbox");

        assert!(!String::from_utf8_lossy(&encrypted).contains("report-credential-must-not-leak"));
        let decrypted = decrypt(&encrypted, &key).expect("decrypt outbox");
        assert_eq!(decrypted.len(), 1);
        let PendingControlPlaneReport::Lifecycle {
            registration,
            report,
        } = &decrypted[0]
        else {
            panic!("expected lifecycle report");
        };
        assert_eq!(
            registration.report_credential,
            "report-credential-must-not-leak"
        );
        let PendingControlPlaneReport::Lifecycle {
            report: expected, ..
        } = &pending[0]
        else {
            panic!("expected lifecycle report");
        };
        assert_eq!(report.event_id, expected.event_id);
    }

    #[test]
    fn encrypted_outbox_rejects_wrong_key() {
        let encrypted = encrypt(&[pending_report("secret")], &[1_u8; 32]).expect("encrypt outbox");
        assert!(decrypt(&encrypted, &[2_u8; 32]).is_err());
    }

    #[test]
    fn legacy_lifecycle_outbox_migrates_on_read() {
        let key = [3_u8; 32];
        let legacy = vec![LegacyPendingLifecycleReport {
            deployment_id: "dep_legacy".to_owned(),
            installation_generation: 5,
            control_plane_url: "https://control.example/api".to_owned(),
            report_credential: "legacy-secret".to_owned(),
            report: LifecycleReport::new("heartbeat", "active", "ok"),
        }];
        let plaintext = serde_json::to_vec(&legacy).expect("serialize legacy outbox");
        let mut nonce = [0_u8; 24];
        nonce[0] = 9;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: &plaintext,
                    aad: OUTBOX_AAD,
                },
            )
            .expect("encrypt legacy outbox");
        let envelope = serde_json::to_vec(&EncryptedOutbox {
            version: OUTBOX_VERSION,
            nonce: BASE64.encode(nonce),
            ciphertext: BASE64.encode(ciphertext),
        })
        .expect("serialize encrypted legacy outbox");

        let migrated = decrypt(&envelope, &key).expect("migrate legacy outbox");
        assert!(matches!(
            &migrated[0],
            PendingControlPlaneReport::Lifecycle { registration, .. }
                if registration.deployment_id == "dep_legacy"
                    && registration.installation_generation == 5
        ));
    }

    #[test]
    fn upgrade_transition_outbox_is_encrypted_and_round_trips() {
        let key = [8_u8; 32];
        let registration = DeploymentRegistration {
            deployment_id: "dep_upgrade".to_owned(),
            installation_generation: 3,
            control_plane_url: "https://control.example/api".to_owned(),
            report_credential: SecretString::from("transition-secret".to_owned()),
            pull_credential: SecretString::from(String::new()),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 300,
            silent_updates_enabled: true,
            release_schema_version: "1".to_owned(),
            release_manifest_public_key: String::new(),
            release_artifact_allowed_hosts: Vec::new(),
        };
        let pending = vec![PendingControlPlaneReport::UpgradeTransition {
            registration: PersistedRegistration::from_registration(&registration),
            report: UpgradeTransitionReport {
                operation_id: "op_transition_test".to_owned(),
                release_id: "rel_test".to_owned(),
                state: "BACKUP_VERIFIED".to_owned(),
                phase: "BACKUP_VERIFIED".to_owned(),
                backup_id: "backup-test".to_owned(),
                error_code: String::new(),
                error_summary: String::new(),
            },
        }];

        let encrypted = encrypt(&pending, &key).expect("encrypt transition outbox");
        assert!(!String::from_utf8_lossy(&encrypted).contains("transition-secret"));
        let decrypted = decrypt(&encrypted, &key).expect("decrypt transition outbox");
        assert!(matches!(
            &decrypted[0],
            PendingControlPlaneReport::UpgradeTransition { report, .. }
                if report.operation_id == "op_transition_test"
                    && report.state == "BACKUP_VERIFIED"
        ));
    }
}
