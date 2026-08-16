use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use chacha20poly1305::{
    Key, KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, rand_core::RngCore},
};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, Result},
    source::{DeploymentRegistration, LifecycleReport, send_lifecycle_report},
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
struct PendingLifecycleReport {
    deployment_id: String,
    installation_generation: u32,
    control_plane_url: String,
    report_credential: String,
    report: LifecycleReport,
}

impl PendingLifecycleReport {
    fn from_registration(registration: &DeploymentRegistration, report: LifecycleReport) -> Self {
        Self {
            deployment_id: registration.deployment_id.clone(),
            installation_generation: registration.installation_generation,
            control_plane_url: registration.control_plane_url.clone(),
            report_credential: registration.report_credential.expose_secret().to_owned(),
            report,
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
        }
    }
}

pub fn enqueue(registration: &DeploymentRegistration, report: LifecycleReport) -> Result<String> {
    let event_id = report.event_id.clone();
    let mut pending = load()?;
    if pending
        .iter()
        .any(|existing| existing.report.event_id == event_id)
    {
        return Ok(event_id);
    }
    if pending.len() >= MAX_PENDING_EVENTS {
        return Err(AppError::State(
            "lifecycle outbox is full; retry pending reports before continuing".to_owned(),
        ));
    }
    pending.push(PendingLifecycleReport::from_registration(
        registration,
        report,
    ));
    save(&pending)?;
    Ok(event_id)
}

pub fn remove(event_id: &str) -> Result<()> {
    let mut pending = load()?;
    pending.retain(|report| report.report.event_id != event_id);
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
        if let Err(error) = send_lifecycle_report(&current.registration(), &current.report).await {
            save(&pending)?;
            return Err(AppError::Source(error));
        }
        pending.remove(0);
        sent += 1;
        save(&pending)?;
    }
    Ok(sent)
}

fn load() -> Result<Vec<PendingLifecycleReport>> {
    let Some(content) = storage::read(LIFECYCLE_OUTBOX_FILE)? else {
        return Ok(Vec::new());
    };
    let key = load_key(false)?;
    decrypt(&content, &key)
}

fn save(pending: &[PendingLifecycleReport]) -> Result<()> {
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

fn encrypt(pending: &[PendingLifecycleReport], key: &[u8; 32]) -> Result<Vec<u8>> {
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

fn decrypt(content: &[u8], key: &[u8; 32]) -> Result<Vec<PendingLifecycleReport>> {
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
    serde_json::from_slice(&plaintext)
        .map_err(|error| AppError::State(format!("parse decrypted lifecycle outbox: {error}")))
}

#[cfg(test)]
mod tests {
    use secrecy::SecretString;

    use super::*;

    fn pending_report(secret: &str) -> PendingLifecycleReport {
        PendingLifecycleReport::from_registration(
            &DeploymentRegistration {
                deployment_id: "dep_outbox".to_owned(),
                installation_generation: 2,
                control_plane_url: "https://control.example/api".to_owned(),
                report_credential: SecretString::from(secret.to_owned()),
                pull_credential: SecretString::from(String::new()),
                heartbeat_interval_seconds: 60,
                snapshot_interval_seconds: 300,
                silent_updates_enabled: true,
                release_schema_version: "1".to_owned(),
            },
            LifecycleReport::new("removed", "removed", "cleanup completed"),
        )
    }

    #[test]
    fn encrypted_outbox_round_trips_without_plaintext_credential() {
        let key = [7_u8; 32];
        let pending = vec![pending_report("report-credential-must-not-leak")];
        let encrypted = encrypt(&pending, &key).expect("encrypt outbox");

        assert!(!String::from_utf8_lossy(&encrypted).contains("report-credential-must-not-leak"));
        let decrypted = decrypt(&encrypted, &key).expect("decrypt outbox");
        assert_eq!(decrypted.len(), 1);
        assert_eq!(
            decrypted[0].report_credential,
            "report-credential-must-not-leak"
        );
        assert_eq!(decrypted[0].report.event_id, pending[0].report.event_id);
    }

    #[test]
    fn encrypted_outbox_rejects_wrong_key() {
        let encrypted = encrypt(&[pending_report("secret")], &[1_u8; 32]).expect("encrypt outbox");
        assert!(decrypt(&encrypted, &[2_u8; 32]).is_err());
    }
}
