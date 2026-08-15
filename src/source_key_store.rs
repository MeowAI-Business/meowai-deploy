use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::{
    error::{AppError, Result},
    security::validate_env_value,
    storage::{self, SOURCE_STATUS_KEYS_FILE},
};

#[derive(Default, Deserialize, Serialize)]
struct SourceStatusKeyStore {
    #[serde(default = "store_version")]
    version: u32,
    #[serde(default)]
    entries: Vec<SourceStatusKeyEntry>,
}

#[derive(Deserialize, Serialize)]
struct SourceStatusKeyEntry {
    source_url: String,
    source_user_id: i64,
    status_key_id: i64,
    key: String,
}

pub fn load(
    source_url: &str,
    source_user_id: i64,
    status_key_id: i64,
) -> Result<Option<SecretString>> {
    let source_url = normalize_source_url(source_url)?;
    let store = read_store()?;
    Ok(store
        .entries
        .into_iter()
        .find(|entry| {
            entry.source_url == source_url
                && entry.source_user_id == source_user_id
                && entry.status_key_id == status_key_id
        })
        .map(|entry| SecretString::from(entry.key)))
}

pub fn save(
    source_url: &str,
    source_user_id: i64,
    status_key_id: i64,
    key: &SecretString,
) -> Result<()> {
    validate_identity(source_user_id, status_key_id)?;
    validate_env_value("PUBLIC_STATUS_SOURCE_KEY", key.expose_secret())?;
    let source_url = normalize_source_url(source_url)?;
    let mut store = read_store()?;
    store
        .entries
        .retain(|entry| entry.source_url != source_url || entry.source_user_id != source_user_id);
    store.entries.push(SourceStatusKeyEntry {
        source_url,
        source_user_id,
        status_key_id,
        key: key.expose_secret().to_owned(),
    });
    write_store(&store)
}

pub fn remove(source_url: &str, source_user_id: i64) -> Result<()> {
    let source_url = normalize_source_url(source_url)?;
    let mut store = read_store()?;
    let previous_len = store.entries.len();
    store
        .entries
        .retain(|entry| entry.source_url != source_url || entry.source_user_id != source_user_id);
    if store.entries.len() != previous_len {
        write_store(&store)?;
    }
    Ok(())
}

pub fn ensure_writable() -> Result<()> {
    let store = read_store()?;
    write_store(&store)
}

fn normalize_source_url(source_url: &str) -> Result<String> {
    let mut url = url::Url::parse(source_url)
        .map_err(|error| AppError::State(format!("invalid source URL in key store: {error}")))?;
    url.set_path("/");
    url.set_query(None);
    url.set_fragment(None);
    Ok(url.to_string())
}

fn read_store() -> Result<SourceStatusKeyStore> {
    let Some(content) = storage::read(SOURCE_STATUS_KEYS_FILE)? else {
        return Ok(SourceStatusKeyStore {
            version: store_version(),
            entries: Vec::new(),
        });
    };
    let store: SourceStatusKeyStore = serde_json::from_slice(&content)
        .map_err(|error| AppError::State(format!("parse {SOURCE_STATUS_KEYS_FILE}: {error}")))?;
    if store.version != store_version() {
        return Err(AppError::State(format!(
            "unsupported {SOURCE_STATUS_KEYS_FILE} version {}",
            store.version
        )));
    }
    Ok(store)
}

fn write_store(store: &SourceStatusKeyStore) -> Result<()> {
    let content = serde_json::to_vec_pretty(store).map_err(|error| {
        AppError::State(format!("serialize {SOURCE_STATUS_KEYS_FILE}: {error}"))
    })?;
    storage::write(SOURCE_STATUS_KEYS_FILE, &content)
}

fn validate_identity(source_user_id: i64, status_key_id: i64) -> Result<()> {
    if source_user_id <= 0 || status_key_id <= 0 {
        return Err(AppError::State(
            "source user id and status key id must be positive".to_owned(),
        ));
    }
    Ok(())
}

const fn store_version() -> u32 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_url_identity_ignores_a_trailing_slash() {
        assert_eq!(
            normalize_source_url("http://localhost:3004").expect("URL"),
            normalize_source_url("http://localhost:3004/").expect("URL")
        );
    }
}
