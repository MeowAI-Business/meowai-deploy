use std::{
    fs,
    path::{Path, PathBuf},
};

use crate::{
    error::{AppError, Result},
    platform,
    security::write_private_file,
};

pub const CONFIG_FILE: &str = "deployment.toml";
pub const STATE_FILE: &str = "state.json";
pub const OPERATION_FILE: &str = "operation.json";
pub const CREDENTIALS_FILE: &str = "credentials.env";
pub const SESSION_FILE: &str = "session.json";
pub const SOURCE_STATUS_KEYS_FILE: &str = "source-status-keys.json";
pub const UPDATE_CHECK_FILE: &str = "update-check.json";
pub const LOG_FILE: &str = "meowai-deploy.log";
pub const WEB_DRAFT_FILE: &str = "webui-draft.json";
pub const WEB_INSTANCE_FILE: &str = "webui-instance.json";

const DEPLOYMENT_FILES: [&str; 5] = [
    CONFIG_FILE,
    STATE_FILE,
    OPERATION_FILE,
    CREDENTIALS_FILE,
    SESSION_FILE,
];

pub fn directory() -> Result<PathBuf> {
    platform::state_home()
}

pub fn exists(name: &str) -> Result<bool> {
    validate_name(name)?;
    Ok(directory()?.join(name).is_file())
}

pub fn read(name: &str) -> Result<Option<Vec<u8>>> {
    validate_name(name)?;
    let path = directory()?.join(name);
    match fs::read(&path) {
        Ok(content) => Ok(Some(content)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(AppError::ReadFile { path, source }),
    }
}

pub fn write(name: &str, content: &[u8]) -> Result<()> {
    validate_name(name)?;
    let root = ensure_directory()?;
    write_private_file(&root.join(name), content)
}

pub fn open_log_file() -> Result<fs::File> {
    let root = ensure_directory()?;
    let path = root.join(LOG_FILE);
    platform::open_private_append(&path).map_err(|source| AppError::WriteFile { path, source })
}

pub fn remove(name: &str) -> Result<bool> {
    validate_name(name)?;
    let path = directory()?.join(name);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(AppError::WriteFile { path, source }),
    }
}

pub fn clear_deployment() -> Result<()> {
    for name in DEPLOYMENT_FILES {
        remove(name)?;
    }
    Ok(())
}

fn ensure_directory() -> Result<PathBuf> {
    let root = directory()?;
    platform::ensure_private_directory(&root).map_err(|source| AppError::WriteFile {
        path: root.clone(),
        source,
    })?;
    if !platform::private_path_is_restricted(&root, true).map_err(|source| AppError::WriteFile {
        path: root.clone(),
        source,
    })? {
        return Err(AppError::State(format!(
            "state directory permissions are too broad: {}",
            root.display()
        )));
    }
    Ok(root)
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || Path::new(name).components().count() != 1 {
        return Err(AppError::State(format!(
            "invalid meowai-deploy storage file name: {name}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clearing_a_deployment_preserves_account_status_keys() {
        assert!(!DEPLOYMENT_FILES.contains(&SOURCE_STATUS_KEYS_FILE));
    }
}
