use std::{
    env,
    fs::{self, OpenOptions},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use crate::{
    error::{AppError, Result},
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

const DEPLOYMENT_FILES: [&str; 5] = [
    CONFIG_FILE,
    STATE_FILE,
    OPERATION_FILE,
    CREDENTIALS_FILE,
    SESSION_FILE,
];

pub fn directory() -> Result<PathBuf> {
    if let Some(path) = env::var_os("MEOWAI_DEPLOY_HOME") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(AppError::State(
                "MEOWAI_DEPLOY_HOME must be an absolute path".to_owned(),
            ));
        }
        return Ok(path);
    }
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| {
            AppError::State("cannot resolve the current user's home directory".to_owned())
        })?;
    Ok(home.join(".meowai-deploy"))
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
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|source| AppError::WriteFile {
            path: path.clone(),
            source,
        })?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
        .map_err(|source| AppError::WriteFile { path, source })?;
    Ok(file)
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
    fs::create_dir_all(&root).map_err(|source| AppError::WriteFile {
        path: root.clone(),
        source,
    })?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).map_err(|source| {
        AppError::WriteFile {
            path: root.clone(),
            source,
        }
    })?;
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
