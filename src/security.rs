use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

use rand::{Rng, distributions::Alphanumeric};
use sha2::{Digest, Sha256};

use crate::error::{AppError, Result};

pub fn random_secret(length: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(length)
        .map(char::from)
        .collect()
}

pub fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub fn write_private_file(path: &Path, content: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| AppError::State(format!("{} has no parent directory", path.display())))?;
    fs::create_dir_all(parent).map_err(|source| AppError::WriteFile {
        path: parent.to_owned(),
        source,
    })?;
    let temporary = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("secret"),
        std::process::id()
    ));
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)
        .map_err(|source| AppError::WriteFile {
            path: temporary.clone(),
            source,
        })?;
    file.write_all(content)
        .and_then(|_| file.sync_all())
        .map_err(|source| AppError::WriteFile {
            path: temporary.clone(),
            source,
        })?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(|source| {
        AppError::WriteFile {
            path: temporary.clone(),
            source,
        }
    })?;
    fs::rename(&temporary, path).map_err(|source| AppError::WriteFile {
        path: path.to_owned(),
        source,
    })
}

pub fn validate_env_value(name: &str, value: &str) -> Result<()> {
    if value.is_empty() || value.bytes().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(AppError::State(format!(
            "{name} is empty or contains a line break"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn private_file_is_written_with_owner_only_permissions() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("secrets.env");
        write_private_file(&path, b"SECRET=value\n").expect("write secret");
        let metadata = fs::metadata(path).expect("secret metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn env_values_reject_line_injection() {
        assert!(validate_env_value("TOKEN", "safe").is_ok());
        assert!(validate_env_value("TOKEN", "unsafe\nINJECTED=yes").is_err());
    }
}
