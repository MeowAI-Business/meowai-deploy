use std::path::Path;

use rand::{Rng, distributions::Alphanumeric};
use sha2::{Digest, Sha256};

use crate::{
    error::{AppError, Result},
    platform,
};

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
    platform::write_private_file(path, content).map_err(|source| AppError::WriteFile {
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
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[cfg(unix)]
    #[test]
    fn private_file_is_written_with_owner_only_permissions() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("secrets.env");
        write_private_file(&path, b"SECRET=value\n").expect("write secret");
        let metadata = fs::metadata(path).expect("secret metadata");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn private_file_is_replaced_atomically() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("session.json");
        write_private_file(&path, b"old").expect("initial secret");
        write_private_file(&path, b"new").expect("replacement secret");
        assert_eq!(fs::read(path).expect("secret content"), b"new");
    }

    #[test]
    fn env_values_reject_line_injection() {
        assert!(validate_env_value("TOKEN", "safe").is_ok());
        assert!(validate_env_value("TOKEN", "unsafe\nINJECTED=yes").is_err());
    }
}
