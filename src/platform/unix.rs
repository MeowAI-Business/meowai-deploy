use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rand::Rng;

pub fn user_profile_directory() -> Option<PathBuf> {
    env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub const fn launched_from_desktop_shell() -> bool {
    false
}

pub fn ensure_private_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub fn open_private_append(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(file)
}

pub fn write_private_file(path: &Path, content: &[u8]) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = unique_temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temporary, path)?;
        sync_parent(parent)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub fn private_path_is_restricted(path: &Path, directory: bool) -> io::Result<bool> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    let expected = if directory { 0o700 } else { 0o600 };
    Ok(mode == expected)
}

fn unique_temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("private");
    let random = rand::thread_rng().r#gen::<u64>();
    path.with_file_name(format!(".{name}.tmp-{}-{random:016x}", std::process::id()))
}

fn sync_parent(parent: &Path) -> io::Result<()> {
    File::open(parent)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_directory_and_file_use_owner_only_modes() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let root = temporary.path().join("state");
        ensure_private_directory(&root).expect("private directory");
        let path = root.join("session.json");
        write_private_file(&path, b"{}\n").expect("private file");
        assert!(private_path_is_restricted(&root, true).expect("directory mode"));
        assert!(private_path_is_restricted(&path, false).expect("file mode"));
    }

    #[test]
    fn failed_replacement_preserves_the_existing_file() {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let path = temporary.path().join("session.json");
        write_private_file(&path, b"old").expect("initial file");
        let replacement_error = write_private_file(&path.join("child"), b"new");
        assert!(replacement_error.is_err());
        assert_eq!(fs::read(path).expect("existing file"), b"old");
    }
}
