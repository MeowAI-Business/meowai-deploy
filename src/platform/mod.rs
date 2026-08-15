use std::{env, path::PathBuf};

use crate::error::{AppError, Result};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
use unix as implementation;
#[cfg(windows)]
use windows as implementation;

pub use implementation::{
    ensure_private_directory, open_private_append, private_path_is_restricted, write_private_file,
};

pub fn state_home() -> Result<PathBuf> {
    if let Some(path) = env::var_os("MEOWAI_DEPLOY_HOME") {
        let path = PathBuf::from(path);
        if !path.is_absolute() {
            return Err(AppError::State(
                "MEOWAI_DEPLOY_HOME must be an absolute path".to_owned(),
            ));
        }
        return Ok(path);
    }

    implementation::user_profile_directory()
        .map(|path| path.join(".meowai-deploy"))
        .ok_or_else(|| {
            AppError::State("cannot resolve the current user's profile directory".to_owned())
        })
}

#[allow(dead_code)]
pub const fn supports_local_target() -> bool {
    cfg!(unix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_target_capability_matches_the_control_platform() {
        assert_eq!(supports_local_target(), cfg!(unix));
    }
}
