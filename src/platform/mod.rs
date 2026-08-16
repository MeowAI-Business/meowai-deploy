use std::{
    env,
    io::{IsTerminal, stdin, stdout},
    path::PathBuf,
};

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

pub const fn supports_local_target() -> bool {
    cfg!(unix)
}

pub fn should_launch_webui_without_args() -> bool {
    should_launch_webui_in_context(
        env::var_os("MEOWAI_DEPLOY_DISABLE_GUI").is_some(),
        stdin().is_terminal(),
        stdout().is_terminal(),
        implementation::launched_from_desktop_shell(),
    )
}

fn should_launch_webui_in_context(
    disabled: bool,
    stdin_is_terminal: bool,
    stdout_is_terminal: bool,
    launched_from_desktop_shell: bool,
) -> bool {
    !disabled && stdin_is_terminal && stdout_is_terminal && launched_from_desktop_shell
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_target_capability_matches_the_control_platform() {
        assert_eq!(supports_local_target(), cfg!(unix));
    }

    #[cfg(unix)]
    #[test]
    fn terminal_no_args_never_launches_webui_on_unix() {
        assert!(!implementation::launched_from_desktop_shell());
    }

    #[test]
    fn desktop_launch_requires_both_terminals_and_no_disable_override() {
        assert!(should_launch_webui_in_context(false, true, true, true));
        assert!(!should_launch_webui_in_context(true, true, true, true));
        assert!(!should_launch_webui_in_context(false, false, true, true));
        assert!(!should_launch_webui_in_context(false, true, false, true));
        assert!(!should_launch_webui_in_context(false, true, true, false));
    }
}
