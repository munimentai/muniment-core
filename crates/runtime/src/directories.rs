use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirectoryUnavailableError;

impl std::fmt::Display for DirectoryUnavailableError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("directory is unavailable")
    }
}

impl std::error::Error for DirectoryUnavailableError {}

/// The one root for runtime state, desktop config and the agent harness:
/// `~/.muniment`, or the directory `MUNIMENT_STATE_DIR` names.
pub fn profile_directory() -> Result<PathBuf, DirectoryUnavailableError> {
    muniment_core::state_root::state_directory().ok_or(DirectoryUnavailableError)
}

/// Config and state share the root, so the desktop and the runtime read one
/// local-mode marker and one Home record.
pub fn config_directory() -> Result<PathBuf, DirectoryUnavailableError> {
    profile_directory()
}

/// Resolves the root and moves an earlier install's files under it once. An
/// adoption failure is logged and the root still answers, so a fresh start
/// follows a move the filesystem refused.
pub fn adopt_state_directory() -> Result<PathBuf, DirectoryUnavailableError> {
    use muniment_core::state_root::{adopt_legacy_state, legacy_roots, Adoption};
    let state = profile_directory()?;
    // Local mode keeps prompts in files under this root instead of the keychain.
    muniment_core::chat_prompt::install_local_prompt_store(state.clone());
    match adopt_legacy_state(&state, &legacy_roots()) {
        Ok(Adoption::Moved) => {
            muniment_core::runtime_eprintln!(
                "muniment-runtime: state_adoption outcome=moved state_directory={}",
                state.display()
            );
        }
        Ok(_) => {}
        Err(error) => {
            muniment_core::runtime_eprintln!(
                "muniment-runtime: state_adoption outcome=failed state_directory={} error={error}",
                state.display()
            );
        }
    }
    Ok(state)
}

#[cfg(all(test, target_os = "windows"))]
mod windows_tests {
    use super::*;

    #[test]
    fn profile_directory_is_the_user_profile_dotdir() {
        let profile = std::env::var_os("USERPROFILE").expect("USERPROFILE should be set");

        assert_eq!(
            profile_directory(),
            Ok(PathBuf::from(profile).join(".muniment"))
        );
    }
}
