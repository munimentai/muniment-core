//! The headless host value and the directories the server runs in.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use muniment_runtime_core::host::{
    plain_sign_in_page, FileCredentialStore, NoCloud, CREDENTIALS_DIRECTORY_NAME,
};
use muniment_runtime_core::RuntimeHost;

use crate::remote::RUNTIME_VERSION;

/// The reader sidecar's file name beside the server.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const READER_NAME: &str = "muniment-reader";

/// The state root's directory for the attach endpoint when
/// `XDG_RUNTIME_DIR` is unset.
const RUNTIME_DIRECTORY_NAME: &str = "run";

/// No cloud account or chat grants, secrets in files under the state root,
/// no desktop peer, the reader sidecar beside this binary when one is there,
/// this binary's version, no provider OAuth clients and a plain sign-in page.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn headless_host(state: &Path) -> RuntimeHost {
    RuntimeHost {
        account: Arc::new(NoCloud),
        chat_grants: Arc::new(NoCloud),
        credentials: Arc::new(FileCredentialStore::new(
            state.join(CREDENTIALS_DIRECTORY_NAME),
        )),
        expected_desktop_executable: None,
        reader_executable: std::env::current_exe()
            .ok()
            .as_deref()
            .and_then(reader_beside),
        runtime_version: RUNTIME_VERSION,
        provider_clients: Default::default(),
        sign_in_page: Arc::new(plain_sign_in_page),
    }
}

/// The reader sidecar beside `executable`, when the file is there.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn reader_beside(executable: &Path) -> Option<PathBuf> {
    Some(executable.parent()?.join(READER_NAME)).filter(|path| path.is_file())
}

/// The directory that holds the attach endpoint.
pub fn runtime_directory(state: &Path) -> PathBuf {
    runtime_directory_from(state, std::env::var_os("XDG_RUNTIME_DIR"))
}

fn runtime_directory_from(state: &Path, xdg_runtime: Option<OsString>) -> PathBuf {
    xdg_runtime
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| state.join(RUNTIME_DIRECTORY_NAME))
}

/// Answers the runtime directory, and creates the state root's own one with
/// mode 0700 when `XDG_RUNTIME_DIR` is unset. The attach listener refuses a
/// runtime directory that another user can open.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn prepare_runtime_directory(state: &Path) -> Result<PathBuf, String> {
    let directory = runtime_directory(state);
    if directory == state.join(RUNTIME_DIRECTORY_NAME) {
        create_private_directory(&directory)
            .map_err(|error| format!("{}: {error}", directory.display()))?;
    }
    Ok(directory)
}

fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        // A directory that already existed keeps its mode, so set it here.
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// The attach endpoint under `runtime_directory`.
#[cfg(target_os = "linux")]
pub fn endpoint_path(runtime_directory: &Path) -> Result<PathBuf, String> {
    muniment_core::attach::linux::AttachFilesystem::from_runtime_directory(runtime_directory)
        .map(|filesystem| filesystem.endpoint_path().to_path_buf())
        .map_err(|error| format!("{}: {error}", runtime_directory.display()))
}

/// The directory that holds Pi's installed revisions, as a chat launch finds
/// it: `MUNIMENT_PI_ROOT`, or `harness` under the state root.
pub fn pi_install_root(state: &Path) -> PathBuf {
    std::env::var_os("MUNIMENT_PI_ROOT")
        .filter(|root| !root.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| muniment_core::chat_profile::ChatProfile::new(state).pi_install_root())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "muniment-server-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn the_runtime_directory_falls_back_to_the_state_root() {
        let state = Path::new("/data");
        assert_eq!(
            runtime_directory_from(state, None),
            PathBuf::from("/data/run")
        );
        assert_eq!(
            runtime_directory_from(state, Some(OsString::new())),
            PathBuf::from("/data/run")
        );
        assert_eq!(
            runtime_directory_from(state, Some(OsString::from("/run/user/1000"))),
            PathBuf::from("/run/user/1000")
        );
    }

    #[test]
    fn the_state_root_runtime_directory_is_owner_only() {
        let state = temporary_directory("runtime");
        let directory = state.join(RUNTIME_DIRECTORY_NAME);
        std::fs::create_dir(&directory).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
            create_private_directory(&directory).unwrap();
            assert_eq!(
                std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn the_host_keeps_secrets_under_the_state_root_and_has_no_desktop() {
        let state = temporary_directory("host");
        let host = headless_host(&state);
        assert!(host.expected_desktop_executable.is_none());
        assert_eq!(host.runtime_version, RUNTIME_VERSION);
        host.credentials
            .write("test.server", "key", "sk_1")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(state.join("credentials/test.server/key")).unwrap(),
            "sk_1"
        );
        assert_eq!(
            host.credentials.read("test.server", "key").as_deref(),
            Some("sk_1")
        );
        std::fs::remove_dir_all(state).unwrap();
    }

    #[test]
    fn the_reader_counts_only_when_it_sits_beside_the_server() {
        let directory = temporary_directory("reader");
        let server = directory.join("muniment-server");
        assert_eq!(reader_beside(&server), None);
        std::fs::write(directory.join(READER_NAME), b"").unwrap();
        assert_eq!(reader_beside(&server), Some(directory.join(READER_NAME)));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
