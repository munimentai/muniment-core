use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub const LOCAL_MODE_MARKER: &str = "local-mode";

pub fn macos_config_directory_from(
    xdg_value: Option<&OsStr>,
    home_value: Option<&OsStr>,
) -> Option<PathBuf> {
    xdg_value
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            home_value
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .map(|path| path.join("Library/Application Support"))
        })
        .map(|path| path.join("ai.muniment.desktop"))
}

pub fn macos_config_directory() -> Option<PathBuf> {
    macos_config_directory_from(
        std::env::var_os("XDG_CONFIG_HOME").as_deref(),
        std::env::var_os("HOME").as_deref(),
    )
}

pub fn is_local_mode(config_directory: &Path) -> bool {
    config_directory.join(LOCAL_MODE_MARKER).is_file()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn macos_config_uses_application_support_in_login_and_spec_homes() {
        for home in [
            "/Users/person",
            "/tmp/wdio state/degraded",
            "/tmp/wdio state/ready",
        ] {
            assert_eq!(
                macos_config_directory_from(None, Some(OsStr::new(home))).unwrap(),
                Path::new(home).join("Library/Application Support/ai.muniment.desktop")
            );
        }
    }

    #[test]
    fn macos_config_link_shares_the_marker_without_runner_environment() {
        let root = std::env::temp_dir().join(format!(
            "muniment-config-link-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let login_home = root.join("login home");
        let runtime_config =
            macos_config_directory_from(None, Some(login_home.as_os_str())).unwrap();
        std::fs::create_dir_all(runtime_config.parent().unwrap()).unwrap();
        for spec in ["degraded", "ready"] {
            let spec_home = root.join(spec);
            let desktop_config =
                macos_config_directory_from(None, Some(spec_home.as_os_str())).unwrap();
            std::fs::create_dir_all(&desktop_config).unwrap();
            std::os::unix::fs::symlink(&desktop_config, &runtime_config).unwrap();
            assert_eq!(
                std::fs::canonicalize(&runtime_config).unwrap(),
                std::fs::canonicalize(&desktop_config).unwrap()
            );
            assert!(!is_local_mode(&runtime_config));
            let marker = desktop_config.join(LOCAL_MODE_MARKER);
            std::fs::write(&marker, []).unwrap();
            assert!(is_local_mode(&runtime_config));
            std::fs::remove_file(marker).unwrap();
            assert!(!is_local_mode(&runtime_config));
            std::fs::remove_file(&runtime_config).unwrap();
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn macos_config_override_keeps_launchd_and_the_desktop_in_the_spec_home() {
        let config = OsStr::new("/tmp/wdio state/degraded/Library/Application Support");
        for home in [
            None,
            Some(OsStr::new("/Users/person")),
            Some(OsStr::new("/tmp/wdio state/degraded")),
        ] {
            assert_eq!(
                macos_config_directory_from(Some(config), home).unwrap(),
                Path::new(config).join("ai.muniment.desktop")
            );
        }
        for invalid in ["", "relative/config"] {
            assert_eq!(
                macos_config_directory_from(
                    Some(OsStr::new(invalid)),
                    Some(OsStr::new("/Users/person"))
                )
                .unwrap(),
                Path::new("/Users/person/Library/Application Support/ai.muniment.desktop")
            );
            assert_eq!(
                macos_config_directory_from(
                    Some(OsStr::new(invalid)),
                    Some(OsStr::new("relative/home"))
                ),
                None
            );
        }
        assert_eq!(macos_config_directory_from(None, None), None);
    }
}
