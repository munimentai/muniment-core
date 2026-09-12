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
