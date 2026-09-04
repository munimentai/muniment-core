use std::path::Path;

pub const LOCAL_MODE_MARKER: &str = "local-mode";

pub fn is_local_mode(config_directory: &Path) -> bool {
    config_directory.join(LOCAL_MODE_MARKER).is_file()
}
