use std::path::Path;

pub const LOCAL_MODE_MARKER: &str = "local-mode";

pub fn is_local_mode(config_directory: &Path) -> bool {
    config_directory.join(LOCAL_MODE_MARKER).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_marker_file_switches_local_mode() {
        let root = std::env::temp_dir().join(format!(
            "muniment-local-mode-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).unwrap();
        assert!(!is_local_mode(&root));
        std::fs::write(root.join(LOCAL_MODE_MARKER), []).unwrap();
        assert!(is_local_mode(&root));
        std::fs::remove_file(root.join(LOCAL_MODE_MARKER)).unwrap();
        std::fs::create_dir(root.join(LOCAL_MODE_MARKER)).unwrap();
        // A directory at the marker path is not the marker.
        assert!(!is_local_mode(&root));
        std::fs::remove_dir_all(root).unwrap();
    }
}
