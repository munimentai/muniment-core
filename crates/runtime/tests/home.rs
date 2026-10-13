use std::fs;

use muniment_core::attach::ErrorCode;
use muniment_runtime_core::ensure_home;

const SCAFFOLD_DIRECTORIES: [&str; 4] = ["memory", "agents", "projects", "sessions"];

fn temporary_path(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-runtime-home-{name}-{}",
        std::process::id()
    ))
}

#[test]
fn creates_each_home_scaffold_and_preserves_it_on_a_second_call() {
    let home = temporary_path("scaffold");
    fs::create_dir_all(&home).unwrap();

    ensure_home(&home).unwrap();
    let original_files: Vec<_> = SCAFFOLD_DIRECTORIES
        .iter()
        .map(|name| {
            let readme = home.join(name).join("README.md");
            assert!(readme.is_file());
            let contents = format!("custom {name} contents").into_bytes();
            fs::write(&readme, &contents).unwrap();
            (readme, contents)
        })
        .collect();

    ensure_home(&home).unwrap();

    for (readme, contents) in original_files {
        assert_eq!(fs::read(&readme).unwrap(), contents);
    }

    fs::remove_dir_all(home).unwrap();
}

#[test]
fn rejects_a_home_path_that_names_a_regular_file() {
    let root = temporary_path("file");
    fs::create_dir_all(&root).unwrap();
    let home = root.join("home");
    fs::write(&home, b"not a directory").unwrap();

    let error = ensure_home(&home).unwrap_err();

    assert_eq!(error.code(), ErrorCode::PersistenceFailed);
    fs::remove_dir_all(root).unwrap();
}
