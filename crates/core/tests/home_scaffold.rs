use muniment_core::home::{configured_home, confirm_home, scaffold_home};
use std::{
    fs,
    path::PathBuf,
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

fn temporary_directory(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "muniment-home-{name}-{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn rejects_a_home_equal_to_or_ancestor_of_the_config_directory() {
    let root = temporary_directory("config-inside-home");
    let config = root.join("config");

    assert!(confirm_home(&config, &config).is_err());
    assert!(confirm_home(&config, &root).is_err());
    assert!(!config.join("home.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn concurrent_updates_leave_one_complete_valid_configuration() {
    let root = temporary_directory("concurrent");
    let config = root.join("config");
    let homes: Vec<_> = (0..8)
        .map(|index| root.join(format!("Home-{index}")))
        .collect();
    let handles: Vec<_> = homes
        .iter()
        .cloned()
        .map(|home| {
            let config = config.clone();
            thread::spawn(move || confirm_home(&config, &home))
        })
        .collect();
    for handle in handles {
        handle.join().unwrap().unwrap();
    }

    let configured = configured_home(&config).unwrap().unwrap();
    assert!(homes.contains(&configured));
    assert!(fs::read_dir(&config).unwrap().all(|entry| !entry
        .unwrap()
        .file_name()
        .to_string_lossy()
        .ends_with(".tmp")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn scaffolds_the_visible_home_layout_idempotently() {
    let root = temporary_directory("scaffold");
    let home = root.join("Muniment");

    scaffold_home(&home).unwrap();
    scaffold_home(&home).unwrap();

    for directory in ["memory", "agents", "projects", "sessions"] {
        assert!(home.join(directory).is_dir());
    }
    assert!(!home.join(".memory").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn persists_the_location_outside_home_and_round_trips_it() {
    let root = temporary_directory("config");
    let home = root.join("Documents").join("Muniment");
    let config = root.join("app-config");
    fs::create_dir(home.parent().unwrap()).unwrap();

    assert_eq!(configured_home(&config).unwrap(), None);
    confirm_home(&config, &home).unwrap();

    assert_eq!(configured_home(&config).unwrap(), Some(home.clone()));
    assert!(config.join("home.json").is_file());
    assert!(!home.join("home.json").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn a_failed_scaffold_does_not_persist_the_location() {
    let root = temporary_directory("failure");
    let home = root.join("Muniment");
    let config = root.join("app-config");
    fs::create_dir(&home).unwrap();
    fs::write(home.join("agents"), "not a directory").unwrap();

    assert!(confirm_home(&config, &home).is_err());
    assert_eq!(configured_home(&config).unwrap(), None);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_hidden_and_root_home_locations() {
    let root = temporary_directory("validation");
    let config = root.join("config");

    assert!(confirm_home(&config, &root.join(".muniment")).is_err());
    assert!(confirm_home(&config, PathBuf::from("/").as_path()).is_err());
    assert_eq!(configured_home(&config).unwrap(), None);
    fs::remove_dir_all(root).unwrap();
}
