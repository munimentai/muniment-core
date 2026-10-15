use muniment_runtime_core::{RuntimeAttachState, RuntimeHost};
mod common;

#[test]
fn opening_the_runtime_names_legacy_session_folders() {
    let temporary = common::TemporaryProfile::new("session-names", false);
    let profile = &temporary.profile;
    let home = temporary.root.join("muniment");
    muniment_core::home::confirm_home(profile, &home).unwrap();
    let legacy = home.join("sessions").join(uuid::Uuid::new_v4().to_string());
    std::fs::create_dir_all(&legacy).unwrap();
    std::fs::write(legacy.join("notes.md"), "kept").unwrap();

    let _state = RuntimeAttachState::open(RuntimeHost::default(), profile, profile).unwrap();

    assert!(!legacy.exists());
    let renamed: Vec<_> = std::fs::read_dir(home.join("sessions"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.join("notes.md").is_file())
        .collect();
    assert_eq!(renamed.len(), 1);
    assert!(renamed[0]
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("Thread-"));
}
