use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use muniment_core::attach::{ErrorCode, WorkspaceContextMap, WorkspaceOnboardRequest};
use muniment_runtime_core::onboard_workspace;

fn temporary_path(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "muniment-runtime-workspace-{name}-{}",
        std::process::id()
    ))
}

#[test]
fn returns_nearest_instructions_and_records_both_canonical_directories() {
    let root = temporary_path("success");
    let opened = root.join("repo").join("nested");
    let memory = root.join("workspace-memory");
    fs::create_dir_all(&opened).unwrap();
    fs::write(root.join("repo").join("AGENTS.md"), "nearest instructions").unwrap();
    fs::write(root.join("AGENTS.md"), "root instructions").unwrap();
    let contexts = Arc::new(Mutex::new(WorkspaceContextMap::default()));

    let onboarded = onboard_workspace(
        Arc::clone(&contexts),
        "client-a",
        "workspace-a",
        WorkspaceOnboardRequest {
            opened_directory: opened.to_string_lossy().into_owned(),
            memory_location: memory.to_string_lossy().into_owned(),
        },
    )
    .unwrap();

    assert_eq!(
        onboarded.instructions.as_deref(),
        Some("nearest instructions")
    );
    assert_eq!(onboarded.opened_directory, opened.to_string_lossy());
    assert_eq!(onboarded.memory_location, memory.to_string_lossy());
    assert!(memory.join("memory").join("README.md").is_file());
    let contexts = contexts.lock().unwrap();
    assert_eq!(
        contexts.authorized_directory("client-a", "workspace-a", &opened.canonicalize().unwrap()),
        Some(opened.canonicalize().unwrap())
    );
    assert_eq!(
        contexts.authorized_directory("client-a", "workspace-a", &memory.canonicalize().unwrap()),
        Some(memory.canonicalize().unwrap())
    );
    drop(contexts);
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn rejects_relative_paths_without_recording_a_directory() {
    let root = temporary_path("relative");
    let absolute_opened = root.join("opened");
    let absolute_memory = root.join("memory");
    fs::create_dir_all(&absolute_opened).unwrap();
    fs::create_dir_all(&absolute_memory).unwrap();
    for (opened, memory, absolute_candidate) in [
        (
            "relative".into(),
            absolute_memory.to_string_lossy().into_owned(),
            &absolute_memory,
        ),
        (
            absolute_opened.to_string_lossy().into_owned(),
            "relative".into(),
            &absolute_opened,
        ),
    ] {
        let contexts = Arc::new(Mutex::new(WorkspaceContextMap::default()));

        let error = onboard_workspace(
            Arc::clone(&contexts),
            "client-a",
            "workspace-a",
            WorkspaceOnboardRequest {
                opened_directory: opened,
                memory_location: memory,
            },
        )
        .unwrap_err();

        assert_eq!(error.code(), ErrorCode::InvalidRequest);
        let contexts = contexts.lock().unwrap();
        assert_eq!(
            contexts.authorized_directory(
                "client-a",
                "workspace-a",
                &absolute_candidate.canonicalize().unwrap()
            ),
            None
        );
    }
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn maps_a_filesystem_failure_to_persistence_failed() {
    let root = temporary_path("failure");
    let opened = root.join("opened");
    let memory = root.join("memory-file");
    fs::create_dir_all(&opened).unwrap();
    fs::write(&memory, "not a directory").unwrap();

    let error = onboard_workspace(
        Arc::new(Mutex::new(WorkspaceContextMap::default())),
        "client-a",
        "workspace-a",
        WorkspaceOnboardRequest {
            opened_directory: opened.to_string_lossy().into_owned(),
            memory_location: memory.to_string_lossy().into_owned(),
        },
    )
    .unwrap_err();

    assert_eq!(error.code(), ErrorCode::PersistenceFailed);
    fs::remove_dir_all(root).unwrap();
}
