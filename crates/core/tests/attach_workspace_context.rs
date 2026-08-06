use std::path::{Path, PathBuf};

use muniment_core::attach::WorkspaceContextMap;

fn recorded_contexts() -> (WorkspaceContextMap, PathBuf) {
    let mut contexts = WorkspaceContextMap::default();
    let directory = PathBuf::from("/canonical/first");
    contexts.record(
        "client-a",
        "workspace-a",
        directory.clone(),
        Some("instructions".to_owned()),
    );
    (contexts, directory)
}

#[test]
fn unknown_identity_is_not_authorized() {
    let (contexts, directory) = recorded_contexts();
    assert_eq!(
        contexts.authorized_directory("unknown", "workspace-a", &directory),
        None
    );
}

#[test]
fn wrong_session_workspace_is_not_authorized() {
    let (contexts, directory) = recorded_contexts();
    assert_eq!(
        contexts.authorized_directory("client-a", "workspace-b", &directory),
        None
    );
}

#[test]
fn unrecorded_directory_is_not_authorized() {
    let (contexts, _) = recorded_contexts();
    assert_eq!(
        contexts.authorized_directory(
            "client-a",
            "workspace-a",
            Path::new("/canonical/unrecorded")
        ),
        None
    );
}

#[test]
fn recorded_directory_is_authorized() {
    let (contexts, directory) = recorded_contexts();
    assert_eq!(
        contexts.authorized_directory("client-a", "workspace-a", &directory),
        Some(directory)
    );
}

#[test]
fn second_identity_cannot_see_first_identity_directory() {
    let (contexts, directory) = recorded_contexts();
    assert_eq!(
        contexts.authorized_directory("client-b", "workspace-a", &directory),
        None
    );
}

#[test]
fn second_session_workspace_is_authorized_under_one_identity() {
    let (mut contexts, _) = recorded_contexts();
    let directory = PathBuf::from("/canonical/second");
    contexts.record("client-a", "workspace-b", directory.clone(), None);
    assert_eq!(
        contexts.authorized_directory("client-a", "workspace-b", &directory),
        Some(directory)
    );
}
