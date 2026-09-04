use std::fs;

#[test]
fn restored_lifecycle_adr_records_the_delivery_split_and_rollback_contract() {
    let adr = fs::read_to_string("../../docs/decisions/0027-pinned-model-artifact-lifecycle.md")
        .expect("ADR 0027 must exist");

    for required in [
        "- Status: accepted",
        "- Supersedes: ADR 0021",
        "model_artifact.rs",
        "name, version, byte size, and SHA-256 digest",
        "current`, `previous`, and `rejected",
        "resumable `.part` files",
        "NativeInstallLock",
        "checked_initial_url",
        "checked_redirect_url",
        "classifier ships in the desktop bundle",
        "extractor uses the restored descriptor",
    ] {
        assert!(adr.contains(required), "ADR 0027 must contain {required:?}");
    }
    assert!(!adr.contains("src-tauri/core/src/llama"));
}
