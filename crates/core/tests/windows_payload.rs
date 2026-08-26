use muniment_core::windows_payload::{
    resolve_windows_payload, PayloadFileKind, PayloadRootError, WindowsPayloadProbe,
};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct FakeProbe {
    kinds: HashMap<PathBuf, PayloadFileKind>,
    probed: RefCell<Vec<PathBuf>>,
}

impl FakeProbe {
    fn with_kind(mut self, path: PathBuf, kind: PayloadFileKind) -> Self {
        self.kinds.insert(path, kind);
        self
    }
}

impl WindowsPayloadProbe for FakeProbe {
    fn file_kind(&self, path: &Path) -> PayloadFileKind {
        self.probed.borrow_mut().push(path.to_owned());
        self.kinds
            .get(path)
            .copied()
            .unwrap_or(PayloadFileKind::Missing)
    }
}

fn payload(root: &Path) -> PathBuf {
    root.join("muniment").join("muniment-runtime.exe")
}

#[test]
fn machine_payload_takes_precedence() {
    let program_files = Path::new(r"C:\Program Files");
    let local_app_data = Path::new(r"C:\Users\Ada\AppData\Local");
    let machine_payload = payload(program_files);
    let user_payload = payload(local_app_data);
    let probe = FakeProbe::default()
        .with_kind(machine_payload.clone(), PayloadFileKind::RegularFile)
        .with_kind(user_payload, PayloadFileKind::RegularFile);

    assert_eq!(
        resolve_windows_payload(program_files, local_app_data, &probe),
        Ok(Some(machine_payload.clone()))
    );
    assert_eq!(*probe.probed.borrow(), [machine_payload]);
}

#[test]
fn user_payload_is_used_only_when_machine_payload_is_absent() {
    let program_files = Path::new(r"C:\Program Files");
    let local_app_data = Path::new(r"C:\Users\Ada\AppData\Local");
    let machine_payload = payload(program_files);
    let user_payload = payload(local_app_data);

    for machine_kind in [
        PayloadFileKind::Missing,
        PayloadFileKind::Directory,
        PayloadFileKind::SymbolicLink,
        PayloadFileKind::Other,
    ] {
        let probe = FakeProbe::default()
            .with_kind(machine_payload.clone(), machine_kind)
            .with_kind(user_payload.clone(), PayloadFileKind::RegularFile);
        assert_eq!(
            resolve_windows_payload(program_files, local_app_data, &probe),
            Ok(Some(user_payload.clone())),
            "machine: {machine_kind:?}"
        );
        assert_eq!(
            *probe.probed.borrow(),
            [machine_payload.clone(), user_payload.clone()]
        );
    }
}

#[test]
fn non_regular_payloads_are_absent() {
    let program_files = Path::new(r"C:\Program Files");
    let local_app_data = Path::new(r"C:\Users\Ada\AppData\Local");

    for machine_kind in [
        PayloadFileKind::Missing,
        PayloadFileKind::Directory,
        PayloadFileKind::SymbolicLink,
        PayloadFileKind::Other,
    ] {
        for user_kind in [
            PayloadFileKind::Missing,
            PayloadFileKind::Directory,
            PayloadFileKind::SymbolicLink,
            PayloadFileKind::Other,
        ] {
            let probe = FakeProbe::default()
                .with_kind(payload(program_files), machine_kind)
                .with_kind(payload(local_app_data), user_kind);
            assert_eq!(
                resolve_windows_payload(program_files, local_app_data, &probe),
                Ok(None),
                "machine: {machine_kind:?}, user: {user_kind:?}"
            );
        }
    }
}

#[test]
fn invalid_roots_are_rejected_before_any_probe() {
    let cases = [
        (
            Path::new("Program Files"),
            Path::new(r"C:\Users\Ada\AppData\Local"),
            PayloadRootError::RelativeRoot,
        ),
        (
            Path::new(r"C:\Program Files"),
            Path::new("AppData\\Local"),
            PayloadRootError::RelativeRoot,
        ),
        (
            Path::new(r"C:\Program Files\..\Other"),
            Path::new(r"C:\Users\Ada\AppData\Local"),
            PayloadRootError::ParentPathSegment,
        ),
        (
            Path::new(r"C:\Program Files"),
            Path::new(r"C:\Users\Ada\..\Other"),
            PayloadRootError::ParentPathSegment,
        ),
    ];

    for (program_files, local_app_data, error) in cases {
        let probe = FakeProbe::default().with_kind(
            payload(Path::new(r"C:\Program Files")),
            PayloadFileKind::RegularFile,
        );
        assert_eq!(
            resolve_windows_payload(program_files, local_app_data, &probe),
            Err(error)
        );
        assert!(probe.probed.borrow().is_empty());
    }
}
