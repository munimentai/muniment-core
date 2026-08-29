use muniment_core::windows_payload::{
    installed_desktop_executable_from, plan_scope_task_removals, plan_windows_payload_removals,
    resolve_windows_payload, resolve_windows_payload_scopes, PayloadFileKind, PayloadRootError,
    WindowsPayloadProbe, WindowsPayloadScopes,
};
use muniment_core::windows_task::{
    LogonType, ObservedRegistration, RemovalScope, RunLevel, SidError, TaskRemovalPlan,
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
fn maps_installed_windows_payloads_to_the_desktop_executable() {
    for (runtime_payload, desktop_executable) in [
        (
            r"C:\Program Files\muniment\muniment-runtime.exe",
            r"C:\Program Files\muniment\muniment.exe",
        ),
        (
            r"C:\Users\Ada\AppData\Local\muniment\muniment-runtime.exe",
            r"C:\Users\Ada\AppData\Local\muniment\muniment.exe",
        ),
    ] {
        assert_eq!(
            installed_desktop_executable_from(Path::new(runtime_payload)),
            Some(PathBuf::from(desktop_executable))
        );
    }
}

#[test]
fn rejects_payloads_outside_the_installed_windows_layout() {
    for runtime_payload in [
        r"muniment\muniment-runtime.exe",
        r"C:\Program Files\muniment\another-runtime.exe",
        r"C:\Program Files\another\muniment-runtime.exe",
    ] {
        assert_eq!(
            installed_desktop_executable_from(Path::new(runtime_payload)),
            None,
            "payload: {runtime_payload}"
        );
    }
}

const SID: &str = "S-1-5-21-111-222-333-1001";
const OTHER_SID: &str = "S-1-5-21-111-222-333-1002";

fn registration(sid: &str, action_path: impl Into<PathBuf>) -> ObservedRegistration {
    ObservedRegistration {
        uri: format!(r"\Muniment\Runtime-{sid}"),
        principal_sid: sid.to_owned(),
        logon_type: LogonType::InteractiveToken,
        run_level: RunLevel::LeastPrivilege,
        action_path: action_path.into(),
        action_arguments: None,
    }
}

#[test]
fn resolves_both_payload_scopes_independently() {
    let program_files = Path::new(r"C:\Program Files");
    let local_app_data = Path::new(r"C:\Users\Ada\AppData\Local");
    let machine_payload = payload(program_files);
    let user_payload = payload(local_app_data);

    for (machine_kind, user_kind, expected_machine, expected_user) in [
        (
            PayloadFileKind::RegularFile,
            PayloadFileKind::RegularFile,
            Some(machine_payload.clone()),
            Some(user_payload.clone()),
        ),
        (
            PayloadFileKind::RegularFile,
            PayloadFileKind::Missing,
            Some(machine_payload.clone()),
            None,
        ),
        (
            PayloadFileKind::Missing,
            PayloadFileKind::RegularFile,
            None,
            Some(user_payload.clone()),
        ),
        (
            PayloadFileKind::Missing,
            PayloadFileKind::Missing,
            None,
            None,
        ),
        (
            PayloadFileKind::SymbolicLink,
            PayloadFileKind::SymbolicLink,
            None,
            None,
        ),
    ] {
        let probe = FakeProbe::default()
            .with_kind(machine_payload.clone(), machine_kind)
            .with_kind(user_payload.clone(), user_kind);
        assert_eq!(
            resolve_windows_payload_scopes(program_files, local_app_data, &probe),
            Ok(WindowsPayloadScopes {
                machine_payload_path: expected_machine,
                per_user_payload_path: expected_user,
            }),
            "machine: {machine_kind:?}, user: {user_kind:?}"
        );
        assert_eq!(
            *probe.probed.borrow(),
            [machine_payload.clone(), user_payload.clone()]
        );
    }
}

#[test]
fn builds_removal_scopes_from_resolved_payloads() {
    let machine_payload = PathBuf::from(r"C:\Program Files\muniment\muniment-runtime.exe");
    let user_payload = PathBuf::from(r"C:\Users\Ada\AppData\Local\muniment\muniment-runtime.exe");
    let scopes = WindowsPayloadScopes {
        machine_payload_path: Some(machine_payload.clone()),
        per_user_payload_path: Some(user_payload.clone()),
    };

    assert_eq!(
        scopes.per_user_removal_scope(SID),
        Ok(Some(RemovalScope::PerUser {
            user_sid: SID.to_owned(),
            payload_path: user_payload.clone(),
            machine_payload_path: Some(machine_payload.clone()),
        }))
    );
    assert_eq!(
        scopes.machine_removal_scope(),
        Some(RemovalScope::Machine {
            payload_path: machine_payload,
            per_user_payload_path: Some(user_payload),
        })
    );
    assert_eq!(
        scopes.per_user_removal_scope("s-1-5-21-111-222-333-1001"),
        Err(SidError::NotCanonical)
    );
}

#[test]
fn removal_scope_is_absent_when_its_payload_is_absent() {
    let scopes = WindowsPayloadScopes {
        machine_payload_path: None,
        per_user_payload_path: None,
    };

    assert_eq!(scopes.per_user_removal_scope(SID), Ok(None));
    assert_eq!(scopes.machine_removal_scope(), None);
}

#[test]
fn per_user_removal_repoints_its_registration_to_the_machine_payload() {
    let machine_payload = PathBuf::from(r"C:\Program Files\muniment\muniment-runtime.exe");
    let user_payload = PathBuf::from(r"C:\Users\Ada\AppData\Local\muniment\muniment-runtime.exe");
    let registrations = [registration(SID, &user_payload)];
    let scope = RemovalScope::PerUser {
        user_sid: SID.to_owned(),
        payload_path: user_payload,
        machine_payload_path: Some(machine_payload.clone()),
    };

    let removal = plan_scope_task_removals(scope.clone(), &registrations);

    assert_eq!(removal.scope, scope);
    assert_eq!(removal.tasks.len(), 1);
    assert_eq!(removal.tasks[0].registration, registrations[0]);
    assert_eq!(
        removal.tasks[0].plan,
        TaskRemovalPlan::RepointTo(machine_payload)
    );
}

#[test]
fn machine_removal_stops_and_deletes_its_registration_without_a_user_payload() {
    let machine_payload = PathBuf::from(r"C:\Program Files\muniment\muniment-runtime.exe");
    let scopes = WindowsPayloadScopes {
        machine_payload_path: Some(machine_payload.clone()),
        per_user_payload_path: None,
    };
    let registrations = [registration(OTHER_SID, machine_payload)];

    let removals = plan_windows_payload_removals(&scopes, SID, &registrations).unwrap();

    assert_eq!(removals.len(), 1);
    assert!(matches!(removals[0].scope, RemovalScope::Machine { .. }));
    assert_eq!(removals[0].tasks[0].plan, TaskRemovalPlan::StopAndDelete);
}

#[test]
fn removal_plans_leave_foreign_registrations_unchanged() {
    let machine_payload = PathBuf::from(r"C:\Program Files\muniment\muniment-runtime.exe");
    let user_payload = PathBuf::from(r"C:\Users\Ada\AppData\Local\muniment\muniment-runtime.exe");
    let scopes = WindowsPayloadScopes {
        machine_payload_path: Some(machine_payload),
        per_user_payload_path: Some(user_payload),
    };
    let registrations = [registration(
        SID,
        r"C:\Foreign\muniment\muniment-runtime.exe",
    )];

    let removals = plan_windows_payload_removals(&scopes, SID, &registrations).unwrap();

    assert_eq!(removals.len(), 2);
    assert!(removals.iter().all(|removal| removal.tasks
        == [muniment_core::windows_payload::PlannedTaskRemoval {
            registration: registrations[0].clone(),
            plan: TaskRemovalPlan::LeaveUnchanged,
        }]));
}

#[test]
fn absent_payloads_produce_no_uninstaller_entries() {
    let scopes = WindowsPayloadScopes {
        machine_payload_path: None,
        per_user_payload_path: None,
    };
    let registrations = [registration(
        SID,
        r"C:\Foreign\muniment\muniment-runtime.exe",
    )];

    assert_eq!(
        plan_windows_payload_removals(&scopes, SID, &registrations),
        Ok(Vec::new())
    );
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
        assert_eq!(
            resolve_windows_payload_scopes(program_files, local_app_data, &probe),
            Err(error)
        );
        assert!(probe.probed.borrow().is_empty());
    }
}
