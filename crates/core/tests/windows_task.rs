use muniment_core::windows_task::{
    build_task_definition, registration_verdict, task_uri, LogonType, MultipleInstancesPolicy,
    ObservedRegistration, RegistrationVerdict, RunLevel, SidError, TaskDefinitionError, Trigger,
};
use std::path::PathBuf;
use std::time::Duration;

const SID: &str = "S-1-5-21-111-222-333-1001";
const PAYLOAD: &str = r"C:\Program Files\muniment\muniment-runtime.exe";

#[test]
fn builds_the_stable_uri_only_for_canonical_sids() {
    assert_eq!(
        task_uri(SID),
        Ok(r"\Muniment\Runtime-S-1-5-21-111-222-333-1001".to_owned())
    );

    for sid in [
        "S-1-4294967295-1",
        "S-1-0x000100000000-1",
        "S-1-0xffffffffffff-4294967295",
    ] {
        assert!(task_uri(sid).is_ok(), "{sid}");
    }

    for sid in [
        "",
        "s-1-5-21-1",
        "S-2-5-21-1",
        "S-1-",
        "S-1-5",
        "S-1-5-",
        "S-1-5-1--2",
        "S-1-05-21-1",
        "S-1-5-021-1",
        "S-1-5-a",
        "S-1-4294967296-1",
        "S-1-0x0000ffffffff-1",
        "S-1-0x100000000-1",
        "S-1-0x1000000000000-1",
        "S-1-281474976710655-1",
        "S-1-281474976710656-1",
        "S-1-5-4294967296",
        "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
    ] {
        assert_eq!(task_uri(sid), Err(SidError::NotCanonical), "{sid}");
    }
}

#[test]
fn rejects_unsafe_or_wrong_payload_paths() {
    assert_eq!(
        build_task_definition(SID, r"muniment\muniment-runtime.exe"),
        Err(TaskDefinitionError::RelativePayloadPath)
    );
    assert_eq!(
        build_task_definition(SID, r"C:\muniment\..\other\muniment-runtime.exe"),
        Err(TaskDefinitionError::ParentPathSegment)
    );
    assert_eq!(
        build_task_definition(SID, r"C:\muniment\desktop.exe"),
        Err(TaskDefinitionError::WrongPayloadFileName)
    );
    assert_eq!(
        build_task_definition(SID, r"\\server\muniment-runtime.exe"),
        Err(TaskDefinitionError::RelativePayloadPath)
    );
    assert!(build_task_definition(SID, r"\\server\share\muniment-runtime.exe").is_ok());
}

#[test]
fn builds_the_required_principal_action_trigger_and_settings() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();

    assert_eq!(definition.principal_sid, SID);
    assert_eq!(definition.logon_type, LogonType::InteractiveToken);
    assert_eq!(definition.run_level, RunLevel::LeastPrivilege);
    assert_eq!(definition.triggers, [Trigger::Logon]);
    assert_eq!(definition.action.path, PathBuf::from(PAYLOAD));
    assert_eq!(definition.action.arguments, None);
    assert!(definition.settings.allow_start_on_demand);
    assert_eq!(
        definition.settings.multiple_instances,
        MultipleInstancesPolicy::IgnoreNew
    );
    assert_eq!(definition.settings.restart_count, 4);
    assert_eq!(
        definition.settings.restart_interval,
        Duration::from_secs(60)
    );
    assert!(definition.settings.start_when_available);
    assert_eq!(definition.settings.execution_time_limit, None);
    assert!(!definition.settings.run_only_if_network_available);
    assert!(!definition.settings.disallow_start_if_on_batteries);
    assert!(!definition.settings.stop_if_going_on_batteries);
}

#[test]
fn classifies_equal_different_and_foreign_registrations() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();
    let mut observed = observed_registration(&definition.uri);
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Equal
    );

    observed.action_arguments = Some("--unexpected".to_owned());
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Foreign
    );
    observed = observed_registration(&definition.uri);
    observed.logon_type = LogonType::Other(1);
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Different
    );
    observed = observed_registration(&definition.uri);
    observed.run_level = RunLevel::HighestPrivilege;
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Different
    );

    observed = observed_registration(&definition.uri);
    observed.action_path = PathBuf::from(r"C:\other\muniment-runtime.exe");
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Foreign
    );

    observed = observed_registration(&definition.uri);
    observed.principal_sid = "S-1-5-21-111-222-333-1002".to_owned();
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Foreign
    );
    observed = observed_registration(r"\Muniment\Runtime-S-1-5-21-foreign");
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Foreign
    );
}

#[test]
fn verdict_ignores_settings_outside_the_registration_identity() {
    let mut definition = build_task_definition(SID, PAYLOAD).unwrap();
    let observed = observed_registration(&definition.uri);
    definition.settings.restart_count = 0;
    definition.settings.allow_start_on_demand = false;
    definition.triggers.clear();

    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Equal
    );
}

fn observed_registration(uri: &str) -> ObservedRegistration {
    ObservedRegistration {
        uri: uri.to_owned(),
        principal_sid: SID.to_owned(),
        logon_type: LogonType::InteractiveToken,
        run_level: RunLevel::LeastPrivilege,
        action_path: PathBuf::from(PAYLOAD),
        action_arguments: None,
    }
}
