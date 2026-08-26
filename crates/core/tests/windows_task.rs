use muniment_core::windows_task::{
    build_task_definition, plan_task_registration, registration_verdict,
    render_task_definition_xml, task_uri, LogonType, MultipleInstancesPolicy, ObservedRegistration,
    RegistrationVerdict, RenderTaskDefinitionError, RunLevel, SidError, TaskDefinitionError,
    TaskRegistrationPlan, Trigger,
};
use std::path::PathBuf;
use std::time::Duration;

const SID: &str = "S-1-5-21-111-222-333-1001";
const MACHINE_ROOT: &str = r"C:\Program Files";
const USER_ROOT: &str = r"C:\Users\Alice\AppData\Local";
const PAYLOAD: &str = r"C:\Program Files\muniment\muniment-runtime.exe";
const USER_PAYLOAD: &str = r"C:\Users\Alice\AppData\Local\muniment\muniment-runtime.exe";

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
fn renders_the_machine_payload_task_document() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();

    assert_eq!(
        render_task_definition_xml(&definition),
        Ok(format!(
            r#"<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <URI>\Muniment\Runtime-{SID}</URI>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger>
      <UserId>{SID}</UserId>
    </LogonTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{SID}</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure>
      <Count>4</Count>
      <Interval>PT1M</Interval>
    </RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{PAYLOAD}</Command>
    </Exec>
  </Actions>
</Task>
"#
        ))
    );
}

#[test]
fn escapes_action_values_and_writes_optional_arguments() {
    let mut definition = build_task_definition(SID, PAYLOAD).unwrap();
    definition.action.path = PathBuf::from(r#"C:\A&B<"folder">\muniment-runtime.exe"#);
    definition.action.arguments = Some(r#"--value=&<">"#.to_owned());

    let machine_xml =
        render_task_definition_xml(&build_task_definition(SID, PAYLOAD).unwrap()).unwrap();
    let expected = machine_xml.replace(
        &format!("      <Command>{PAYLOAD}</Command>"),
        concat!(
            "      <Command>C:\\A&amp;B&lt;&quot;folder&quot;&gt;\\muniment-runtime.exe</Command>\n",
            "      <Arguments>--value=&amp;&lt;&quot;&gt;</Arguments>"
        ),
    );

    assert_eq!(render_task_definition_xml(&definition), Ok(expected));
}

#[test]
fn rejects_unsupported_principal_variants() {
    let mut definition = build_task_definition(SID, PAYLOAD).unwrap();
    definition.logon_type = LogonType::Other(99);
    assert_eq!(
        render_task_definition_xml(&definition),
        Err(RenderTaskDefinitionError::UnsupportedLogonType)
    );

    definition.logon_type = LogonType::InteractiveToken;
    definition.run_level = RunLevel::Other(99);
    assert_eq!(
        render_task_definition_xml(&definition),
        Err(RenderTaskDefinitionError::UnsupportedRunLevel)
    );
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

#[test]
fn plans_registration_for_absent_and_equal_tasks() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();
    assert_eq!(
        plan_task_registration(&definition, None, MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::Register
    );

    let observed = observed_registration(&definition.uri);
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::LeaveUnchanged
    );
}

#[test]
fn keeps_the_machine_payload_when_the_expected_payload_is_per_user() {
    let definition = build_task_definition(SID, USER_PAYLOAD).unwrap();
    let mut observed = observed_registration(&definition.uri);
    observed.logon_type = LogonType::Other(1);
    observed.run_level = RunLevel::HighestPrivilege;

    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::LeaveUnchanged
    );
}

#[test]
fn plans_updates_for_compatible_task_differences() {
    let definition = build_task_definition(SID, USER_PAYLOAD).unwrap();
    let mut observed = ObservedRegistration {
        uri: definition.uri.clone(),
        principal_sid: SID.to_owned(),
        logon_type: LogonType::Other(1),
        run_level: RunLevel::LeastPrivilege,
        action_path: PathBuf::from(USER_PAYLOAD),
        action_arguments: None,
    };
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::Update
    );

    observed.logon_type = LogonType::InteractiveToken;
    observed.run_level = RunLevel::HighestPrivilege;
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::Update
    );

    observed.run_level = RunLevel::LeastPrivilege;
    observed.action_path = PathBuf::from(r"C:\Users\Alice\AppData\Local\old\muniment-runtime.exe");
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::Update
    );
}

#[test]
fn refuses_tasks_that_are_not_safe_to_update() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();
    let mut observed = observed_registration(&definition.uri);

    observed.principal_sid = "S-1-5-21-111-222-333-1002".to_owned();
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::Refuse
    );

    observed = observed_registration(&definition.uri);
    observed.action_arguments = Some(String::new());
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::Refuse
    );

    for path in [
        r"C:\other\muniment-runtime.exe",
        r"C:\Program Files-old\muniment-runtime.exe",
        r"C:\Program Files\..\other\muniment-runtime.exe",
    ] {
        observed = observed_registration(&definition.uri);
        observed.action_path = PathBuf::from(path);
        assert_eq!(
            plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
            TaskRegistrationPlan::Refuse,
            "{path}"
        );
    }

    observed = observed_registration(r"\Muniment\Runtime-S-1-5-21-foreign");
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), MACHINE_ROOT, USER_ROOT),
        TaskRegistrationPlan::Refuse
    );

    observed = observed_registration(&definition.uri);
    observed.action_path = PathBuf::from(r"relative\muniment-runtime.exe");
    assert_eq!(
        plan_task_registration(&definition, Some(&observed), "relative", USER_ROOT),
        TaskRegistrationPlan::Refuse
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
