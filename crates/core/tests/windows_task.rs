use muniment_core::windows_task::{
    build_task_definition, parse_observed_registration, plan_task_registration, plan_task_removal,
    registration_verdict, render_task_definition_xml, sid_from_task_uri, task_uri, LogonType,
    MultipleInstancesPolicy, ObservedRegistration, ParseObservedRegistrationError,
    RegistrationVerdict, RemovalScope, RenderTaskDefinitionError, RunLevel, SidError,
    TaskDefinitionError, TaskRegistrationPlan, TaskRemovalPlan, Trigger,
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
fn reads_canonical_sids_only_from_stable_task_uris() {
    assert_eq!(
        sid_from_task_uri(r"\Muniment\Runtime-S-1-5-21-111-222-333-1001"),
        Some(SID)
    );

    for uri in [
        "",
        SID,
        r"Muniment\Runtime-S-1-5-21-111-222-333-1001",
        r"\muniment\Runtime-S-1-5-21-111-222-333-1001",
        r"\Muniment\Other-S-1-5-21-111-222-333-1001",
        r"\Muniment\Runtime-s-1-5-21-111-222-333-1001",
        r"\Muniment\Runtime-S-1-05-21-111-222-333-1001",
        r"\Muniment\Runtime-S-1-5-21-111-222-333-1001\extra",
    ] {
        assert_eq!(sid_from_task_uri(uri), None, "{uri}");
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
fn parses_a_rendered_definition_as_an_equal_registration() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();
    let xml = render_task_definition_xml(&definition).unwrap();
    let observed = parse_observed_registration(&definition.uri, &xml).unwrap();

    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Equal
    );
}

#[test]
fn defaults_an_omitted_run_level_to_least_privilege() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();
    let xml = render_task_definition_xml(&definition)
        .unwrap()
        .replace("      <RunLevel>LeastPrivilege</RunLevel>\n", "");
    assert!(!xml.contains("RunLevel"));

    let observed = parse_observed_registration(&definition.uri, &xml).unwrap();
    assert_eq!(observed.run_level, RunLevel::LeastPrivilege);
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Equal
    );
}

#[test]
fn defaults_an_omitted_logon_type_to_service_account() {
    let definition = build_task_definition(SID, PAYLOAD).unwrap();
    let xml = render_task_definition_xml(&definition)
        .unwrap()
        .replace("      <LogonType>InteractiveToken</LogonType>\n", "");
    assert!(!xml.contains("LogonType"));

    let observed = parse_observed_registration(&definition.uri, &xml).unwrap();
    assert_eq!(observed.logon_type, LogonType::Other(5));
    assert_eq!(
        registration_verdict(&definition, &observed),
        RegistrationVerdict::Different
    );
}

#[test]
fn parses_live_task_extras_entities_and_optional_arguments() {
    let uri = task_uri(SID).unwrap();
    let xml = format!(
        r#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>A &amp; B</Author><URI>{uri}</URI><Date>2025-01-01</Date></RegistrationInfo>
  <Principals><Principal id="Author"><UserId>{SID}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings><IdleSettings><StopOnIdleEnd>true</StopOnIdleEnd></IdleSettings></Settings>
  <Actions Context="Author"><Exec><Command>C:\A&amp;B&lt;C&gt;&quot;D&quot;&apos;E\muniment-runtime.exe</Command><Arguments>--name=&quot;A&amp;B&apos;s&quot;</Arguments></Exec></Actions>
</Task>"#
    );

    let observed = parse_observed_registration(&uri, &xml).unwrap();
    assert_eq!(observed.uri, uri);
    assert_eq!(observed.principal_sid, SID);
    assert_eq!(observed.logon_type, LogonType::InteractiveToken);
    assert_eq!(observed.run_level, RunLevel::HighestPrivilege);
    assert_eq!(
        observed.action_path,
        PathBuf::from("C:\\A&B<C>\"D\"'E\\muniment-runtime.exe")
    );
    assert_eq!(
        observed.action_arguments.as_deref(),
        Some("--name=\"A&B's\"")
    );
}

#[test]
fn maps_all_documented_principal_names() {
    let uri = task_uri(SID).unwrap();
    for (name, expected) in [
        ("None", LogonType::Other(0)),
        ("Password", LogonType::Other(1)),
        ("S4U", LogonType::Other(2)),
        ("InteractiveToken", LogonType::InteractiveToken),
        ("Group", LogonType::Other(4)),
        ("ServiceAccount", LogonType::Other(5)),
        ("InteractiveTokenOrPassword", LogonType::Other(6)),
    ] {
        let xml = observed_xml(&uri, name, "LeastPrivilege", false);
        assert_eq!(
            parse_observed_registration(&uri, &xml).unwrap().logon_type,
            expected,
            "{name}"
        );
    }

    let xml = observed_xml(&uri, "InteractiveToken", "HighestAvailable", false);
    assert_eq!(
        parse_observed_registration(&uri, &xml).unwrap().run_level,
        RunLevel::HighestPrivilege
    );
}

#[test]
fn rejects_invalid_or_incomplete_task_documents() {
    use ParseObservedRegistrationError as Error;

    let uri = task_uri(SID).unwrap();
    let valid = observed_xml(&uri, "InteractiveToken", "LeastPrivilege", false);
    assert_eq!(
        parse_observed_registration(&uri, "<NotTask />"),
        Err(Error::MissingTaskRoot)
    );
    assert_eq!(
        parse_observed_registration(&uri, "not xml"),
        Err(Error::MissingTaskRoot)
    );
    assert_eq!(
        parse_observed_registration("different", &valid),
        Err(Error::UriMismatch)
    );

    let without_user = valid.replace(&format!("<UserId>{SID}</UserId>"), "");
    assert_eq!(
        parse_observed_registration(&uri, &without_user),
        Err(Error::MissingElement("Principals/Principal/UserId"))
    );
    let without_command = valid.replace(&format!("<Command>{PAYLOAD}</Command>"), "");
    assert_eq!(
        parse_observed_registration(&uri, &without_command),
        Err(Error::MissingElement("Actions/Exec/Command"))
    );

    let two_exec_actions = observed_xml(&uri, "InteractiveToken", "LeastPrivilege", true);
    assert_eq!(
        parse_observed_registration(&uri, &two_exec_actions),
        Err(Error::MultipleExecActions)
    );
    let unknown_logon = observed_xml(&uri, "FutureLogon", "LeastPrivilege", false);
    assert_eq!(
        parse_observed_registration(&uri, &unknown_logon),
        Err(Error::UnrecognizedLogonType)
    );
    let unknown_level = observed_xml(&uri, "InteractiveToken", "FutureLevel", false);
    assert_eq!(
        parse_observed_registration(&uri, &unknown_level),
        Err(Error::UnrecognizedRunLevel)
    );
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

#[test]
fn plans_per_user_task_removal() {
    let mut observed = observed_registration(&task_uri(SID).unwrap());
    observed.action_path = PathBuf::from(USER_PAYLOAD);
    let scope = RemovalScope::PerUser {
        user_sid: SID.to_owned(),
        payload_path: PathBuf::from(USER_PAYLOAD),
        machine_payload_path: Some(PathBuf::from(PAYLOAD)),
    };
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::RepointTo(PathBuf::from(PAYLOAD))
    );

    let scope = RemovalScope::PerUser {
        user_sid: SID.to_owned(),
        payload_path: PathBuf::from(USER_PAYLOAD),
        machine_payload_path: None,
    };
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::StopAndDelete
    );
}

#[test]
fn leaves_another_users_task_unchanged_during_per_user_removal() {
    const OTHER_SID: &str = "S-1-5-21-111-222-333-1002";

    let mut observed = observed_registration(&task_uri(OTHER_SID).unwrap());
    observed.principal_sid = OTHER_SID.to_owned();
    observed.action_path = PathBuf::from(USER_PAYLOAD);

    for machine_payload_path in [Some(PathBuf::from(PAYLOAD)), None] {
        let scope = RemovalScope::PerUser {
            user_sid: SID.to_owned(),
            payload_path: PathBuf::from(USER_PAYLOAD),
            machine_payload_path,
        };
        assert_eq!(
            plan_task_removal(&scope, &observed),
            TaskRemovalPlan::LeaveUnchanged
        );
    }
}

#[test]
fn plans_machine_task_removal() {
    let observed = observed_registration(&task_uri(SID).unwrap());
    let scope = RemovalScope::Machine {
        payload_path: PathBuf::from(PAYLOAD),
        per_user_payload_path: Some(PathBuf::from(USER_PAYLOAD)),
    };
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::RepointTo(PathBuf::from(USER_PAYLOAD))
    );

    let scope = RemovalScope::Machine {
        payload_path: PathBuf::from(PAYLOAD),
        per_user_payload_path: None,
    };
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::StopAndDelete
    );
}

#[test]
fn leaves_tasks_unchanged_when_removal_ownership_does_not_match() {
    let scope = RemovalScope::Machine {
        payload_path: PathBuf::from(PAYLOAD),
        per_user_payload_path: Some(PathBuf::from(USER_PAYLOAD)),
    };
    let uri = task_uri(SID).unwrap();
    let mut observed = observed_registration(&uri);

    observed.uri = r"\Muniment\Runtime-S-1-5-21-111-222-333-1002".to_owned();
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::LeaveUnchanged
    );

    observed = observed_registration(r"\Muniment\Runtime-S-1-5-21-foreign");
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::LeaveUnchanged
    );

    observed = observed_registration(&uri);
    observed.action_arguments = Some(String::new());
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::LeaveUnchanged
    );

    observed = observed_registration(&uri);
    observed.action_path = PathBuf::from(USER_PAYLOAD);
    assert_eq!(
        plan_task_removal(&scope, &observed),
        TaskRemovalPlan::LeaveUnchanged
    );
}

fn observed_xml(uri: &str, logon_type: &str, run_level: &str, second_exec: bool) -> String {
    let second_exec = if second_exec {
        format!("<Exec><Command>{PAYLOAD}</Command></Exec>")
    } else {
        String::new()
    };
    format!(
        "<Task><RegistrationInfo><URI>{uri}</URI></RegistrationInfo>\
         <Principals><Principal><UserId>{SID}</UserId><LogonType>{logon_type}</LogonType>\
         <RunLevel>{run_level}</RunLevel></Principal></Principals>\
         <Actions><Exec><Command>{PAYLOAD}</Command></Exec>{second_exec}</Actions></Task>"
    )
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
