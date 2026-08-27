//! Platform-independent values for the Windows runtime Scheduled Task.

use quick_xml::events::Event;
use quick_xml::Reader;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

const RUNTIME_FILE_NAME: &str = "muniment-runtime.exe";
const MAX_SID_AUTHORITY: u64 = 0x0000_ffff_ffff_ffff;
const MAX_SID_SUB_AUTHORITIES: usize = 15;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogonType {
    InteractiveToken,
    Other(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RunLevel {
    LeastPrivilege,
    HighestPrivilege,
    Other(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Trigger {
    Logon,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MultipleInstancesPolicy {
    IgnoreNew,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskAction {
    pub path: PathBuf,
    pub arguments: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskSettings {
    pub allow_start_on_demand: bool,
    pub multiple_instances: MultipleInstancesPolicy,
    pub restart_count: u8,
    pub restart_interval: Duration,
    pub start_when_available: bool,
    pub execution_time_limit: Option<Duration>,
    pub run_only_if_network_available: bool,
    pub disallow_start_if_on_batteries: bool,
    pub stop_if_going_on_batteries: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TaskDefinition {
    pub uri: String,
    pub principal_sid: String,
    pub logon_type: LogonType,
    pub run_level: RunLevel,
    pub triggers: Vec<Trigger>,
    pub action: TaskAction,
    pub settings: TaskSettings,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SidError {
    NotCanonical,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskDefinitionError {
    InvalidSid,
    RelativePayloadPath,
    ParentPathSegment,
    WrongPayloadFileName,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderTaskDefinitionError {
    UnsupportedLogonType,
    UnsupportedRunLevel,
    NonUnicodeActionPath,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservedRegistration {
    pub uri: String,
    pub principal_sid: String,
    pub logon_type: LogonType,
    pub run_level: RunLevel,
    pub action_path: PathBuf,
    pub action_arguments: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseObservedRegistrationError {
    MalformedXml,
    MissingTaskRoot,
    MissingElement(&'static str),
    DuplicateElement(&'static str),
    MultipleExecActions,
    UriMismatch,
    UnrecognizedLogonType,
    UnrecognizedRunLevel,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationVerdict {
    Equal,
    Different,
    Foreign,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TaskRegistrationPlan {
    Register,
    Update,
    LeaveUnchanged,
    Refuse,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RemovalScope {
    PerUser {
        user_sid: String,
        payload_path: PathBuf,
        machine_payload_path: Option<PathBuf>,
    },
    Machine {
        payload_path: PathBuf,
        per_user_payload_path: Option<PathBuf>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TaskRemovalPlan {
    RepointTo(PathBuf),
    StopAndDelete,
    LeaveUnchanged,
}

/// Returns the stable Task Scheduler URI for a canonical SID string.
pub fn task_uri(sid: &str) -> Result<String, SidError> {
    if !is_canonical_sid(sid) {
        return Err(SidError::NotCanonical);
    }
    Ok(format!(r"\Muniment\Runtime-{sid}"))
}

/// Returns the canonical SID suffix from a stable runtime task URI.
pub fn sid_from_task_uri(uri: &str) -> Option<&str> {
    let sid = uri.strip_prefix(r"\Muniment\Runtime-")?;
    is_canonical_sid(sid).then_some(sid)
}

impl TaskDefinition {
    pub fn new(sid: &str, payload_path: impl AsRef<Path>) -> Result<Self, TaskDefinitionError> {
        let uri = task_uri(sid).map_err(|_| TaskDefinitionError::InvalidSid)?;
        let payload_path = payload_path.as_ref();
        validate_payload_path(payload_path)?;

        Ok(Self {
            uri,
            principal_sid: sid.to_owned(),
            logon_type: LogonType::InteractiveToken,
            run_level: RunLevel::LeastPrivilege,
            triggers: vec![Trigger::Logon],
            action: TaskAction {
                path: payload_path.to_path_buf(),
                arguments: None,
            },
            settings: TaskSettings {
                allow_start_on_demand: true,
                multiple_instances: MultipleInstancesPolicy::IgnoreNew,
                restart_count: 4,
                restart_interval: Duration::from_secs(60),
                start_when_available: true,
                execution_time_limit: None,
                run_only_if_network_available: false,
                disallow_start_if_on_batteries: false,
                stop_if_going_on_batteries: false,
            },
        })
    }
}

pub fn build_task_definition(
    sid: &str,
    payload_path: impl AsRef<Path>,
) -> Result<TaskDefinition, TaskDefinitionError> {
    TaskDefinition::new(sid, payload_path)
}

/// Renders a Task Scheduler XML document from a platform-independent definition.
pub fn render_task_definition_xml(
    definition: &TaskDefinition,
) -> Result<String, RenderTaskDefinitionError> {
    let logon_type = match definition.logon_type {
        LogonType::InteractiveToken => "InteractiveToken",
        LogonType::Other(_) => return Err(RenderTaskDefinitionError::UnsupportedLogonType),
    };
    let run_level = match definition.run_level {
        RunLevel::LeastPrivilege => "LeastPrivilege",
        RunLevel::HighestPrivilege => "HighestAvailable",
        RunLevel::Other(_) => return Err(RenderTaskDefinitionError::UnsupportedRunLevel),
    };
    let action_path = definition
        .action
        .path
        .to_str()
        .ok_or(RenderTaskDefinitionError::NonUnicodeActionPath)?;

    let mut xml = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-16\"?>\n\
<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">\n",
    );
    xml.push_str("  <RegistrationInfo>\n");
    write_element(&mut xml, 4, "URI", &definition.uri);
    xml.push_str("  </RegistrationInfo>\n  <Triggers>\n");
    for trigger in &definition.triggers {
        match trigger {
            Trigger::Logon => {
                xml.push_str("    <LogonTrigger>\n");
                write_element(&mut xml, 6, "UserId", &definition.principal_sid);
                xml.push_str("    </LogonTrigger>\n");
            }
        }
    }
    xml.push_str("  </Triggers>\n  <Principals>\n    <Principal id=\"Author\">\n");
    write_element(&mut xml, 6, "UserId", &definition.principal_sid);
    write_element(&mut xml, 6, "LogonType", logon_type);
    write_element(&mut xml, 6, "RunLevel", run_level);
    xml.push_str("    </Principal>\n  </Principals>\n  <Settings>\n");
    write_bool_element(
        &mut xml,
        "AllowStartOnDemand",
        definition.settings.allow_start_on_demand,
    );
    write_element(
        &mut xml,
        4,
        "MultipleInstancesPolicy",
        match definition.settings.multiple_instances {
            MultipleInstancesPolicy::IgnoreNew => "IgnoreNew",
        },
    );
    write_bool_element(
        &mut xml,
        "StartWhenAvailable",
        definition.settings.start_when_available,
    );
    write_bool_element(
        &mut xml,
        "DisallowStartIfOnBatteries",
        definition.settings.disallow_start_if_on_batteries,
    );
    write_bool_element(
        &mut xml,
        "StopIfGoingOnBatteries",
        definition.settings.stop_if_going_on_batteries,
    );
    write_bool_element(
        &mut xml,
        "RunOnlyIfNetworkAvailable",
        definition.settings.run_only_if_network_available,
    );
    let execution_time_limit = definition
        .settings
        .execution_time_limit
        .map(format_duration)
        .unwrap_or_else(|| "PT0S".to_owned());
    write_element(&mut xml, 4, "ExecutionTimeLimit", &execution_time_limit);
    xml.push_str("    <RestartOnFailure>\n");
    write_element(
        &mut xml,
        6,
        "Count",
        &definition.settings.restart_count.to_string(),
    );
    write_element(
        &mut xml,
        6,
        "Interval",
        &format_duration(definition.settings.restart_interval),
    );
    xml.push_str(
        "    </RestartOnFailure>\n  </Settings>\n  <Actions Context=\"Author\">\n    <Exec>\n",
    );
    write_element(&mut xml, 6, "Command", action_path);
    if let Some(arguments) = &definition.action.arguments {
        write_element(&mut xml, 6, "Arguments", arguments);
    }
    xml.push_str("    </Exec>\n  </Actions>\n</Task>\n");
    Ok(xml)
}

fn write_bool_element(xml: &mut String, name: &str, value: bool) {
    write_element(xml, 4, name, if value { "true" } else { "false" });
}

fn write_element(xml: &mut String, indent: usize, name: &str, value: &str) {
    let escaped = escape_xml(value);
    writeln!(xml, "{space:indent$}<{name}>{escaped}</{name}>", space = "")
        .expect("writing to a String cannot fail");
}

fn escape_xml(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            _ => escaped.push(character),
        }
    }
    escaped
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ObservedField {
    Uri,
    UserId,
    LogonType,
    RunLevel,
    Command,
    Arguments,
}

impl ObservedField {
    fn name(self) -> &'static str {
        match self {
            Self::Uri => "RegistrationInfo/URI",
            Self::UserId => "Principals/Principal/UserId",
            Self::LogonType => "Principals/Principal/LogonType",
            Self::RunLevel => "Principals/Principal/RunLevel",
            Self::Command => "Actions/Exec/Command",
            Self::Arguments => "Actions/Exec/Arguments",
        }
    }
}

/// Parses the registration values from a Task Scheduler XML document.
pub fn parse_observed_registration(
    uri: &str,
    xml: &str,
) -> Result<ObservedRegistration, ParseObservedRegistrationError> {
    use ParseObservedRegistrationError as Error;

    let mut reader = Reader::from_str(xml);
    let mut path = Vec::<Vec<u8>>::new();
    let mut saw_root = false;
    let mut root_closed = false;
    let mut exec_count = 0;
    let mut active_field: Option<(ObservedField, String)> = None;
    let mut values: Vec<(ObservedField, String)> = Vec::new();

    loop {
        match reader.read_event().map_err(|_| Error::MalformedXml)? {
            Event::Start(element) => {
                if path.is_empty() {
                    if saw_root || element.local_name().as_ref() != b"Task" {
                        return Err(Error::MissingTaskRoot);
                    }
                    saw_root = true;
                } else if root_closed {
                    return Err(Error::MalformedXml);
                }
                path.push(element.local_name().as_ref().to_vec());
                start_observed_element(&path, &mut exec_count, &mut active_field, &values)?;
            }
            Event::Empty(element) => {
                if path.is_empty() {
                    if saw_root || element.local_name().as_ref() != b"Task" {
                        return Err(Error::MissingTaskRoot);
                    }
                    saw_root = true;
                } else if root_closed {
                    return Err(Error::MalformedXml);
                }
                path.push(element.local_name().as_ref().to_vec());
                start_observed_element(&path, &mut exec_count, &mut active_field, &values)?;
                finish_observed_element(&path, &mut active_field, &mut values);
                path.pop();
                if path.is_empty() {
                    root_closed = true;
                }
            }
            Event::Text(text) => {
                if let Some((_, value)) = &mut active_field {
                    value.push_str(&text.decode().map_err(|_| Error::MalformedXml)?);
                }
            }
            Event::GeneralRef(reference) => {
                if let Some((_, value)) = &mut active_field {
                    let reference = reference.decode().map_err(|_| Error::MalformedXml)?;
                    let escaped = format!("&{reference};");
                    value.push_str(
                        &quick_xml::escape::unescape(&escaped).map_err(|_| Error::MalformedXml)?,
                    );
                }
            }
            Event::CData(text) => {
                if let Some((_, value)) = &mut active_field {
                    value.push_str(&text.decode().map_err(|_| Error::MalformedXml)?);
                }
            }
            Event::End(_) => {
                finish_observed_element(&path, &mut active_field, &mut values);
                path.pop().ok_or(Error::MalformedXml)?;
                if path.is_empty() {
                    root_closed = true;
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }

    if !saw_root {
        return Err(Error::MissingTaskRoot);
    }
    if !root_closed {
        return Err(Error::MalformedXml);
    }
    if exec_count == 0 {
        return Err(Error::MissingElement("Actions/Exec"));
    }

    let document_uri = take_observed_value(&mut values, ObservedField::Uri)?;
    if document_uri != uri {
        return Err(Error::UriMismatch);
    }
    let principal_sid = take_observed_value(&mut values, ObservedField::UserId)?;
    let logon_type = match take_observed_value(&mut values, ObservedField::LogonType)?.as_str() {
        "InteractiveToken" => LogonType::InteractiveToken,
        "None" => LogonType::Other(0),
        "Password" => LogonType::Other(1),
        "S4U" => LogonType::Other(2),
        "Group" => LogonType::Other(4),
        "ServiceAccount" => LogonType::Other(5),
        "InteractiveTokenOrPassword" => LogonType::Other(6),
        _ => return Err(Error::UnrecognizedLogonType),
    };
    let run_level = match values
        .iter()
        .position(|(field, _)| *field == ObservedField::RunLevel)
        .map(|index| values.swap_remove(index).1)
        .as_deref()
    {
        None | Some("LeastPrivilege") => RunLevel::LeastPrivilege,
        Some("HighestAvailable") => RunLevel::HighestPrivilege,
        Some(_) => return Err(Error::UnrecognizedRunLevel),
    };
    let action_path = PathBuf::from(take_observed_value(&mut values, ObservedField::Command)?);
    let action_arguments = values
        .iter()
        .position(|(field, _)| *field == ObservedField::Arguments)
        .map(|index| values.swap_remove(index).1);

    Ok(ObservedRegistration {
        uri: uri.to_owned(),
        principal_sid,
        logon_type,
        run_level,
        action_path,
        action_arguments,
    })
}

fn start_observed_element(
    path: &[Vec<u8>],
    exec_count: &mut usize,
    active_field: &mut Option<(ObservedField, String)>,
    values: &[(ObservedField, String)],
) -> Result<(), ParseObservedRegistrationError> {
    if path_matches(path, &["Task", "Actions", "Exec"]) {
        *exec_count += 1;
        if *exec_count > 1 {
            return Err(ParseObservedRegistrationError::MultipleExecActions);
        }
    }

    let field = if path_matches(path, &["Task", "RegistrationInfo", "URI"]) {
        Some(ObservedField::Uri)
    } else if path_matches(path, &["Task", "Principals", "Principal", "UserId"]) {
        Some(ObservedField::UserId)
    } else if path_matches(path, &["Task", "Principals", "Principal", "LogonType"]) {
        Some(ObservedField::LogonType)
    } else if path_matches(path, &["Task", "Principals", "Principal", "RunLevel"]) {
        Some(ObservedField::RunLevel)
    } else if path_matches(path, &["Task", "Actions", "Exec", "Command"]) {
        Some(ObservedField::Command)
    } else if path_matches(path, &["Task", "Actions", "Exec", "Arguments"]) {
        Some(ObservedField::Arguments)
    } else {
        None
    };

    if let Some(field) = field {
        if values.iter().any(|(existing, _)| *existing == field)
            || active_field
                .as_ref()
                .is_some_and(|(existing, _)| *existing == field)
        {
            return Err(ParseObservedRegistrationError::DuplicateElement(
                field.name(),
            ));
        }
        *active_field = Some((field, String::new()));
    }
    Ok(())
}

fn finish_observed_element(
    path: &[Vec<u8>],
    active_field: &mut Option<(ObservedField, String)>,
    values: &mut Vec<(ObservedField, String)>,
) {
    let should_finish = active_field
        .as_ref()
        .is_some_and(|(field, _)| observed_field_for_path(path) == Some(*field));
    if should_finish {
        values.push(active_field.take().expect("the field exists"));
    }
}

fn observed_field_for_path(path: &[Vec<u8>]) -> Option<ObservedField> {
    [
        (ObservedField::Uri, &["Task", "RegistrationInfo", "URI"][..]),
        (
            ObservedField::UserId,
            &["Task", "Principals", "Principal", "UserId"][..],
        ),
        (
            ObservedField::LogonType,
            &["Task", "Principals", "Principal", "LogonType"][..],
        ),
        (
            ObservedField::RunLevel,
            &["Task", "Principals", "Principal", "RunLevel"][..],
        ),
        (
            ObservedField::Command,
            &["Task", "Actions", "Exec", "Command"][..],
        ),
        (
            ObservedField::Arguments,
            &["Task", "Actions", "Exec", "Arguments"][..],
        ),
    ]
    .into_iter()
    .find_map(|(field, expected)| path_matches(path, expected).then_some(field))
}

fn path_matches(path: &[Vec<u8>], expected: &[&str]) -> bool {
    path.len() == expected.len()
        && path
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual == expected.as_bytes())
}

fn take_observed_value(
    values: &mut Vec<(ObservedField, String)>,
    field: ObservedField,
) -> Result<String, ParseObservedRegistrationError> {
    let index = values
        .iter()
        .position(|(existing, _)| *existing == field)
        .ok_or(ParseObservedRegistrationError::MissingElement(field.name()))?;
    Ok(values.swap_remove(index).1)
}

fn format_duration(duration: Duration) -> String {
    let total_seconds = duration.as_secs();
    let days = total_seconds / 86_400;
    let hours = total_seconds % 86_400 / 3_600;
    let minutes = total_seconds % 3_600 / 60;
    let seconds = total_seconds % 60;
    let nanos = duration.subsec_nanos();

    let mut value = String::from("P");
    if days > 0 {
        write!(value, "{days}D").expect("writing to a String cannot fail");
    }
    if hours > 0 || minutes > 0 || seconds > 0 || nanos > 0 || days == 0 {
        value.push('T');
        if hours > 0 {
            write!(value, "{hours}H").expect("writing to a String cannot fail");
        }
        if minutes > 0 {
            write!(value, "{minutes}M").expect("writing to a String cannot fail");
        }
        if seconds > 0 || nanos > 0 || (hours == 0 && minutes == 0) {
            write!(value, "{seconds}").expect("writing to a String cannot fail");
            if nanos > 0 {
                let fraction = format!("{nanos:09}");
                value.push('.');
                value.push_str(fraction.trim_end_matches('0'));
            }
            value.push('S');
        }
    }
    value
}

/// Classifies only the registration values that establish ownership and compatibility.
pub fn registration_verdict(
    expected: &TaskDefinition,
    observed: &ObservedRegistration,
) -> RegistrationVerdict {
    if observed.uri != expected.uri
        || observed.principal_sid != expected.principal_sid
        || observed.action_path != expected.action.path
        || observed.action_arguments != expected.action.arguments
    {
        return RegistrationVerdict::Foreign;
    }

    if observed.logon_type == expected.logon_type && observed.run_level == expected.run_level {
        RegistrationVerdict::Equal
    } else {
        RegistrationVerdict::Different
    }
}

/// Plans how to register the task while preserving an existing machine payload action.
pub fn plan_task_registration(
    expected: &TaskDefinition,
    observed: Option<&ObservedRegistration>,
    machine_payload_root: impl AsRef<Path>,
    user_payload_root: impl AsRef<Path>,
) -> TaskRegistrationPlan {
    let Some(observed) = observed else {
        return TaskRegistrationPlan::Register;
    };

    if observed.uri != expected.uri
        || observed.principal_sid != expected.principal_sid
        || observed.action_arguments.is_some()
        || (!is_path_under(&observed.action_path, machine_payload_root.as_ref())
            && !is_path_under(&observed.action_path, user_payload_root.as_ref()))
    {
        return TaskRegistrationPlan::Refuse;
    }

    if observed.logon_type == expected.logon_type
        && observed.run_level == expected.run_level
        && observed.action_path == expected.action.path
        && observed.action_arguments == expected.action.arguments
    {
        return TaskRegistrationPlan::LeaveUnchanged;
    }

    if is_path_under(&observed.action_path, machine_payload_root.as_ref())
        && is_path_under(&expected.action.path, user_payload_root.as_ref())
    {
        TaskRegistrationPlan::LeaveUnchanged
    } else {
        TaskRegistrationPlan::Update
    }
}

/// Plans how an uninstaller handles an observed runtime task.
pub fn plan_task_removal(scope: &RemovalScope, observed: &ObservedRegistration) -> TaskRemovalPlan {
    let (payload_path, replacement_path, user_sid) = match scope {
        RemovalScope::PerUser {
            user_sid,
            payload_path,
            machine_payload_path,
        } => (payload_path, machine_payload_path, Some(user_sid.as_str())),
        RemovalScope::Machine {
            payload_path,
            per_user_payload_path,
        } => (payload_path, per_user_payload_path, None),
    };

    let observed_sid = sid_from_task_uri(&observed.uri);
    if observed_sid != Some(observed.principal_sid.as_str())
        || user_sid.is_some_and(|user_sid| observed_sid != Some(user_sid))
        || observed.action_arguments.is_some()
        || observed.action_path != *payload_path
    {
        return TaskRemovalPlan::LeaveUnchanged;
    }

    replacement_path
        .clone()
        .map_or(TaskRemovalPlan::StopAndDelete, TaskRemovalPlan::RepointTo)
}

fn is_path_under(path: &Path, root: &Path) -> bool {
    let (Some(path), Some(root)) = (path.to_str(), root.to_str()) else {
        return false;
    };
    let root_segments: Vec<_> = root.split(['\\', '/']).collect();
    if path
        .split(['\\', '/'])
        .any(|part| matches!(part, "." | ".."))
        || root_segments.iter().any(|part| matches!(*part, "." | ".."))
        || !is_absolute_windows_root(root, &root_segments)
    {
        return false;
    }

    let path = path.replace('/', "\\").to_ascii_lowercase();
    let root = root
        .replace('/', "\\")
        .trim_end_matches('\\')
        .to_ascii_lowercase();
    path.strip_prefix(&root)
        .is_some_and(|suffix| suffix.starts_with('\\'))
}

fn is_absolute_windows_root(path: &str, segments: &[&str]) -> bool {
    let drive_absolute = path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && matches!(path.as_bytes().get(2), Some(b'\\' | b'/'));
    let unc_absolute = (path.starts_with(r"\\") || path.starts_with("//"))
        && segments.get(2).is_some_and(|server| !server.is_empty())
        && segments.get(3).is_some_and(|share| !share.is_empty());
    drive_absolute || unc_absolute
}

fn validate_payload_path(path: &Path) -> Result<(), TaskDefinitionError> {
    let path = path
        .to_str()
        .ok_or(TaskDefinitionError::RelativePayloadPath)?;
    let segments: Vec<_> = path.split(['\\', '/']).collect();
    if segments.contains(&"..") {
        return Err(TaskDefinitionError::ParentPathSegment);
    }
    if !is_absolute_windows_path(path, &segments) {
        return Err(TaskDefinitionError::RelativePayloadPath);
    }
    if !segments
        .last()
        .is_some_and(|name| name.eq_ignore_ascii_case(RUNTIME_FILE_NAME))
    {
        return Err(TaskDefinitionError::WrongPayloadFileName);
    }
    Ok(())
}

fn is_absolute_windows_path(path: &str, segments: &[&str]) -> bool {
    let drive_absolute = path.as_bytes().get(1) == Some(&b':')
        && path.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && matches!(path.as_bytes().get(2), Some(b'\\' | b'/'));
    let unc_absolute = (path.starts_with(r"\\") || path.starts_with("//"))
        && segments.get(2).is_some_and(|server| !server.is_empty())
        && segments.get(3).is_some_and(|share| !share.is_empty())
        && segments
            .get(4)
            .is_some_and(|component| !component.is_empty());
    drive_absolute || unc_absolute
}

/// Returns whether a string uses the canonical SID syntax.
pub fn is_canonical_sid(sid: &str) -> bool {
    let mut parts = sid.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return false;
    }
    let Some(authority) = parts.next() else {
        return false;
    };
    if !is_canonical_authority(authority) {
        return false;
    }

    let sub_authorities: Vec<_> = parts.collect();
    !sub_authorities.is_empty()
        && sub_authorities.len() <= MAX_SID_SUB_AUTHORITIES
        && sub_authorities
            .iter()
            .all(|part| parse_canonical_decimal(part, u32::MAX as u64).is_some())
}

fn is_canonical_authority(authority: &str) -> bool {
    const HEX_PREFIX: &str = "0x";
    const HEX_DIGITS: usize = 12;
    const DECIMAL_LIMIT: u64 = 1 << 32;

    if let Some(hex) = authority.strip_prefix(HEX_PREFIX) {
        return hex.len() == HEX_DIGITS
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
            && u64::from_str_radix(hex, 16).is_ok_and(|value| value >= DECIMAL_LIMIT);
    }

    parse_canonical_decimal(authority, MAX_SID_AUTHORITY).is_some_and(|value| value < DECIMAL_LIMIT)
}

fn parse_canonical_decimal(value: &str, maximum: u64) -> Option<u64> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return None;
    }
    value.parse::<u64>().ok().filter(|value| *value <= maximum)
}
