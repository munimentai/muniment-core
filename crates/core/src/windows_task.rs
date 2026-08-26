//! Platform-independent values for the Windows runtime Scheduled Task.

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
pub enum RegistrationVerdict {
    Equal,
    Different,
    Foreign,
}

/// Returns the stable Task Scheduler URI for a canonical SID string.
pub fn task_uri(sid: &str) -> Result<String, SidError> {
    if !is_canonical_sid(sid) {
        return Err(SidError::NotCanonical);
    }
    Ok(format!(r"\Muniment\Runtime-{sid}"))
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
