//! Live registration access through the Windows Task Scheduler.

use crate::windows_payload::{
    plan_windows_payload_removals, resolve_live_windows_payload,
    resolve_live_windows_payload_scopes, LiveWindowsPayloadScopesError, UninstallerRemovalPlan,
};
use crate::windows_sid::{current_process_user_sid, WindowsSidError};
use crate::windows_task::{
    parse_observed_registration, plan_task_registration, plan_task_removal, registration_verdict,
    render_task_definition_xml, sid_from_task_uri, task_uri, ObservedRegistration,
    ParseObservedRegistrationError, RegistrationVerdict, RemovalScope, RenderTaskDefinitionError,
    SidError, TaskDefinition, TaskDefinitionError, TaskRegistrationPlan, TaskRemovalPlan,
};
use std::fmt;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};
use windows::core::{Interface, BSTR, HRESULT};
use windows::Win32::Foundation::{RPC_E_CHANGED_MODE, SCHED_E_ALREADY_RUNNING};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::TaskScheduler::{
    IExecAction, ITaskDefinition, ITaskFolder, ITaskService, TaskScheduler, TASK_ACTION_EXEC,
    TASK_CREATE_OR_UPDATE, TASK_ENUM_HIDDEN, TASK_LOGON_INTERACTIVE_TOKEN, TASK_LOGON_NONE,
    TASK_LOGON_TYPE, TASK_RUN_IGNORE_CONSTRAINTS, TASK_RUN_USE_SESSION_ID, TASK_STATE,
    TASK_STATE_QUEUED, TASK_STATE_RUNNING, TASK_UPDATE,
};
use windows::Win32::System::Variant::VARIANT;

const TASK_FOLDER: &str = r"\Muniment";
const HRESULT_FILE_NOT_FOUND: HRESULT = HRESULT(0x8007_0002_u32 as i32);
const HRESULT_PATH_NOT_FOUND: HRESULT = HRESULT(0x8007_0003_u32 as i32);
const HRESULT_ALREADY_EXISTS: HRESULT = HRESULT(0x8007_00b7_u32 as i32);
const SCHED_E_TASK_NOT_FOUND: HRESULT = HRESULT(0x8004_130f_u32 as i32);

/// A failure while reading a runtime task registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadObservedRegistrationError {
    InvalidSid(SidError),
    InitializeCom(HRESULT),
    CreateTaskService(HRESULT),
    ConnectTaskService(HRESULT),
    OpenTaskFolder(HRESULT),
    OpenTask(HRESULT),
    ReadTaskXml(HRESULT),
    InvalidTaskXmlText,
    ParseTaskXml(ParseObservedRegistrationError),
}

impl fmt::Display for ReadObservedRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSid(_) => "the task SID is not canonical",
            Self::InitializeCom(_) => "could not initialize COM",
            Self::CreateTaskService(_) => "could not create the Task Scheduler service",
            Self::ConnectTaskService(_) => "could not connect to the local Task Scheduler",
            Self::OpenTaskFolder(_) => "could not open the Muniment task folder",
            Self::OpenTask(_) => "could not open the runtime task",
            Self::ReadTaskXml(_) => "could not read the runtime task XML",
            Self::InvalidTaskXmlText => "the runtime task XML contains invalid text",
            Self::ParseTaskXml(_) => "could not parse the runtime task XML",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReadObservedRegistrationError {}

/// A failure while listing runtime task registrations.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ListObservedRegistrationsError {
    InitializeCom(HRESULT),
    CreateTaskService(HRESULT),
    ConnectTaskService(HRESULT),
    OpenTaskFolder(HRESULT),
    ListTasks(HRESULT),
    CountTasks(HRESULT),
    ReadTask(HRESULT),
    ReadTaskName(HRESULT),
    InvalidTaskNameText,
    ReadTaskXml {
        uri: String,
        code: HRESULT,
    },
    InvalidTaskXmlText {
        uri: String,
    },
    ParseTaskXml {
        uri: String,
        source: ParseObservedRegistrationError,
    },
}

impl fmt::Display for ListObservedRegistrationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InitializeCom(_) => formatter.write_str("could not initialize COM"),
            Self::CreateTaskService(_) => {
                formatter.write_str("could not create the Task Scheduler service")
            }
            Self::ConnectTaskService(_) => {
                formatter.write_str("could not connect to the local Task Scheduler")
            }
            Self::OpenTaskFolder(_) => {
                formatter.write_str("could not open the Muniment task folder")
            }
            Self::ListTasks(_) => formatter.write_str("could not list the Muniment tasks"),
            Self::CountTasks(_) => formatter.write_str("could not count the Muniment tasks"),
            Self::ReadTask(_) => formatter.write_str("could not read a Muniment task"),
            Self::ReadTaskName(_) => formatter.write_str("could not read a Muniment task name"),
            Self::InvalidTaskNameText => {
                formatter.write_str("a Muniment task name contains invalid text")
            }
            Self::ReadTaskXml { uri, .. } => write!(formatter, "could not read task XML for {uri}"),
            Self::InvalidTaskXmlText { uri } => {
                write!(formatter, "task XML for {uri} contains invalid text")
            }
            Self::ParseTaskXml { uri, .. } => {
                write!(formatter, "could not parse task XML for {uri}")
            }
        }
    }
}

impl std::error::Error for ListObservedRegistrationsError {}

/// A failure while planning live runtime task removal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PlanLiveTaskRemovalsError {
    ResolvePayloads(LiveWindowsPayloadScopesError),
    ReadProcessUserSid(WindowsSidError),
    ListRegistrations(ListObservedRegistrationsError),
    InvalidProcessUserSid(SidError),
}

impl fmt::Display for PlanLiveTaskRemovalsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ResolvePayloads(_) => "could not resolve the installed runtime payloads",
            Self::ReadProcessUserSid(_) => "could not read the process user SID",
            Self::ListRegistrations(_) => "could not list the runtime task registrations",
            Self::InvalidProcessUserSid(_) => "the process user SID is not canonical",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PlanLiveTaskRemovalsError {}

/// A failure while writing a runtime task registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureTaskRegistrationError {
    InvalidSid(SidError),
    InvalidTaskDefinition(TaskDefinitionError),
    InitializeCom(HRESULT),
    CreateTaskService(HRESULT),
    ConnectTaskService(HRESULT),
    OpenTaskFolder(HRESULT),
    OpenTask(HRESULT),
    ReadTaskXml(HRESULT),
    InvalidTaskXmlText,
    ParseTaskXml(ParseObservedRegistrationError),
    OpenRootFolder(HRESULT),
    CreateTaskFolder(HRESULT),
    CreateTaskDefinition(HRESULT),
    RenderTaskXml(RenderTaskDefinitionError),
    SetTaskXml(HRESULT),
    RegisterTaskDefinition(HRESULT),
    Refused,
}

impl fmt::Display for EnsureTaskRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSid(_) => "the task SID is not canonical",
            Self::InvalidTaskDefinition(_) => "the runtime task definition is invalid",
            Self::InitializeCom(_) => "could not initialize COM",
            Self::CreateTaskService(_) => "could not create the Task Scheduler service",
            Self::ConnectTaskService(_) => "could not connect to the local Task Scheduler",
            Self::OpenTaskFolder(_) => "could not open the Muniment task folder",
            Self::OpenTask(_) => "could not open the runtime task",
            Self::ReadTaskXml(_) => "could not read the runtime task XML",
            Self::InvalidTaskXmlText => "the runtime task XML contains invalid text",
            Self::ParseTaskXml(_) => "could not parse the runtime task XML",
            Self::OpenRootFolder(_) => "could not open the Task Scheduler root folder",
            Self::CreateTaskFolder(_) => "could not create the Muniment task folder",
            Self::CreateTaskDefinition(_) => "could not create the runtime task definition",
            Self::RenderTaskXml(_) => "could not render the runtime task XML",
            Self::SetTaskXml(_) => "could not set the runtime task XML",
            Self::RegisterTaskDefinition(_) => "could not register the runtime task",
            Self::Refused => "refused to replace a foreign runtime task",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for EnsureTaskRegistrationError {}

/// A failure while writing a live runtime task registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnsureLiveTaskRegistrationError {
    ReadProcessUserSid(WindowsSidError),
    ResolvePayload(LiveWindowsPayloadScopesError),
    NoInstalledPayload,
    EnsureRegistration(EnsureTaskRegistrationError),
}

impl fmt::Display for EnsureLiveTaskRegistrationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ReadProcessUserSid(_) => "could not read the process user SID",
            Self::ResolvePayload(_) => "could not resolve the installed runtime payload",
            Self::NoInstalledPayload => "no installed runtime payload exists",
            Self::EnsureRegistration(_) => "could not write the runtime task registration",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for EnsureLiveTaskRegistrationError {}

/// A failure while removing or repointing a runtime task registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ApplyTaskRemovalError {
    InvalidSid(SidError),
    InitializeCom(HRESULT),
    CreateTaskService(HRESULT),
    ConnectTaskService(HRESULT),
    OpenTaskFolder(HRESULT),
    OpenTask(HRESULT),
    ReadTaskXml(HRESULT),
    InvalidTaskXmlText,
    ParseTaskXml(ParseObservedRegistrationError),
    StopTask(HRESULT),
    DeleteTask(HRESULT),
    ReadRemainingTasks(HRESULT),
    CountRemainingTasks(HRESULT),
    OpenRootFolder(HRESULT),
    DeleteTaskFolder(HRESULT),
    ReadTaskDefinition(HRESULT),
    ReadTaskActions(HRESULT),
    CountTaskActions(HRESULT),
    ReadTaskAction(HRESULT),
    ReadTaskActionType(HRESULT),
    ReadExecAction(HRESULT),
    MissingExecAction,
    SetActionPath(HRESULT),
    RegisterTaskDefinition(HRESULT),
}

impl fmt::Display for ApplyTaskRemovalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSid(_) => "the task SID is not canonical",
            Self::InitializeCom(_) => "could not initialize COM",
            Self::CreateTaskService(_) => "could not create the Task Scheduler service",
            Self::ConnectTaskService(_) => "could not connect to the local Task Scheduler",
            Self::OpenTaskFolder(_) => "could not open the Muniment task folder",
            Self::OpenTask(_) => "could not open the runtime task",
            Self::ReadTaskXml(_) => "could not read the runtime task XML",
            Self::InvalidTaskXmlText => "the runtime task XML contains invalid text",
            Self::ParseTaskXml(_) => "could not parse the runtime task XML",
            Self::StopTask(_) => "could not stop the runtime task",
            Self::DeleteTask(_) => "could not delete the runtime task",
            Self::ReadRemainingTasks(_) => "could not read the remaining Muniment tasks",
            Self::CountRemainingTasks(_) => "could not count the remaining Muniment tasks",
            Self::OpenRootFolder(_) => "could not open the Task Scheduler root folder",
            Self::DeleteTaskFolder(_) => "could not delete the Muniment task folder",
            Self::ReadTaskDefinition(_) => "could not read the runtime task definition",
            Self::ReadTaskActions(_) => "could not read the runtime task actions",
            Self::CountTaskActions(_) => "could not count the runtime task actions",
            Self::ReadTaskAction(_) => "could not read the runtime task action",
            Self::ReadTaskActionType(_) => "could not read the runtime task action type",
            Self::ReadExecAction(_) => "the runtime task action is not executable",
            Self::MissingExecAction => "the runtime task has no executable action",
            Self::SetActionPath(_) => "could not set the runtime task action path",
            Self::RegisterTaskDefinition(_) => "could not register the runtime task",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ApplyTaskRemovalError {}

/// The result of a request to start the registered runtime task.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartRegisteredTaskResult {
    Started,
    AlreadyRunning,
}

/// A failure while starting the registered runtime task.
#[derive(Debug, Eq, PartialEq)]
pub enum StartRegisteredTaskError<E> {
    ReadRegistration(ReadObservedRegistrationError),
    Missing,
    InvalidTaskDefinition(TaskDefinitionError),
    Refused,
    InitializeCom(HRESULT),
    CreateTaskService(HRESULT),
    ConnectTaskService(HRESULT),
    OpenTaskFolder(HRESULT),
    OpenTask(HRESULT),
    ReadTaskXml(HRESULT),
    InvalidTaskXmlText,
    ParseTaskXml(ParseObservedRegistrationError),
    ReadTaskState(HRESULT),
    ReadProcessSession(u32),
    InvalidProcessSession(u32),
    ClearCrashWindow(E),
    RunTask(HRESULT),
    Queued { session_id: u32 },
}

impl<E> fmt::Display for StartRegisteredTaskError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::ReadRegistration(_) => "could not read the runtime task registration",
            Self::Missing => "the runtime task is not registered",
            Self::InvalidTaskDefinition(_) => "the runtime task definition is invalid",
            Self::Refused => "refused to start a foreign runtime task",
            Self::InitializeCom(_) => "could not initialize COM",
            Self::CreateTaskService(_) => "could not create the Task Scheduler service",
            Self::ConnectTaskService(_) => "could not connect to the local Task Scheduler",
            Self::OpenTaskFolder(_) => "could not open the Muniment task folder",
            Self::OpenTask(_) => "could not open the runtime task",
            Self::ReadTaskXml(_) => "could not read the runtime task XML",
            Self::InvalidTaskXmlText => "the runtime task XML contains invalid text",
            Self::ParseTaskXml(_) => "could not parse the runtime task XML",
            Self::ReadTaskState(_) => "could not read the runtime task state",
            Self::ReadProcessSession(_) => "The desktop could not read the process session id.",
            Self::InvalidProcessSession(session_id) => {
                return write!(
                    formatter,
                    "The process session id {session_id} is outside the interactive range."
                );
            }
            Self::ClearCrashWindow(_) => "could not clear the runtime crash window",
            Self::RunTask(_) => "could not start the runtime task",
            Self::Queued { session_id } => {
                return write!(formatter, "Task Scheduler kept the runtime task in state Queued for session id {session_id}.");
            }
        };
        formatter.write_str(message)
    }
}

impl<E> std::error::Error for StartRegisteredTaskError<E>
where
    E: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ReadRegistration(error) => Some(error),
            Self::ClearCrashWindow(error) => Some(error),
            _ => None,
        }
    }
}

/// Reads, validates, and starts the registered runtime task.
pub fn start_registered_task<F, E>(
    sid: &str,
    expected_payload_path: impl AsRef<Path>,
    clear_crash_window: F,
) -> Result<StartRegisteredTaskResult, StartRegisteredTaskError<E>>
where
    F: FnOnce() -> Result<(), E>,
{
    let observed = read_observed_registration(sid)
        .map_err(StartRegisteredTaskError::ReadRegistration)?
        .ok_or(StartRegisteredTaskError::Missing)?;
    let expected = TaskDefinition::new(sid, expected_payload_path)
        .map_err(StartRegisteredTaskError::InvalidTaskDefinition)?;
    if registration_verdict(&expected, &observed) == RegistrationVerdict::Foreign {
        return Err(StartRegisteredTaskError::Refused);
    }

    let task_name = expected
        .uri
        .strip_prefix(r"\Muniment\")
        .expect("TaskDefinition::new always returns a task in the Muniment folder");
    let _apartment = ComApartment::initialize_for_start()?;
    let service: ITaskService = unsafe {
        CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| StartRegisteredTaskError::CreateTaskService(error.code()))?
    };
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|error| StartRegisteredTaskError::ConnectTaskService(error.code()))?;
    let folder = unsafe { service.GetFolder(&BSTR::from(TASK_FOLDER)) }
        .map_err(|error| StartRegisteredTaskError::OpenTaskFolder(error.code()))?;
    let task = unsafe { folder.GetTask(&BSTR::from(task_name)) }
        .map_err(|error| StartRegisteredTaskError::OpenTask(error.code()))?;
    let xml = unsafe { task.Xml() }
        .map_err(|error| StartRegisteredTaskError::ReadTaskXml(error.code()))?;
    let xml = String::try_from(&xml).map_err(|_| StartRegisteredTaskError::InvalidTaskXmlText)?;
    let current = parse_observed_registration(&expected.uri, &xml)
        .map_err(StartRegisteredTaskError::ParseTaskXml)?;
    if registration_verdict(&expected, &current) == RegistrationVerdict::Foreign {
        return Err(StartRegisteredTaskError::Refused);
    }
    let state = unsafe { task.State() }
        .map_err(|error| StartRegisteredTaskError::ReadTaskState(error.code()))?;
    if state == TASK_STATE_RUNNING {
        return Ok(StartRegisteredTaskResult::AlreadyRunning);
    }

    let mut session_id = 0;
    if unsafe {
        windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
            std::process::id(),
            &mut session_id,
        )
    } == 0
    {
        return Err(StartRegisteredTaskError::ReadProcessSession(unsafe {
            windows_sys::Win32::Foundation::GetLastError()
        }));
    }
    start_task_in_session(session_id, clear_crash_window, |flags, session_id| {
        let _running = unsafe { task.RunEx(&empty, flags, session_id, &BSTR::new()) }
            .map_err(|error| StartRegisteredTaskError::RunTask(error.code()))?;
        // Give the scheduler time to place the instance before reporting Queued.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let state = unsafe { task.State() }
                .map_err(|error| StartRegisteredTaskError::ReadTaskState(error.code()))?;
            if state != TASK_STATE_QUEUED || Instant::now() >= deadline {
                return Ok(state);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    })
}

fn start_task_in_session<E>(
    session_id: u32,
    clear_crash_window: impl FnOnce() -> Result<(), E>,
    run: impl FnOnce(i32, i32) -> Result<TASK_STATE, StartRegisteredTaskError<E>>,
) -> Result<StartRegisteredTaskResult, StartRegisteredTaskError<E>> {
    let session = i32::try_from(session_id)
        .ok()
        .filter(|session| *session > 0)
        .ok_or(StartRegisteredTaskError::InvalidProcessSession(session_id))?;
    clear_crash_window().map_err(StartRegisteredTaskError::ClearCrashWindow)?;
    // An app launch must not wait for idle or power constraints in the scheduler.
    // Keep the caller's session explicit without changing the registered task.
    let flags = TASK_RUN_USE_SESSION_ID.0 | TASK_RUN_IGNORE_CONSTRAINTS.0;
    match run(flags, session) {
        Ok(TASK_STATE_QUEUED) => Err(StartRegisteredTaskError::Queued { session_id }),
        Ok(_) => Ok(StartRegisteredTaskResult::Started),
        Err(StartRegisteredTaskError::RunTask(SCHED_E_ALREADY_RUNNING)) => {
            Ok(StartRegisteredTaskResult::AlreadyRunning)
        }
        Err(error) => Err(error),
    }
}

/// Reads the runtime task registration for a canonical user SID.
pub fn read_observed_registration(
    sid: &str,
) -> Result<Option<ObservedRegistration>, ReadObservedRegistrationError> {
    let uri = task_uri(sid).map_err(ReadObservedRegistrationError::InvalidSid)?;
    let task_name = uri
        .strip_prefix(r"\Muniment\")
        .expect("task_uri always returns a task in the Muniment folder");

    let _apartment = ComApartment::initialize()?;
    let service: ITaskService = unsafe {
        CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| ReadObservedRegistrationError::CreateTaskService(error.code()))?
    };
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|error| ReadObservedRegistrationError::ConnectTaskService(error.code()))?;

    let folder = match unsafe { service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
        Ok(folder) => folder,
        Err(error) if is_absent(error.code()) => return Ok(None),
        Err(error) => return Err(ReadObservedRegistrationError::OpenTaskFolder(error.code())),
    };
    let task = match unsafe { folder.GetTask(&BSTR::from(task_name)) } {
        Ok(task) => task,
        Err(error) if is_absent(error.code()) => return Ok(None),
        Err(error) => return Err(ReadObservedRegistrationError::OpenTask(error.code())),
    };
    let xml = unsafe { task.Xml() }
        .map_err(|error| ReadObservedRegistrationError::ReadTaskXml(error.code()))?;
    let xml =
        String::try_from(&xml).map_err(|_| ReadObservedRegistrationError::InvalidTaskXmlText)?;
    let observed = parse_observed_registration(&uri, &xml)
        .map_err(ReadObservedRegistrationError::ParseTaskXml)?;

    Ok(Some(observed))
}

/// Lists the runtime task registrations in the Muniment task folder.
pub fn list_observed_registrations(
) -> Result<Vec<ObservedRegistration>, ListObservedRegistrationsError> {
    let _apartment = ComApartment::initialize_for_list()?;
    let service: ITaskService = unsafe {
        CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| ListObservedRegistrationsError::CreateTaskService(error.code()))?
    };
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|error| ListObservedRegistrationsError::ConnectTaskService(error.code()))?;
    let folder = match unsafe { service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
        Ok(folder) => folder,
        Err(error) if is_absent(error.code()) => return Ok(Vec::new()),
        Err(error) => return Err(ListObservedRegistrationsError::OpenTaskFolder(error.code())),
    };
    let tasks = unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) }
        .map_err(|error| ListObservedRegistrationsError::ListTasks(error.code()))?;
    let count = unsafe { tasks.Count() }
        .map_err(|error| ListObservedRegistrationsError::CountTasks(error.code()))?;
    let mut registrations = Vec::new();

    for index in 1..=count {
        let task = unsafe { tasks.get_Item(&VARIANT::from(index)) }
            .map_err(|error| ListObservedRegistrationsError::ReadTask(error.code()))?;
        let name = unsafe { task.Name() }
            .map_err(|error| ListObservedRegistrationsError::ReadTaskName(error.code()))?;
        let name = String::try_from(&name)
            .map_err(|_| ListObservedRegistrationsError::InvalidTaskNameText)?;
        let uri = format!(r"{TASK_FOLDER}\{name}");
        if sid_from_task_uri(&uri).is_none() {
            continue;
        }
        let xml =
            unsafe { task.Xml() }.map_err(|error| ListObservedRegistrationsError::ReadTaskXml {
                uri: uri.clone(),
                code: error.code(),
            })?;
        let xml = String::try_from(&xml)
            .map_err(|_| ListObservedRegistrationsError::InvalidTaskXmlText { uri: uri.clone() })?;
        let observed = parse_observed_registration(&uri, &xml).map_err(|source| {
            ListObservedRegistrationsError::ParseTaskXml {
                uri: uri.clone(),
                source,
            }
        })?;
        registrations.push(observed);
    }

    Ok(registrations)
}

/// Plans every live uninstaller scope against every runtime task registration.
pub fn plan_live_task_removals() -> Result<Vec<UninstallerRemovalPlan>, PlanLiveTaskRemovalsError> {
    let payload_scopes = resolve_live_windows_payload_scopes()
        .map_err(PlanLiveTaskRemovalsError::ResolvePayloads)?;
    let user_sid =
        current_process_user_sid().map_err(PlanLiveTaskRemovalsError::ReadProcessUserSid)?;
    let registrations =
        list_observed_registrations().map_err(PlanLiveTaskRemovalsError::ListRegistrations)?;
    plan_windows_payload_removals(&payload_scopes, user_sid.as_str(), &registrations)
        .map_err(PlanLiveTaskRemovalsError::InvalidProcessUserSid)
}

/// Registers the runtime task from the live payload and known-folder roots.
///
/// The caller must hold the per-user install lock.
pub fn ensure_live_task_registration(
) -> Result<TaskRegistrationPlan, EnsureLiveTaskRegistrationError> {
    let sid =
        current_process_user_sid().map_err(EnsureLiveTaskRegistrationError::ReadProcessUserSid)?;
    let payload = resolve_live_windows_payload()
        .map_err(EnsureLiveTaskRegistrationError::ResolvePayload)?
        .ok_or(EnsureLiveTaskRegistrationError::NoInstalledPayload)?;

    ensure_task_registration(
        sid.as_str(),
        payload.payload_path,
        payload.machine_payload_root,
        payload.user_payload_root,
    )
    .map_err(EnsureLiveTaskRegistrationError::EnsureRegistration)
}

/// Makes the planned runtime task registration change and returns its plan.
pub fn ensure_task_registration(
    sid: &str,
    payload_path: impl AsRef<Path>,
    machine_payload_root: impl AsRef<Path>,
    user_payload_root: impl AsRef<Path>,
) -> Result<TaskRegistrationPlan, EnsureTaskRegistrationError> {
    let expected = TaskDefinition::new(sid, payload_path).map_err(|error| match error {
        TaskDefinitionError::InvalidSid => {
            EnsureTaskRegistrationError::InvalidSid(SidError::NotCanonical)
        }
        error => EnsureTaskRegistrationError::InvalidTaskDefinition(error),
    })?;
    let observed = read_observed_registration(sid).map_err(map_read_error)?;
    let plan = plan_task_registration(
        &expected,
        observed.as_ref(),
        machine_payload_root,
        user_payload_root,
    );

    match plan {
        TaskRegistrationPlan::LeaveUnchanged => return Ok(plan),
        TaskRegistrationPlan::Refuse => return Err(EnsureTaskRegistrationError::Refused),
        TaskRegistrationPlan::Register | TaskRegistrationPlan::Update => {}
    }

    let xml = render_task_definition_xml(&expected)
        .map_err(EnsureTaskRegistrationError::RenderTaskXml)?;
    let task_name = expected
        .uri
        .strip_prefix(r"\Muniment\")
        .expect("TaskDefinition::new always returns a task in the Muniment folder");

    let _apartment = ComApartment::initialize_for_write()?;
    let service: ITaskService = unsafe {
        CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| EnsureTaskRegistrationError::CreateTaskService(error.code()))?
    };
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|error| EnsureTaskRegistrationError::ConnectTaskService(error.code()))?;
    let folder = open_or_create_task_folder(&service, &empty)?;
    let definition = unsafe { service.NewTask(0) }
        .map_err(|error| EnsureTaskRegistrationError::CreateTaskDefinition(error.code()))?;
    unsafe { definition.SetXmlText(&BSTR::from(xml)) }
        .map_err(|error| EnsureTaskRegistrationError::SetTaskXml(error.code()))?;
    register_task_definition(
        &folder,
        task_name,
        &definition,
        TASK_CREATE_OR_UPDATE.0,
        TASK_LOGON_INTERACTIVE_TOKEN,
        &empty,
    )
    .map_err(EnsureTaskRegistrationError::RegisterTaskDefinition)?;

    Ok(plan)
}

/// Makes the planned runtime task removal change and returns its plan.
pub fn apply_task_removal(
    sid: &str,
    scope: &RemovalScope,
) -> Result<TaskRemovalPlan, ApplyTaskRemovalError> {
    let uri = task_uri(sid).map_err(ApplyTaskRemovalError::InvalidSid)?;
    let task_name = uri
        .strip_prefix(r"\Muniment\")
        .expect("task_uri always returns a task in the Muniment folder");
    let _apartment = ComApartment::initialize_for_removal()?;
    let service: ITaskService = unsafe {
        CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER)
            .map_err(|error| ApplyTaskRemovalError::CreateTaskService(error.code()))?
    };
    let empty = VARIANT::default();
    unsafe { service.Connect(&empty, &empty, &empty, &empty) }
        .map_err(|error| ApplyTaskRemovalError::ConnectTaskService(error.code()))?;
    let folder = match unsafe { service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
        Ok(folder) => folder,
        Err(error) if is_absent(error.code()) => return Ok(TaskRemovalPlan::LeaveUnchanged),
        Err(error) => return Err(ApplyTaskRemovalError::OpenTaskFolder(error.code())),
    };
    let task = match unsafe { folder.GetTask(&BSTR::from(task_name)) } {
        Ok(task) => task,
        Err(error) if is_absent(error.code()) => return Ok(TaskRemovalPlan::LeaveUnchanged),
        Err(error) => return Err(ApplyTaskRemovalError::OpenTask(error.code())),
    };
    let xml =
        unsafe { task.Xml() }.map_err(|error| ApplyTaskRemovalError::ReadTaskXml(error.code()))?;
    let xml = String::try_from(&xml).map_err(|_| ApplyTaskRemovalError::InvalidTaskXmlText)?;
    let observed =
        parse_observed_registration(&uri, &xml).map_err(ApplyTaskRemovalError::ParseTaskXml)?;
    let plan = plan_task_removal(scope, &observed);

    match &plan {
        TaskRemovalPlan::StopAndDelete => {
            let stop_result =
                unsafe { (Interface::vtable(&task).Stop)(Interface::as_raw(&task), 0) };
            after_successful_stop(stop_result, || {
                unsafe { folder.DeleteTask(&BSTR::from(task_name), 0) }
                    .map_err(|error| ApplyTaskRemovalError::DeleteTask(error.code()))?;
                let tasks = unsafe { folder.GetTasks(TASK_ENUM_HIDDEN.0) }
                    .map_err(|error| ApplyTaskRemovalError::ReadRemainingTasks(error.code()))?;
                let count = unsafe { tasks.Count() }
                    .map_err(|error| ApplyTaskRemovalError::CountRemainingTasks(error.code()))?;
                if count == 0 {
                    let root = unsafe { service.GetFolder(&BSTR::from(r"\")) }
                        .map_err(|error| ApplyTaskRemovalError::OpenRootFolder(error.code()))?;
                    unsafe { root.DeleteFolder(&BSTR::from("Muniment"), 0) }
                        .map_err(|error| ApplyTaskRemovalError::DeleteTaskFolder(error.code()))?;
                }
                Ok(())
            })?;
        }
        TaskRemovalPlan::RepointTo(payload_path) => {
            let definition = unsafe { task.Definition() }
                .map_err(|error| ApplyTaskRemovalError::ReadTaskDefinition(error.code()))?;
            let actions = unsafe { definition.Actions() }
                .map_err(|error| ApplyTaskRemovalError::ReadTaskActions(error.code()))?;
            let mut count = 0;
            unsafe { actions.Count(&mut count) }
                .map_err(|error| ApplyTaskRemovalError::CountTaskActions(error.code()))?;
            let mut exec_action = None;
            for index in 1..=count {
                let action = unsafe { actions.get_Item(index) }
                    .map_err(|error| ApplyTaskRemovalError::ReadTaskAction(error.code()))?;
                let mut action_type = Default::default();
                unsafe { action.Type(&mut action_type) }
                    .map_err(|error| ApplyTaskRemovalError::ReadTaskActionType(error.code()))?;
                if action_type == TASK_ACTION_EXEC {
                    exec_action =
                        Some(action.cast::<IExecAction>().map_err(|error| {
                            ApplyTaskRemovalError::ReadExecAction(error.code())
                        })?);
                    break;
                }
            }
            let action = exec_action.ok_or(ApplyTaskRemovalError::MissingExecAction)?;
            let payload_path: Vec<_> = payload_path.as_os_str().encode_wide().collect();
            unsafe { action.SetPath(&BSTR::from_wide(&payload_path)) }
                .map_err(|error| ApplyTaskRemovalError::SetActionPath(error.code()))?;
            register_task_definition(
                &folder,
                task_name,
                &definition,
                TASK_UPDATE.0,
                TASK_LOGON_NONE,
                &empty,
            )
            .map_err(ApplyTaskRemovalError::RegisterTaskDefinition)?;
        }
        TaskRemovalPlan::LeaveUnchanged => {}
    }

    Ok(plan)
}

fn after_successful_stop<T>(
    stop_result: HRESULT,
    write: impl FnOnce() -> Result<T, ApplyTaskRemovalError>,
) -> Result<T, ApplyTaskRemovalError> {
    if stop_result == HRESULT(0) {
        write()
    } else {
        Err(ApplyTaskRemovalError::StopTask(stop_result))
    }
}

fn register_task_definition(
    folder: &ITaskFolder,
    task_name: &str,
    definition: &ITaskDefinition,
    flags: i32,
    logon_type: TASK_LOGON_TYPE,
    empty: &VARIANT,
) -> Result<(), HRESULT> {
    unsafe {
        folder.RegisterTaskDefinition(
            &BSTR::from(task_name),
            definition,
            flags,
            empty,
            empty,
            logon_type,
            empty,
        )
    }
    .map(|_| ())
    .map_err(|error| error.code())
}

fn open_or_create_task_folder(
    service: &ITaskService,
    empty: &VARIANT,
) -> Result<ITaskFolder, EnsureTaskRegistrationError> {
    match unsafe { service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
        Ok(folder) => Ok(folder),
        Err(error) if is_absent(error.code()) => {
            let root = unsafe { service.GetFolder(&BSTR::from(r"\")) }
                .map_err(|error| EnsureTaskRegistrationError::OpenRootFolder(error.code()))?;
            match unsafe { root.CreateFolder(&BSTR::from("Muniment"), empty) } {
                Ok(folder) => Ok(folder),
                Err(error) if error.code() == HRESULT_ALREADY_EXISTS => {
                    unsafe { service.GetFolder(&BSTR::from(TASK_FOLDER)) }
                        .map_err(|error| EnsureTaskRegistrationError::OpenTaskFolder(error.code()))
                }
                Err(error) => Err(EnsureTaskRegistrationError::CreateTaskFolder(error.code())),
            }
        }
        Err(error) => Err(EnsureTaskRegistrationError::OpenTaskFolder(error.code())),
    }
}

fn map_read_error(error: ReadObservedRegistrationError) -> EnsureTaskRegistrationError {
    match error {
        ReadObservedRegistrationError::InvalidSid(error) => {
            EnsureTaskRegistrationError::InvalidSid(error)
        }
        ReadObservedRegistrationError::InitializeCom(code) => {
            EnsureTaskRegistrationError::InitializeCom(code)
        }
        ReadObservedRegistrationError::CreateTaskService(code) => {
            EnsureTaskRegistrationError::CreateTaskService(code)
        }
        ReadObservedRegistrationError::ConnectTaskService(code) => {
            EnsureTaskRegistrationError::ConnectTaskService(code)
        }
        ReadObservedRegistrationError::OpenTaskFolder(code) => {
            EnsureTaskRegistrationError::OpenTaskFolder(code)
        }
        ReadObservedRegistrationError::OpenTask(code) => {
            EnsureTaskRegistrationError::OpenTask(code)
        }
        ReadObservedRegistrationError::ReadTaskXml(code) => {
            EnsureTaskRegistrationError::ReadTaskXml(code)
        }
        ReadObservedRegistrationError::InvalidTaskXmlText => {
            EnsureTaskRegistrationError::InvalidTaskXmlText
        }
        ReadObservedRegistrationError::ParseTaskXml(error) => {
            EnsureTaskRegistrationError::ParseTaskXml(error)
        }
    }
}

fn is_absent(code: HRESULT) -> bool {
    matches!(
        code,
        HRESULT_FILE_NOT_FOUND | HRESULT_PATH_NOT_FOUND | SCHED_E_TASK_NOT_FOUND
    )
}

struct ComApartment {
    uninitialize: bool,
}

impl ComApartment {
    fn initialize() -> Result<Self, ReadObservedRegistrationError> {
        Self::initialize_inner().map_err(ReadObservedRegistrationError::InitializeCom)
    }

    fn initialize_for_list() -> Result<Self, ListObservedRegistrationsError> {
        Self::initialize_inner().map_err(ListObservedRegistrationsError::InitializeCom)
    }

    fn initialize_for_write() -> Result<Self, EnsureTaskRegistrationError> {
        Self::initialize_inner().map_err(EnsureTaskRegistrationError::InitializeCom)
    }

    fn initialize_for_start<E>() -> Result<Self, StartRegisteredTaskError<E>> {
        Self::initialize_inner().map_err(StartRegisteredTaskError::InitializeCom)
    }

    fn initialize_for_removal() -> Result<Self, ApplyTaskRemovalError> {
        Self::initialize_inner().map_err(ApplyTaskRemovalError::InitializeCom)
    }

    fn initialize_inner() -> Result<Self, HRESULT> {
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.is_ok() {
            Ok(Self { uninitialize: true })
        } else if result == RPC_E_CHANGED_MODE {
            Ok(Self {
                uninitialize: false,
            })
        } else {
            Err(result)
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.uninitialize {
            unsafe { CoUninitialize() };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use windows::Win32::Foundation::{E_ACCESSDENIED, S_FALSE};

    #[test]
    fn start_passes_the_process_session_and_reports_a_queued_instance() {
        for session_id in [1, 7, i32::MAX as u32] {
            for state in [TASK_STATE_RUNNING, TASK_STATE_QUEUED] {
                let cleared = Cell::new(false);
                let result = start_task_in_session(
                    session_id,
                    || {
                        cleared.set(true);
                        Ok::<(), ()>(())
                    },
                    |flags, session| {
                        assert!(cleared.get());
                        assert_eq!(flags, 6);
                        assert_eq!(
                            flags,
                            TASK_RUN_USE_SESSION_ID.0 | TASK_RUN_IGNORE_CONSTRAINTS.0
                        );
                        assert_eq!(session, session_id as i32);
                        Ok(state)
                    },
                );
                if state == TASK_STATE_QUEUED {
                    let error = StartRegisteredTaskError::<()>::Queued { session_id };
                    assert_eq!(error.to_string(), format!(
                        "Task Scheduler kept the runtime task in state Queued for session id {session_id}."
                    ));
                    assert_eq!(result, Err(error));
                } else {
                    assert_eq!(result, Ok(StartRegisteredTaskResult::Started));
                }
            }
        }
    }

    #[test]
    fn invalid_sessions_do_not_clear_the_crash_window_or_run_the_task() {
        for session_id in [0, i32::MAX as u32 + 1, u32::MAX] {
            let result = start_task_in_session::<()>(
                session_id,
                || panic!("The crash window must stay intact."),
                |_, _| panic!("The task must not run."),
            );
            assert_eq!(
                result,
                Err(StartRegisteredTaskError::InvalidProcessSession(session_id))
            );
        }
    }

    #[test]
    fn a_clear_failure_prevents_the_session_start() {
        let result =
            start_task_in_session(1, || Err("locked"), |_, _| panic!("The task must not run."));
        assert_eq!(
            result,
            Err(StartRegisteredTaskError::ClearCrashWindow("locked"))
        );
    }

    #[test]
    fn session_start_preserves_races_and_scheduler_errors() {
        for (error, expected) in [
            (
                StartRegisteredTaskError::RunTask(SCHED_E_ALREADY_RUNNING),
                Ok(StartRegisteredTaskResult::AlreadyRunning),
            ),
            (
                StartRegisteredTaskError::RunTask(E_ACCESSDENIED),
                Err(StartRegisteredTaskError::RunTask(E_ACCESSDENIED)),
            ),
            (
                StartRegisteredTaskError::ReadTaskState(E_ACCESSDENIED),
                Err(StartRegisteredTaskError::ReadTaskState(E_ACCESSDENIED)),
            ),
        ] {
            assert_eq!(
                start_task_in_session(1, || Ok::<(), ()>(()), |_, _| Err(error)),
                expected
            );
        }
    }

    #[test]
    fn s_false_from_stop_prevents_the_write() {
        let wrote = Cell::new(false);

        let result = after_successful_stop(S_FALSE, || {
            wrote.set(true);
            Ok(())
        });

        assert_eq!(result, Err(ApplyTaskRemovalError::StopTask(S_FALSE)));
        assert!(!wrote.get());
    }
}
