//! Live reads from the Windows Task Scheduler.

use crate::windows_task::{
    parse_observed_registration, task_uri, ObservedRegistration, ParseObservedRegistrationError,
    SidError,
};
use std::fmt;
use windows::core::{BSTR, HRESULT};
use windows::Win32::Foundation::RPC_E_CHANGED_MODE;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::TaskScheduler::{ITaskService, TaskScheduler};
use windows::Win32::System::Variant::VARIANT;

const TASK_FOLDER: &str = r"\Muniment";
const HRESULT_FILE_NOT_FOUND: HRESULT = HRESULT(0x8007_0002_u32 as i32);
const HRESULT_PATH_NOT_FOUND: HRESULT = HRESULT(0x8007_0003_u32 as i32);
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
        let result = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if result.is_ok() {
            Ok(Self { uninitialize: true })
        } else if result == RPC_E_CHANGED_MODE {
            Ok(Self {
                uninitialize: false,
            })
        } else {
            Err(ReadObservedRegistrationError::InitializeCom(result))
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
