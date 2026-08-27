#![cfg(target_os = "windows")]

use muniment_core::windows_sid::current_process_user_sid;
use muniment_core::windows_task::{
    render_task_definition_xml, SidError, TaskDefinition, TaskRegistrationPlan,
};
use muniment_core::windows_task_service::{
    ensure_task_registration, read_observed_registration, EnsureTaskRegistrationError,
    ReadObservedRegistrationError,
};
use std::path::PathBuf;
use windows::core::BSTR;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::TaskScheduler::{
    ITaskService, TaskScheduler, TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN,
};
use windows::Win32::System::Variant::VARIANT;

const TASK_FOLDER: &str = r"\Muniment";
const MACHINE_ROOT: &str = r"C:\MunimentTaskPreflight\Machine";
const USER_ROOT: &str = r"C:\MunimentTaskPreflight\User";
const PAYLOAD: &str = r"C:\MunimentTaskPreflight\User\muniment-runtime.exe";
const FOREIGN_PAYLOAD: &str = r"C:\MunimentTaskPreflight\Foreign\muniment-runtime.exe";

#[test]
fn absent_runtime_task_returns_none() {
    let observed = read_observed_registration("S-1-5-999999999").unwrap();

    assert_eq!(observed, None);
}

#[test]
fn non_canonical_sid_is_rejected_before_scheduler_access() {
    let error = read_observed_registration("S-1-05-21").unwrap_err();

    assert_eq!(
        error,
        ReadObservedRegistrationError::InvalidSid(SidError::NotCanonical)
    );
}

#[test]
fn registers_leaves_unchanged_and_refuses_a_foreign_task() {
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    assert_eq!(read_observed_registration(sid.as_str()).unwrap(), None);

    fixture.owns_task = true;
    assert_eq!(
        ensure_task_registration(sid.as_str(), PAYLOAD, MACHINE_ROOT, USER_ROOT).unwrap(),
        TaskRegistrationPlan::Register
    );
    assert_eq!(
        ensure_task_registration(sid.as_str(), PAYLOAD, MACHINE_ROOT, USER_ROOT).unwrap(),
        TaskRegistrationPlan::LeaveUnchanged
    );

    fixture.register_foreign_task(sid.as_str());
    assert_eq!(
        ensure_task_registration(sid.as_str(), PAYLOAD, MACHINE_ROOT, USER_ROOT),
        Err(EnsureTaskRegistrationError::Refused)
    );
    assert_eq!(
        read_observed_registration(sid.as_str())
            .unwrap()
            .unwrap()
            .action_path,
        PathBuf::from(FOREIGN_PAYLOAD)
    );
}

struct SchedulerFixture {
    service: ITaskService,
    task_name: String,
    owns_task: bool,
    remove_folder: bool,
    _apartment: TestComApartment,
}

impl SchedulerFixture {
    fn new(sid: &str) -> Self {
        let apartment = TestComApartment::new();
        let service: ITaskService =
            unsafe { CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).unwrap() };
        let empty = VARIANT::default();
        unsafe { service.Connect(&empty, &empty, &empty, &empty) }.unwrap();
        let remove_folder = unsafe { service.GetFolder(&BSTR::from(TASK_FOLDER)) }.is_err();

        Self {
            service,
            task_name: format!("Runtime-{sid}"),
            owns_task: false,
            remove_folder,
            _apartment: apartment,
        }
    }

    fn register_foreign_task(&self, sid: &str) {
        let definition = TaskDefinition::new(sid, FOREIGN_PAYLOAD).unwrap();
        let xml = render_task_definition_xml(&definition).unwrap();
        let task = unsafe { self.service.NewTask(0) }.unwrap();
        unsafe { task.SetXmlText(&BSTR::from(xml)) }.unwrap();
        let folder = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) }.unwrap();
        let empty = VARIANT::default();
        unsafe {
            folder.RegisterTaskDefinition(
                &BSTR::from(self.task_name.as_str()),
                &task,
                TASK_CREATE_OR_UPDATE.0,
                &empty,
                &empty,
                TASK_LOGON_INTERACTIVE_TOKEN,
                &empty,
            )
        }
        .unwrap();
    }
}

impl Drop for SchedulerFixture {
    fn drop(&mut self) {
        if self.owns_task {
            if let Ok(folder) = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
                let _ = unsafe { folder.DeleteTask(&BSTR::from(self.task_name.as_str()), 0) };
            }
        }
        if self.remove_folder {
            if let Ok(root) = unsafe { self.service.GetFolder(&BSTR::from(r"\")) } {
                let _ = unsafe { root.DeleteFolder(&BSTR::from("Muniment"), 0) };
            }
        }
    }
}

struct TestComApartment;

impl TestComApartment {
    fn new() -> Self {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.unwrap();
        Self
    }
}

impl Drop for TestComApartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}
