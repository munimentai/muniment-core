#![cfg(target_os = "windows")]

use muniment_core::windows_known_folders::windows_payload_roots;
use muniment_core::windows_payload::resolve_live_windows_payload;
use muniment_core::windows_sid::current_process_user_sid;
use muniment_core::windows_task::{
    render_task_definition_xml, SidError, TaskDefinition, TaskRegistrationPlan,
};
use muniment_core::windows_task_service::{
    ensure_live_task_registration, ensure_task_registration, list_observed_registrations,
    read_observed_registration, start_registered_task, EnsureLiveTaskRegistrationError,
    EnsureTaskRegistrationError, ReadObservedRegistrationError, StartRegisteredTaskError,
    StartRegisteredTaskResult,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
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
static SCHEDULER_TEST_LOCK: Mutex<()> = Mutex::new(());

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
fn live_registration_rejects_an_absent_payload_without_writing_a_task() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    fixture.owns_task = true;
    assert_eq!(read_observed_registration(sid.as_str()).unwrap(), None);

    let result = ensure_live_task_registration();

    assert_eq!(
        result,
        Err(EnsureLiveTaskRegistrationError::NoInstalledPayload)
    );
    assert_eq!(read_observed_registration(sid.as_str()).unwrap(), None);
}

#[test]
fn live_registration_uses_the_resolved_payload() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    fixture.owns_task = true;
    assert_eq!(read_observed_registration(sid.as_str()).unwrap(), None);

    let roots = windows_payload_roots().unwrap();
    let payload = roots
        .local_app_data
        .join("muniment")
        .join("muniment-runtime.exe");
    let payload_directory = payload.parent().unwrap();
    if !payload_directory.exists() {
        std::fs::create_dir_all(payload_directory).unwrap();
        fixture.payload_directory = Some(payload_directory.to_owned());
    }
    if std::fs::symlink_metadata(&payload)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&payload)
            .unwrap();
        fixture.payload = Some(payload);
    }
    let resolved = resolve_live_windows_payload().unwrap().unwrap();

    ensure_live_task_registration().unwrap();

    assert_eq!(
        read_observed_registration(sid.as_str())
            .unwrap()
            .unwrap()
            .action_path,
        resolved.payload_path
    );
}

#[test]
fn registers_leaves_unchanged_and_refuses_a_foreign_task() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
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

#[test]
fn lists_a_registered_runtime_task_until_it_is_removed() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let uri = format!(r"\Muniment\Runtime-{}", sid.as_str());

    {
        let mut fixture = SchedulerFixture::new(sid.as_str());
        fixture.owns_task = true;
        fixture.register_task(sid.as_str(), Path::new(PAYLOAD));
        let registrations = list_observed_registrations().unwrap();

        assert!(registrations
            .iter()
            .any(|registration| registration.uri == uri));
    }

    let registrations = list_observed_registrations().unwrap();
    assert!(registrations
        .iter()
        .all(|registration| registration.uri != uri));
}

#[test]
fn starting_an_absent_task_does_not_clear_the_crash_window() {
    let mut cleared = false;
    let result = start_registered_task("S-1-5-999999999", || {
        cleared = true;
        Ok::<(), ()>(())
    });

    assert_eq!(result, Err(StartRegisteredTaskError::Missing));
    assert!(!cleared);
}

#[test]
fn starting_a_foreign_task_is_refused_without_clearing_the_crash_window() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    fixture.owns_task = true;
    fixture.register_task(sid.as_str(), Path::new(FOREIGN_PAYLOAD));
    let mut cleared = false;

    let result = start_registered_task(sid.as_str(), || {
        cleared = true;
        Ok::<(), ()>(())
    });

    assert_eq!(result, Err(StartRegisteredTaskError::Refused));
    assert!(!cleared);
}

#[test]
fn starts_a_registered_task_that_exits_at_once() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    let payload = runtime_payload_path();
    let system_root = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
    std::fs::copy(system_root.join("System32").join("where.exe"), &payload).unwrap();
    fixture.payload = Some(payload.clone());
    fixture.owns_task = true;
    fixture.register_task(sid.as_str(), &payload);
    let mut clear_count = 0;

    let result = start_registered_task(sid.as_str(), || {
        clear_count += 1;
        Ok::<(), ()>(())
    });

    assert_eq!(result, Ok(StartRegisteredTaskResult::Started));
    assert_eq!(clear_count, 1);
    fixture.wait_until_task_stops();
}

fn runtime_payload_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.set_file_name("muniment-runtime.exe");
    path
}

struct SchedulerFixture {
    service: ITaskService,
    task_name: String,
    owns_task: bool,
    remove_folder: bool,
    payload: Option<PathBuf>,
    payload_directory: Option<PathBuf>,
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
            payload: None,
            payload_directory: None,
            _apartment: apartment,
        }
    }

    fn register_foreign_task(&self, sid: &str) {
        self.register_task(sid, Path::new(FOREIGN_PAYLOAD));
    }

    fn register_task(&self, sid: &str, payload: &Path) {
        let definition = TaskDefinition::new(sid, payload).unwrap();
        let xml = render_task_definition_xml(&definition).unwrap();
        let task = unsafe { self.service.NewTask(0) }.unwrap();
        unsafe { task.SetXmlText(&BSTR::from(xml)) }.unwrap();
        let empty = VARIANT::default();
        let folder = match unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
            Ok(folder) => folder,
            Err(_) => {
                let root = unsafe { self.service.GetFolder(&BSTR::from(r"\")) }.unwrap();
                unsafe { root.CreateFolder(&BSTR::from("Muniment"), &empty) }.unwrap()
            }
        };
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

    fn wait_until_task_stops(&self) {
        let folder = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) }.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let task = unsafe { folder.GetTask(&BSTR::from(self.task_name.as_str())) }.unwrap();
            if unsafe { task.State() }.unwrap()
                != windows::Win32::System::TaskScheduler::TASK_STATE_RUNNING
            {
                return;
            }
            assert!(Instant::now() < deadline, "the test task did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
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
        if let Some(payload) = &self.payload {
            let _ = std::fs::remove_file(payload);
        }
        if let Some(payload_directory) = &self.payload_directory {
            let _ = std::fs::remove_dir(payload_directory);
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
