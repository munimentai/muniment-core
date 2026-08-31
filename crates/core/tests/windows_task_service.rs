#![cfg(target_os = "windows")]

use muniment_core::windows_known_folders::windows_payload_roots;
use muniment_core::windows_payload::resolve_live_windows_payload;
use muniment_core::windows_sid::current_process_user_sid;
use muniment_core::windows_task::{
    render_task_definition_xml, RemovalScope, SidError, TaskDefinition, TaskRegistrationPlan,
    TaskRemovalPlan,
};
use muniment_core::windows_task_service::{
    apply_task_removal, ensure_live_task_registration, ensure_task_registration,
    list_observed_registrations, read_observed_registration, start_registered_task,
    EnsureLiveTaskRegistrationError, EnsureTaskRegistrationError, ReadObservedRegistrationError,
    StartRegisteredTaskError, StartRegisteredTaskResult,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};
use windows::core::BSTR;
use windows::Win32::Foundation::SCHED_E_TASK_NOT_RUNNING;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::TaskScheduler::{
    IRunningTask, ITaskService, TaskScheduler, TASK_CREATE_OR_UPDATE, TASK_LOGON_INTERACTIVE_TOKEN,
    TASK_LOGON_SERVICE_ACCOUNT, TASK_LOGON_TYPE, TASK_RUN_IGNORE_CONSTRAINTS, TASK_STATE_RUNNING,
};
use windows::Win32::System::Variant::VARIANT;

const TASK_FOLDER: &str = r"\Muniment";
const SERVICE_ACCOUNT_SID: &str = "S-1-5-18";
const TEST_ROOT: &str = r"C:\MunimentTaskPreflight";
const MACHINE_ROOT: &str = r"C:\MunimentTaskPreflight\Machine";
const USER_ROOT: &str = r"C:\MunimentTaskPreflight\User";
const PAYLOAD: &str = r"C:\MunimentTaskPreflight\User\muniment-runtime.exe";
const MACHINE_PAYLOAD: &str = r"C:\MunimentTaskPreflight\Machine\muniment-runtime.exe";
const FOREIGN_PAYLOAD: &str = r"C:\MunimentTaskPreflight\Foreign\muniment-runtime.exe";
const COM_HANDLER_CLASS_ID: &str = "{00000000-0000-0000-0000-000000000001}";
const COM_HANDLER_DATA: &str = "preserve-this-action";
static SCHEDULER_TEST_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn absent_runtime_task_returns_none_without_a_write() {
    let sid = "S-1-5-999999999";
    let observed = read_observed_registration(sid).unwrap();
    let scope = RemovalScope::PerUser {
        user_sid: sid.to_owned(),
        payload_path: PathBuf::from(PAYLOAD),
        machine_payload_path: None,
    };

    assert_eq!(observed, None);
    assert_eq!(
        apply_task_removal(sid, &scope).unwrap(),
        TaskRemovalPlan::LeaveUnchanged
    );
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
fn writes_registration_and_applies_each_removal_plan() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    assert_eq!(read_observed_registration(sid.as_str()).unwrap(), None);

    fixture.owns_task = true;
    assert_eq!(
        ensure_task_registration(sid.as_str(), PAYLOAD, MACHINE_ROOT, USER_ROOT).unwrap(),
        TaskRegistrationPlan::Register
    );
    fixture.register_mixed_task(sid.as_str());

    let per_user_scope = RemovalScope::PerUser {
        user_sid: sid.as_str().to_owned(),
        payload_path: PathBuf::from(PAYLOAD),
        machine_payload_path: Some(PathBuf::from(MACHINE_PAYLOAD)),
    };
    let mut expected_repointed = read_observed_registration(sid.as_str()).unwrap().unwrap();
    expected_repointed.action_path = PathBuf::from(MACHINE_PAYLOAD);
    assert_eq!(
        apply_task_removal(sid.as_str(), &per_user_scope).unwrap(),
        TaskRemovalPlan::RepointTo(PathBuf::from(MACHINE_PAYLOAD))
    );
    assert_eq!(
        read_observed_registration(sid.as_str()).unwrap().unwrap(),
        expected_repointed
    );
    let repointed_xml = fixture.task_xml();
    assert!(repointed_xml.contains(COM_HANDLER_CLASS_ID));
    assert!(repointed_xml.contains(COM_HANDLER_DATA));
    fixture.register_machine_task();

    let machine_scope = RemovalScope::Machine {
        payload_path: PathBuf::from(MACHINE_PAYLOAD),
        per_user_payload_path: None,
    };
    let running_task = fixture.start_controlled_task();
    assert_eq!(
        apply_task_removal(SERVICE_ACCOUNT_SID, &machine_scope).unwrap(),
        TaskRemovalPlan::StopAndDelete
    );
    // IRegisteredTask::Stop returns once the stop request is accepted and the
    // instance tears down asynchronously, so the stop is observed by deadline.
    // IRunningTask properties are snapshots, so each read needs a Refresh,
    // and Refresh on a torn-down instance reports SCHED_E_TASK_NOT_RUNNING.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match unsafe { running_task.Refresh() }.and_then(|()| unsafe { running_task.State() }) {
            Ok(state) if state != TASK_STATE_RUNNING => break,
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.code(), SCHED_E_TASK_NOT_RUNNING);
                break;
            }
        }
        assert!(
            Instant::now() < deadline,
            "the controlled task did not stop"
        );
        thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        read_observed_registration(SERVICE_ACCOUNT_SID).unwrap(),
        None
    );
    assert!(unsafe { fixture.service.GetFolder(&BSTR::from(TASK_FOLDER)) }.is_err());

    fixture.task_name = format!("Runtime-{}", sid.as_str());
    assert_eq!(
        ensure_task_registration(sid.as_str(), PAYLOAD, MACHINE_ROOT, USER_ROOT).unwrap(),
        TaskRegistrationPlan::Register
    );
    fixture.register_foreign_task(sid.as_str());
    let foreign = read_observed_registration(sid.as_str()).unwrap().unwrap();
    assert_eq!(foreign.action_path, PathBuf::from(FOREIGN_PAYLOAD));
    assert_eq!(
        apply_task_removal(sid.as_str(), &per_user_scope).unwrap(),
        TaskRemovalPlan::LeaveUnchanged
    );
    assert_eq!(
        read_observed_registration(sid.as_str()).unwrap().unwrap(),
        foreign
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
    let result = start_registered_task("S-1-5-999999999", runtime_payload_path(), || {
        cleared = true;
        Ok::<(), ()>(())
    });

    assert_eq!(result, Err(StartRegisteredTaskError::Missing));
    assert!(!cleared);
}

#[test]
fn starting_with_a_non_matching_expected_payload_is_refused_without_clearing_the_crash_window() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    fixture.owns_task = true;
    fixture.register_task(sid.as_str(), Path::new(FOREIGN_PAYLOAD));
    let mut cleared = false;

    let result = start_registered_task(sid.as_str(), runtime_payload_path(), || {
        cleared = true;
        Ok::<(), ()>(())
    });

    assert_eq!(result, Err(StartRegisteredTaskError::Refused));
    assert!(!cleared);
}

#[test]
fn starts_a_registered_task_with_a_matching_expected_payload_outside_the_test_directory() {
    let _guard = SCHEDULER_TEST_LOCK.lock().unwrap();
    let sid = current_process_user_sid().unwrap();
    let mut fixture = SchedulerFixture::new(sid.as_str());
    let payload = runtime_payload_path();
    let test_executable = std::env::current_exe().unwrap();
    assert_ne!(payload.parent(), test_executable.parent());
    let payload_directory = payload.parent().unwrap();
    std::fs::create_dir_all(payload_directory).unwrap();
    fixture.payload_directory = Some(payload_directory.to_owned());
    let system_root = PathBuf::from(std::env::var_os("SystemRoot").unwrap());
    std::fs::copy(system_root.join("System32").join("where.exe"), &payload).unwrap();
    fixture.payload = Some(payload.clone());
    fixture.owns_task = true;
    fixture.register_task(sid.as_str(), &payload);
    let mut clear_count = 0;

    let result = start_registered_task(sid.as_str(), &payload, || {
        clear_count += 1;
        Ok::<(), ()>(())
    });

    assert_eq!(result, Ok(StartRegisteredTaskResult::Started));
    assert_eq!(clear_count, 1);
    fixture.wait_until_task_stops();
}

fn runtime_payload_path() -> PathBuf {
    std::env::temp_dir()
        .join(format!("muniment-task-service-{}", std::process::id()))
        .join("muniment-runtime.exe")
}

struct SchedulerFixture {
    service: ITaskService,
    task_name: String,
    owns_task: bool,
    remove_folder: bool,
    remove_test_root: bool,
    remove_machine_root: bool,
    remove_machine_payload: bool,
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
            remove_test_root: false,
            remove_machine_root: false,
            remove_machine_payload: false,
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
        self.register_xml(
            render_task_definition_xml(&definition).unwrap(),
            TASK_LOGON_INTERACTIVE_TOKEN,
        );
    }

    fn register_mixed_task(&self, sid: &str) {
        let definition = TaskDefinition::new(sid, PAYLOAD).unwrap();
        let xml = render_task_definition_xml(&definition).unwrap();
        let exec_start = "  <Actions Context=\"Author\">\n    <Exec>";
        let mixed_start = format!(
            "  <Actions Context=\"Author\">\n    <ComHandler>\n      <ClassId>{COM_HANDLER_CLASS_ID}</ClassId>\n      <Data>{COM_HANDLER_DATA}</Data>\n    </ComHandler>\n    <Exec>"
        );
        let xml = xml.replacen(exec_start, &mixed_start, 1);
        assert_ne!(xml, render_task_definition_xml(&definition).unwrap());
        self.register_xml(xml, TASK_LOGON_INTERACTIVE_TOKEN);
    }

    fn register_machine_task(&mut self) {
        let folder = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) }.unwrap();
        unsafe { folder.DeleteTask(&BSTR::from(self.task_name.as_str()), 0) }.unwrap();
        self.task_name = format!("Runtime-{SERVICE_ACCOUNT_SID}");

        self.remove_test_root = !Path::new(TEST_ROOT).exists();
        self.remove_machine_root = !Path::new(MACHINE_ROOT).exists();
        std::fs::create_dir_all(MACHINE_ROOT).unwrap();
        assert!(!Path::new(MACHINE_PAYLOAD).exists());
        self.remove_machine_payload = true;
        std::fs::copy(
            env!("CARGO_BIN_EXE_windows-task-test-helper"),
            MACHINE_PAYLOAD,
        )
        .unwrap();

        let mut definition = TaskDefinition::new(SERVICE_ACCOUNT_SID, MACHINE_PAYLOAD).unwrap();
        definition.triggers.clear();
        let xml = render_task_definition_xml(&definition).unwrap();
        self.register_xml(xml, TASK_LOGON_SERVICE_ACCOUNT);
    }

    fn register_xml(&self, xml: String, logon_type: TASK_LOGON_TYPE) {
        let task = unsafe { self.service.NewTask(0) }.unwrap();
        unsafe { task.SetXmlText(&BSTR::from(xml)) }.unwrap();
        let principal = unsafe { task.Principal() }.unwrap();
        unsafe { principal.SetLogonType(logon_type) }.unwrap();
        let empty = VARIANT::default();
        let user_id = if logon_type == TASK_LOGON_SERVICE_ACCOUNT {
            VARIANT::from("SYSTEM")
        } else {
            VARIANT::default()
        };
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
                &user_id,
                &empty,
                logon_type,
                &empty,
            )
        }
        .unwrap();
    }

    fn task_xml(&self) -> String {
        let folder = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) }.unwrap();
        let task = unsafe { folder.GetTask(&BSTR::from(self.task_name.as_str())) }.unwrap();
        String::try_from(&unsafe { task.Xml() }.unwrap()).unwrap()
    }

    fn start_controlled_task(&mut self) -> IRunningTask {
        let folder = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) }.unwrap();
        let task = unsafe { folder.GetTask(&BSTR::from(self.task_name.as_str())) }.unwrap();
        // The CI image never satisfies the scheduler's launch-condition
        // evaluation (a plain Run and even trigger firings park every task
        // instance in TASK_STATE_QUEUED), so the controlled start must tell
        // the engine to skip that evaluation.
        let running = unsafe {
            task.RunEx(
                &VARIANT::default(),
                TASK_RUN_IGNORE_CONSTRAINTS.0,
                0,
                &BSTR::new(),
            )
        }
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match unsafe { running.Refresh() }.and_then(|()| unsafe { running.State() }) {
                Ok(state) if state == TASK_STATE_RUNNING => return running,
                Ok(_) => {}
                Err(error) if error.code() == SCHED_E_TASK_NOT_RUNNING => {}
                Err(error) => panic!("could not read the controlled task state: {error}"),
            }
            if Instant::now() >= deadline {
                let state = unsafe { task.State() };
                let last_task_result = unsafe { task.LastTaskResult() };
                let last_run_time = unsafe { task.LastRunTime() };
                panic!(
                    "the controlled task did not start: State={state:?}, LastTaskResult={last_task_result:?}, LastRunTime={last_run_time:?}"
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn wait_until_task_stops(&self) {
        let folder = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) }.unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let task = unsafe { folder.GetTask(&BSTR::from(self.task_name.as_str())) }.unwrap();
            if unsafe { task.State() }.unwrap() != TASK_STATE_RUNNING {
                return;
            }
            assert!(Instant::now() < deadline, "the test task did not stop");
            thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for SchedulerFixture {
    fn drop(&mut self) {
        if self.owns_task {
            if let Ok(folder) = unsafe { self.service.GetFolder(&BSTR::from(TASK_FOLDER)) } {
                if let Ok(task) = unsafe { folder.GetTask(&BSTR::from(self.task_name.as_str())) } {
                    let _ = unsafe { task.Stop(0) };
                }
                let _ = unsafe { folder.DeleteTask(&BSTR::from(self.task_name.as_str()), 0) };
            }
        }
        if self.remove_machine_payload {
            let _ = std::fs::remove_file(MACHINE_PAYLOAD);
        }
        if self.remove_machine_root {
            let _ = std::fs::remove_dir(MACHINE_ROOT);
        }
        if self.remove_test_root {
            let _ = std::fs::remove_dir(TEST_ROOT);
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
