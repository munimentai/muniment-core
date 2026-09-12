fn main() {
    assert!(std::env::args_os().nth(1).is_none());
    #[cfg(target_os = "windows")]
    {
        let mut session_id = 0;
        assert_ne!(
            unsafe {
                windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId(
                    std::process::id(),
                    &mut session_id,
                )
            },
            0
        );
        let report = std::env::current_exe().unwrap().with_extension("session");
        std::fs::write(report, format!("{session_id}\n")).unwrap();
    }
    loop {
        std::thread::park();
    }
}
