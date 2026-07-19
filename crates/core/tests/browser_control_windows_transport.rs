#![cfg(target_os = "windows")]

// The platform-neutral contract suite exercises the exact transport composed on Windows.
#[path = "browser_control_linux_transport.rs"]
mod shared_transport_contract;
