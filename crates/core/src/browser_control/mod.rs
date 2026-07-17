//! Native browser process identity verification.

#[cfg(target_os = "linux")]
mod linux_identity;

#[cfg(target_os = "linux")]
pub use linux_identity::{
    resolve_browser_process, resolve_browser_process_with_readers, verify_browser_process,
    verify_browser_process_with_reader, AuthorizedBrowserProcess, BrowserProcessIdentity,
    LinuxProcReader, LinuxSocketDiagnostic, ProcReadError, ProcReader, ResolutionError,
    SocketDiagnostic, VerificationError,
};
