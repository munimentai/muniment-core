//! Native browser process identity verification.

#[cfg(target_os = "linux")]
mod linux_identity;
#[cfg(target_os = "linux")]
mod linux_transport;
#[cfg(any(target_os = "macos", test))]
mod macos_identity;
#[cfg(target_os = "macos")]
mod macos_transport;
#[cfg(target_os = "windows")]
mod windows_identity;

#[cfg(target_os = "linux")]
pub use linux_identity::{
    authorize_browser_process, authorize_browser_process_with_readers, resolve_browser_process,
    resolve_browser_process_with_readers, verify_browser_process,
    verify_browser_process_with_reader, AuthorizationError, AuthorizedBrowserProcess,
    BrowserProcessIdentity, LinuxProcReader, LinuxSocketDiagnostic, ProcReadError, ProcReader,
    ResolutionError, SocketDiagnostic, VerificationError,
};
#[cfg(target_os = "linux")]
pub use linux_transport::{
    BrowserControlAcceptError, BrowserControlBindError, BrowserControlEndpointInspector,
    BrowserControlListener, BrowserControlPairingAuthorizer, BrowserControlProcessAuthorizer,
    BrowserControlStreamListener, LinuxBrowserProcessAuthorizer, PairingAuthorizationError,
    WebSocketHandshakeConfig, WebSocketHandshakeError,
};
#[cfg(target_os = "macos")]
pub use macos_transport::{
    BrowserControlAcceptError, BrowserControlBindError, BrowserControlEndpointInspector,
    BrowserControlListener, BrowserControlPairingAuthorizer, BrowserControlProcessAuthorizer,
    BrowserControlStreamListener, MacOsBrowserProcessAuthorizer, PairingAuthorizationError,
    WebSocketHandshakeConfig, WebSocketHandshakeError,
};

#[cfg(target_os = "macos")]
pub use macos_identity::{
    authorize_browser_process, authorize_browser_process_with_reader, resolve_browser_process,
    resolve_browser_process_with_reader, AuthorizationError, AuthorizedBrowserProcess,
    BrowserProcessIdentity, MacOsProcessReader, NativeProcessReader, ProcessReadError,
    ProcessSocket, ResolutionError, VerificationError,
};

#[cfg(target_os = "windows")]
pub use windows_identity::{
    authorize_browser_process, authorize_browser_process_with_reader, resolve_browser_process,
    resolve_browser_process_with_reader, verify_browser_process,
    verify_browser_process_with_reader, AuthorizationError, AuthorizedBrowserProcess,
    BrowserProcessIdentity, NativeProcessError, NativeReadError, ResolutionError, TcpConnection,
    VerificationError, WindowsIdentityReader, WindowsNativeReader,
};
