//! Unix termination signal wait.

use std::io;

/// This wait handles `SIGTERM` and `SIGINT` synchronously.
pub struct TerminationSignalWait {
    signals: libc::sigset_t,
}

impl TerminationSignalWait {
    /// Creates a wait and blocks both signals on this thread.
    pub fn new() -> io::Result<Self> {
        let mut signals = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut signals) } != 0
            || unsafe { libc::sigaddset(&mut signals, libc::SIGTERM) } != 0
            || unsafe { libc::sigaddset(&mut signals, libc::SIGINT) } != 0
        {
            return Err(io::Error::last_os_error());
        }
        let mask_result =
            unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut()) };
        if mask_result != 0 {
            return Err(io::Error::from_raw_os_error(mask_result));
        }

        Ok(Self { signals })
    }

    /// Blocks until this thread receives either signal.
    pub fn wait(self) -> io::Result<()> {
        let mut signal = 0;
        let wait_result = unsafe { libc::sigwait(&self.signals, &mut signal) };
        if wait_result != 0 {
            return Err(io::Error::from_raw_os_error(wait_result));
        }
        Ok(())
    }
}
