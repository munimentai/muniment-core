use crate::desktop_client_holder::DesktopClientHolder;
use crate::desktop_supervisor::DesktopClientSupervisorStop;
use std::fmt;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

pub(crate) type ShutdownHook = Box<dyn FnOnce() + Send>;

#[derive(Clone, Debug, Default)]
pub struct DesktopClientStopHandle {
    pub(crate) inner: Arc<(Mutex<DesktopClientStopState>, Condvar)>,
    notification: Arc<(Mutex<Option<std::thread::ThreadId>>, Condvar)>,
}

#[derive(Default)]
pub(crate) struct DesktopClientStopState {
    pub(crate) stopped: bool,
    shutdown: Option<ShutdownHook>,
    holder: Option<DesktopClientHolder>,
}

impl fmt::Debug for DesktopClientStopState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopClientStopState")
            .field("stopped", &self.stopped)
            .field("shutdown", &self.shutdown.is_some())
            .field("holder", &self.holder)
            .finish()
    }
}

impl DesktopClientStopState {
    pub(crate) fn set_shutdown(&mut self, shutdown: Option<ShutdownHook>) {
        self.shutdown = shutdown;
    }
}

impl DesktopClientStopHandle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stop(&self) {
        let current_thread = std::thread::current().id();
        let (notification, notification_wake) = &*self.notification;
        let notification = notification
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let _notification = notification_wake
            .wait_while(notification, |thread| {
                thread.is_some_and(|thread| thread != current_thread)
            })
            .unwrap_or_else(|error| error.into_inner());
        let (state, wake) = &*self.inner;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.stopped = true;
        if let Some(shutdown) = state.shutdown.take() {
            shutdown();
        }
        if let Some(holder) = state.holder.as_ref() {
            let (_, client_wake) = &*holder.inner;
            client_wake.notify_all();
        }
        wake.notify_all();
    }
}

impl DesktopClientSupervisorStop for DesktopClientStopHandle {
    fn stopped(&self) -> bool {
        let (state, _) = &*self.inner;
        state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .stopped
    }

    fn register_holder(&self, holder: DesktopClientHolder) -> bool {
        let (state, _) = &*self.inner;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        if state.stopped {
            return false;
        }
        state.holder = Some(holder);
        true
    }

    fn notify_connected<P, N>(&self, publish: P, notify: N) -> bool
    where
        P: FnOnce(),
        N: FnOnce(),
    {
        let (notification_lock, notification_wake) = &*self.notification;
        let mut notification = notification_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let (state, _) = &*self.inner;
        let state = state.lock().unwrap_or_else(|error| error.into_inner());
        if state.stopped {
            return false;
        }
        publish();
        *notification = Some(std::thread::current().id());
        drop(state);
        drop(notification);
        notify();
        let mut notification = notification_lock
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        *notification = None;
        notification_wake.notify_all();
        true
    }

    fn wait_for_retry(&self, retry_interval: Duration) -> bool {
        let (state, wake) = &*self.inner;
        let mut state = state.lock().unwrap_or_else(|error| error.into_inner());
        state.set_shutdown(None);
        if state.stopped {
            return false;
        }
        let (state, _) = wake
            .wait_timeout_while(state, retry_interval, |state| !state.stopped)
            .unwrap_or_else(|error| error.into_inner());
        !state.stopped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    #[test]
    fn stop_interrupts_retry_without_a_socket() {
        let stop = DesktopClientStopHandle::new();
        let waiting_stop = stop.clone();
        let (result_sender, result) = mpsc::channel();
        let waiter = std::thread::spawn(move || {
            result_sender
                .send(waiting_stop.wait_for_retry(Duration::from_secs(30)))
                .unwrap();
        });

        stop.stop();

        assert!(!result.recv_timeout(Duration::from_secs(1)).unwrap());
        assert!(!stop.wait_for_retry(Duration::ZERO));
        waiter.join().unwrap();
    }
}
