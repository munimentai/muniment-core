use crate::desktop_client::DesktopClient;
use crate::desktop_client_holder::DesktopClientHolder;
use std::time::Duration;

pub trait DesktopClientSupervisorStop {
    fn stopped(&self) -> bool;

    fn register_holder(&self, holder: DesktopClientHolder) -> bool;

    fn notify_connected<P, N>(&self, publish: P, notify: N) -> bool
    where
        P: FnOnce(),
        N: FnOnce();

    fn wait_for_retry(&self, retry_interval: Duration) -> bool;
}

pub fn serve_desktop_client_with<S>(
    mut connect: impl FnMut() -> Option<DesktopClient>,
    stop: S,
    holder: DesktopClientHolder,
    retry_interval: Duration,
    mut observe: impl FnMut(bool),
) where
    S: DesktopClientSupervisorStop,
{
    if !stop.register_holder(holder.clone()) {
        return;
    }

    loop {
        if let Some(client) = connect() {
            let runtime_version = client.runtime_version().to_owned();
            let (held, wake) = &*holder.inner;
            if !stop.notify_connected(
                || {
                    *held.lock().unwrap_or_else(|error| error.into_inner()) = Some(client);
                    *holder
                        .runtime_version
                        .lock()
                        .unwrap_or_else(|error| error.into_inner()) = Some(runtime_version);
                },
                || observe(true),
            ) {
                return;
            }

            let connection = held.lock().unwrap_or_else(|error| error.into_inner());
            let mut connection = wake
                .wait_while(connection, |client| client.is_some() && !stop.stopped())
                .unwrap_or_else(|error| error.into_inner());
            *connection = None;
            *holder
                .runtime_version
                .lock()
                .unwrap_or_else(|error| error.into_inner()) = None;
            observe(false);
        }

        if !stop.wait_for_retry(retry_interval) {
            return;
        }
    }
}
