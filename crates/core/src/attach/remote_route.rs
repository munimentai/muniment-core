//! The remote listener as the runtime's settings direct it.
//!
//! A host opens remote access, hands the route a function that serves a
//! bound listener, and calls `apply`. The route then binds, serves, stops and
//! rebinds the listener whenever the settings change, without a restart, and
//! keeps the endpoints pairing links name current.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use muniment_attach::ProtocolError;
use serde_json::{json, Value};

use super::remote_access::{RemoteAccess, RemoteAccessOptions};
use super::remote_listener::{RemoteListener, RemoteListenerConfig, RemoteListenerError};
use super::remote_settings::{
    advertised_endpoints, interface_addresses, load_remote_settings, remove_listener_status,
    save_remote_settings, write_listener_status, AdvertisedEndpoint, RemoteAccessSettings,
    RemoteListenerStatus, RemoteSettingsOverrides,
};

/// Serves one bound listener with the runtime's attach service until the
/// receiver fires or its sender drops.
pub type RemoteServe = Arc<
    dyn Fn(RemoteListener, RemoteAccess, Receiver<()>) -> Result<(), RemoteListenerError>
        + Send
        + Sync,
>;

/// Lists this machine's interface addresses. Tests replace it.
pub type InterfaceSource = Arc<dyn Fn() -> Vec<IpAddr> + Send + Sync>;

/// What a host passes to start its remote route.
#[derive(Clone, Debug)]
pub struct RemoteRouteOptions {
    pub access: RemoteAccessOptions,
    pub overrides: RemoteSettingsOverrides,
}

/// The listener's live state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteRouteStatus {
    /// The stored settings, before the host's overrides.
    pub settings: RemoteAccessSettings,
    /// Whether the host overrides any stored setting.
    pub overridden: bool,
    /// The address the listener bound, while it serves.
    pub listening: Option<SocketAddr>,
    /// The endpoints new pairing links name.
    pub endpoints: Vec<AdvertisedEndpoint>,
    /// Why the listener is not serving although the settings turn it on.
    pub error: Option<String>,
}

/// The runtime's remote listener, started and stopped to match its settings.
pub struct RemoteRoute {
    access: RemoteAccess,
    overrides: RemoteSettingsOverrides,
    serve: RemoteServe,
    interfaces: InterfaceSource,
    state: Mutex<RouteState>,
}

#[derive(Default)]
struct RouteState {
    stored: RemoteAccessSettings,
    effective: RemoteAccessSettings,
    running: Option<Running>,
    error: Option<String>,
}

struct Running {
    requested: Option<SocketAddr>,
    allow_public: bool,
    bound: SocketAddr,
    stop: Sender<()>,
    thread: JoinHandle<()>,
}

impl RemoteRoute {
    /// A route that serves nothing until `apply` reads the settings.
    pub fn new(
        access: RemoteAccess,
        overrides: RemoteSettingsOverrides,
        serve: RemoteServe,
    ) -> Self {
        Self {
            access,
            overrides,
            serve,
            interfaces: Arc::new(interface_addresses),
            state: Mutex::new(RouteState::default()),
        }
    }

    /// Replaces the interface list the endpoints come from.
    pub fn with_interfaces(mut self, interfaces: InterfaceSource) -> Self {
        self.interfaces = interfaces;
        self
    }

    pub fn access(&self) -> &RemoteAccess {
        &self.access
    }

    /// Reads the stored settings and starts, stops or rebinds the listener to
    /// match them. A listener that keeps its address keeps its connections.
    pub fn apply(&self) -> RemoteRouteStatus {
        let mut state = self.lock();
        match load_remote_settings(self.access.directory()) {
            Ok(stored) => {
                state.effective = self.overrides.apply(stored.clone());
                state.stored = stored;
                state.error = None;
            }
            Err(error) => {
                crate::runtime_eprintln!(
                    "muniment-runtime: remote access settings unreadable reason={error}"
                );
                state.stored = RemoteAccessSettings::default();
                state.effective = RemoteAccessSettings::default();
                state.error = Some("The remote access settings could not be read.".into());
            }
        }
        let desired = state.effective.enabled.then_some(state.effective.listen);
        if state.running.as_ref().is_some_and(|running| {
            Some(running.requested) != desired
                || running.allow_public != state.effective.allow_public
        }) {
            stop_running(&mut state);
        }
        if let (Some(requested), None) = (desired, state.running.as_ref()) {
            match self.start(requested, &state.effective) {
                Ok(running) => state.running = Some(running),
                Err(error) => state.error = Some(error),
            }
        }
        self.publish(&mut state)
    }

    /// Stores `settings` and applies them.
    pub fn save(&self, settings: RemoteAccessSettings) -> Result<RemoteRouteStatus, ProtocolError> {
        settings.validate()?;
        save_remote_settings(self.access.directory(), &settings)
            .map_err(|_| ProtocolError::persistence_failed())?;
        Ok(self.apply())
    }

    /// The live state, with the endpoints listed again from the interfaces.
    pub fn status(&self) -> RemoteRouteStatus {
        let mut state = self.lock();
        self.publish(&mut state)
    }

    /// Stops the listener and closes its connections. A later `apply`
    /// starts it again.
    pub fn stop(&self) {
        let mut state = self.lock();
        if state.running.is_some() {
            stop_running(&mut state);
            self.publish(&mut state);
        }
    }

    /// The `remote.settings` answer: the stored settings, the runtime's id
    /// and certificate fingerprint, and the listener's live state.
    pub fn describe(&self) -> Value {
        let status = self.status();
        let info = self.access.runtime_info();
        json!({
            "settings": status.settings,
            "overridden": status.overridden,
            "runtime_id": info.runtime_id,
            "runtime_name": info.runtime_name,
            "certificate_sha256": self.access.certificate_fingerprint().to_hex(),
            "listening": status.listening.map(|address| address.to_string()),
            "endpoints": status.endpoints,
            "error": status.error,
        })
    }

    fn start(
        &self,
        requested: Option<SocketAddr>,
        settings: &RemoteAccessSettings,
    ) -> Result<Running, String> {
        let mut failure = None;
        for address in settings.listen_candidates() {
            let mut config = RemoteListenerConfig::new(address);
            config.allow_public = settings.allow_public;
            let listener = match RemoteListener::bind(config) {
                Ok(listener) => listener,
                Err(error) => {
                    crate::runtime_eprintln!(
                        "muniment-runtime: remote access bind failed address={address} reason={error}"
                    );
                    failure = Some(format!("The listener could not bind {address}: {error}"));
                    continue;
                }
            };
            let bound = listener.local_addr().map_err(|error| error.to_string())?;
            let (stop, stopped) = mpsc::channel();
            let serve = Arc::clone(&self.serve);
            let access = self.access.clone();
            let thread = std::thread::Builder::new()
                .name("muniment-remote-listener".into())
                .spawn(move || {
                    if let Err(error) = serve(listener, access, stopped) {
                        crate::runtime_eprintln!(
                            "muniment-runtime: remote access listener ended reason={error}"
                        );
                    }
                })
                .map_err(|error| error.to_string())?;
            crate::runtime_eprintln!(
                "muniment-runtime: remote access listening address={bound} runtime_id={} fingerprint={}",
                self.access.runtime_info().runtime_id,
                self.access.certificate_fingerprint()
            );
            return Ok(Running {
                requested,
                allow_public: settings.allow_public,
                bound,
                stop,
                thread,
            });
        }
        Err(failure.unwrap_or_else(|| "The listener has no address to bind.".into()))
    }

    /// Sets the endpoints pairing links name and publishes them for
    /// commands in other processes.
    fn publish(&self, state: &mut RouteState) -> RemoteRouteStatus {
        let directory = self.access.directory();
        let endpoints = match &state.running {
            Some(running) => {
                let endpoints = advertised_endpoints(
                    &state.effective.endpoints,
                    running.bound,
                    &(self.interfaces)(),
                    state.effective.allow_public,
                );
                let listed = endpoints
                    .iter()
                    .map(|endpoint| endpoint.endpoint.clone())
                    .collect();
                if self.access.set_advertised_endpoints(listed).is_err() {
                    state.error = Some("The advertised endpoints are invalid.".into());
                }
                log_failure(write_listener_status(
                    directory,
                    &RemoteListenerStatus {
                        listen: running.bound,
                        endpoints: endpoints.clone(),
                    },
                ));
                endpoints
            }
            None => {
                let _ = self.access.set_advertised_endpoints(Vec::new());
                log_failure(remove_listener_status(directory));
                Vec::new()
            }
        };
        RemoteRouteStatus {
            settings: state.stored.clone(),
            overridden: !self.overrides.is_empty(),
            listening: state.running.as_ref().map(|running| running.bound),
            endpoints,
            error: state.error.clone(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RouteState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Drop for RemoteRoute {
    fn drop(&mut self) {
        self.stop();
    }
}

fn stop_running(state: &mut RouteState) {
    if let Some(running) = state.running.take() {
        let _ = running.stop.send(());
        let _ = running.thread.join();
        crate::runtime_eprintln!(
            "muniment-runtime: remote access stopped address={}",
            running.bound
        );
    }
}

fn log_failure(result: io::Result<()>) {
    if let Err(error) = result {
        crate::runtime_eprintln!(
            "muniment-runtime: remote access status file failed reason={error}"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::time::Duration;

    use muniment_attach::{
        connect_pinned, pair_with_link, InstallKind, RemoteClientOptions, RemoteConnectError,
    };

    use super::super::remote_settings::{read_listener_status, EndpointKind};
    use super::super::thread_service::{ThreadListPage, ThreadListRequest};
    use super::super::{PairingLinkRequest, SignedWorkspaceApproval};
    use super::*;

    struct Directory(std::path::PathBuf);

    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn route(overrides: RemoteSettingsOverrides) -> (RemoteRoute, Directory) {
        let directory = Directory(
            std::env::temp_dir().join(format!("muniment-remote-route-{}", uuid::Uuid::now_v7())),
        );
        let access = RemoteAccess::open(
            directory.0.join("remote"),
            RemoteAccessOptions {
                runtime_name: Some("Route box".into()),
                runtime_version: "1.0.0".into(),
                install_kind: InstallKind::Server,
            },
        )
        .unwrap();
        let serve: RemoteServe = Arc::new(|listener, access, stop| {
            listener.serve(
                access,
                SignedWorkspaceApproval::default(),
                || {
                    Ok::<_, ()>(|_: &str, _: ThreadListRequest| {
                        Ok(ThreadListPage {
                            threads: vec![],
                            next_cursor: None,
                        })
                    })
                },
                stop,
            )
        });
        let route = RemoteRoute::new(access, overrides, serve)
            .with_interfaces(Arc::new(|| vec!["192.0.2.30".parse().unwrap()]));
        (route, directory)
    }

    fn on(listen: &str, endpoints: &[&str]) -> RemoteAccessSettings {
        RemoteAccessSettings {
            enabled: true,
            listen: Some(listen.parse().unwrap()),
            endpoints: endpoints.iter().map(|e| (*e).to_owned()).collect(),
            allow_public: false,
        }
    }

    fn options() -> RemoteClientOptions {
        RemoteClientOptions {
            kind: "cli".into(),
            version: "1.0.0".into(),
            device_name: None,
            scopes: None,
            io_timeout: Duration::from_secs(5),
        }
    }

    fn reaches(route: &RemoteRoute, address: SocketAddr) -> Result<(), RemoteConnectError> {
        let loopback = SocketAddr::new([127, 0, 0, 1].into(), address.port());
        connect_pinned(
            &[loopback.to_string()],
            route.access().certificate_fingerprint(),
            Duration::from_secs(2),
        )
        .map(|mut stream| stream.close())
    }

    #[test]
    fn a_settings_change_starts_stops_and_rebinds_the_listener_without_a_restart() {
        let (route, directory) = route(RemoteSettingsOverrides::default());
        let remote = directory.0.join("remote");
        let status = route.apply();
        assert_eq!(status.listening, None);
        assert!(!status.settings.enabled);
        assert!(route.access().advertised_endpoints().is_empty());

        let status = route.save(on("127.0.0.1:0", &[])).unwrap();
        let first = status.listening.unwrap();
        assert_eq!(
            status.endpoints,
            vec![AdvertisedEndpoint {
                endpoint: first.to_string(),
                kind: EndpointKind::Loopback,
            }]
        );
        assert_eq!(
            read_listener_status(&remote).unwrap().unwrap().listen,
            first
        );
        let link = route
            .access()
            .create_pairing_link(PairingLinkRequest::default())
            .unwrap()
            .link;
        assert_eq!(link.endpoints, vec![first.to_string()]);
        let (_, record) = pair_with_link(&link, &options()).unwrap();
        assert_eq!(record.endpoints, vec![first.to_string()]);

        // Saving the same address keeps the listener and its port.
        let status = route.save(on("127.0.0.1:0", &[])).unwrap();
        assert_eq!(status.listening, Some(first));

        // A new address rebinds. The interface list holds a public address
        // alone, which links name only once public access is on.
        let status = route.save(on("0.0.0.0:0", &[])).unwrap();
        let private_only = status.listening.unwrap();
        assert_ne!(private_only.port(), first.port());
        assert!(status.endpoints.is_empty());
        let status = route
            .save(RemoteAccessSettings {
                allow_public: true,
                ..on("0.0.0.0:0", &[])
            })
            .unwrap();
        let second = status.listening.unwrap();
        assert_ne!(second.port(), private_only.port());
        assert_eq!(
            status.endpoints,
            vec![AdvertisedEndpoint {
                endpoint: format!("192.0.2.30:{}", second.port()),
                kind: EndpointKind::Public,
            }]
        );
        assert!(reaches(&route, second).is_ok());
        assert!(reaches(&route, first).is_err());

        // Configured endpoints replace the interface list.
        let status = route
            .save(RemoteAccessSettings {
                allow_public: true,
                ..on("0.0.0.0:0", &["runtime.example.net:7443"])
            })
            .unwrap();
        assert_eq!(status.listening, Some(second));
        assert_eq!(
            route.access().advertised_endpoints(),
            vec!["runtime.example.net:7443".to_owned()]
        );

        // Turning it off stops serving and clears the published endpoints.
        let status = route
            .save(RemoteAccessSettings {
                enabled: false,
                ..on("0.0.0.0:0", &[])
            })
            .unwrap();
        assert_eq!(status.listening, None);
        assert!(status.endpoints.is_empty());
        assert_eq!(
            reaches(&route, second),
            Err(RemoteConnectError::Unreachable)
        );
        assert_eq!(read_listener_status(&remote).unwrap(), None);
        assert!(route
            .access()
            .create_pairing_link(PairingLinkRequest::default())
            .is_err());

        // The stored settings survive a new route on the same directory.
        assert!(!load_remote_settings(&remote).unwrap().enabled);
    }

    #[test]
    fn host_overrides_win_over_the_stored_settings() {
        let (route, _directory) = route(RemoteSettingsOverrides {
            enabled: Some(true),
            listen: Some("127.0.0.1:0".parse().unwrap()),
            endpoints: Some(vec!["198.51.100.4:7443".into()]),
            allow_public: None,
        });
        let status = route.apply();
        assert!(!status.settings.enabled);
        assert!(status.overridden);
        let listening = status.listening.unwrap();
        assert!(reaches(&route, listening).is_ok());
        assert_eq!(
            status.endpoints,
            vec![AdvertisedEndpoint {
                endpoint: "198.51.100.4:7443".into(),
                kind: EndpointKind::Configured,
            }]
        );
        route.stop();
        assert_eq!(route.status().listening, None);
        assert_eq!(
            reaches(&route, listening),
            Err(RemoteConnectError::Unreachable)
        );
    }

    #[test]
    fn a_bind_failure_is_reported_and_a_later_save_retries() {
        let (route, _directory) = route(RemoteSettingsOverrides::default());
        let taken = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = taken.local_addr().unwrap().to_string();
        let status = route.save(on(&address, &[])).unwrap();
        assert_eq!(status.listening, None);
        assert!(status.error.is_some());
        drop(taken);
        let status = route.save(on(&address, &[])).unwrap();
        assert_eq!(
            status.listening.map(|bound| bound.to_string()),
            Some(address)
        );
        assert_eq!(status.error, None);
    }

    #[test]
    fn invalid_settings_are_refused_and_nothing_changes() {
        let (route, directory) = route(RemoteSettingsOverrides::default());
        let invalid = on("127.0.0.1:0", &["no-port"]);
        assert_eq!(
            route.save(invalid).unwrap_err().code(),
            muniment_attach::ErrorCode::InvalidRequest
        );
        assert!(
            !load_remote_settings(&directory.0.join("remote"))
                .unwrap()
                .enabled
        );
        let described = route.describe();
        assert_eq!(described["settings"]["enabled"], false);
        assert_eq!(described["listening"], Value::Null);
        assert_eq!(
            described["certificate_sha256"],
            route.access().certificate_fingerprint().to_hex()
        );
        assert_eq!(
            described["runtime_id"],
            route.access().runtime_info().runtime_id
        );
    }
}
