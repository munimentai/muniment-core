//! The remote access settings a runtime keeps under its state root, and the
//! endpoints a pairing link advertises.
//!
//! The settings live in `<state root>/remote/settings.json`. Remote access is
//! off until the owner turns it on. A host may override each setting, such
//! as from its environment, without changing the stored file.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;

use muniment_attach::{is_valid_endpoint, ProtocolError, MAX_PAIRING_ENDPOINTS};
use serde::{Deserialize, Serialize};

use super::remote_identity::{read_private, write_private};

/// The port the remote listener binds when the settings name no address.
pub const DEFAULT_REMOTE_PORT: u16 = 7443;
const SETTINGS_FILE: &str = "settings.json";
const LISTENER_FILE: &str = "listener.json";

/// Whether remote access is on, where its listener binds and which
/// endpoints pairing links name.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteAccessSettings {
    pub enabled: bool,
    /// The listen address. `None` binds port 7443 on every interface.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// `host:port` endpoints pairing links name. Empty lets the runtime list
    /// its own interface addresses.
    #[serde(default)]
    pub endpoints: Vec<String>,
}

impl RemoteAccessSettings {
    /// Checks the endpoints: at most eight, each `host:port`.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.endpoints.len() > MAX_PAIRING_ENDPOINTS
            || !self
                .endpoints
                .iter()
                .all(|endpoint| is_valid_endpoint(endpoint))
        {
            return Err(ProtocolError::invalid_request_with_reason(
                "Name at most eight host:port endpoints.",
            ));
        }
        Ok(())
    }

    /// The addresses to try in order. The default tries every IPv6 and IPv4
    /// interface first, then IPv4 alone for a host without IPv6. Windows
    /// binds IPv6 sockets to IPv6 only, so it binds IPv4 there.
    pub fn listen_candidates(&self) -> Vec<SocketAddr> {
        match self.listen {
            Some(address) => vec![address],
            None if cfg!(windows) => {
                vec![SocketAddr::new(
                    Ipv4Addr::UNSPECIFIED.into(),
                    DEFAULT_REMOTE_PORT,
                )]
            }
            None => vec![
                SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), DEFAULT_REMOTE_PORT),
                SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), DEFAULT_REMOTE_PORT),
            ],
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsFile {
    version: u32,
    enabled: bool,
    listen: Option<SocketAddr>,
    endpoints: Vec<String>,
}

/// Reads the stored settings. A missing file reads as remote access off.
pub fn load_remote_settings(directory: &Path) -> io::Result<RemoteAccessSettings> {
    let Some(bytes) = read_private(&directory.join(SETTINGS_FILE))? else {
        return Ok(RemoteAccessSettings::default());
    };
    let file: SettingsFile = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    let settings = RemoteAccessSettings {
        enabled: file.enabled,
        listen: file.listen,
        endpoints: file.endpoints,
    };
    if file.version != 1 || settings.validate().is_err() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(settings)
}

/// Replaces the stored settings with an owner-only file.
pub fn save_remote_settings(directory: &Path, settings: &RemoteAccessSettings) -> io::Result<()> {
    let bytes = serde_json::to_vec(&SettingsFile {
        version: 1,
        enabled: settings.enabled,
        listen: settings.listen,
        endpoints: settings.endpoints.clone(),
    })
    .map_err(io::Error::other)?;
    write_private(&directory.join(SETTINGS_FILE), &bytes)
}

/// Values a host sets over the stored settings, such as from its
/// environment. `None` keeps the stored value.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RemoteSettingsOverrides {
    pub enabled: Option<bool>,
    pub listen: Option<SocketAddr>,
    pub endpoints: Option<Vec<String>>,
}

impl RemoteSettingsOverrides {
    pub fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    /// The stored settings with each override applied.
    pub fn apply(&self, mut settings: RemoteAccessSettings) -> RemoteAccessSettings {
        if let Some(enabled) = self.enabled {
            settings.enabled = enabled;
        }
        if let Some(listen) = self.listen {
            settings.listen = Some(listen);
        }
        if let Some(endpoints) = &self.endpoints {
            settings.endpoints = endpoints.clone();
        }
        settings
    }
}

/// Where an advertised endpoint comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EndpointKind {
    /// The settings or the host named it.
    Configured,
    /// The listener binds one loopback address.
    Loopback,
    /// A private LAN address: RFC 1918 or an IPv6 unique local address.
    Lan,
    /// The shared address space 100.64.0.0/10 and the prefix
    /// fd7a:115c:a1e0::/48, which private overlay networks assign.
    Overlay,
    /// Any other routable address.
    Public,
}

/// One `host:port` a pairing link names, with where it comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvertisedEndpoint {
    pub endpoint: String,
    pub kind: EndpointKind,
}

/// The endpoints pairing links name for a listener bound to `bound`.
/// Configured endpoints win. Otherwise an unspecified address lists each
/// usable interface address with the bound port, IPv4 before IPv6, and an
/// IPv4 listener lists IPv4 addresses only. At most eight are kept.
pub fn advertised_endpoints(
    configured: &[String],
    bound: SocketAddr,
    interfaces: &[IpAddr],
) -> Vec<AdvertisedEndpoint> {
    if !configured.is_empty() {
        return configured
            .iter()
            .take(MAX_PAIRING_ENDPOINTS)
            .map(|endpoint| AdvertisedEndpoint {
                endpoint: endpoint.clone(),
                kind: EndpointKind::Configured,
            })
            .collect();
    }
    let port = bound.port();
    if !bound.ip().is_unspecified() {
        let kind = if bound.ip().is_loopback() {
            EndpointKind::Loopback
        } else {
            classify(bound.ip())
        };
        return vec![AdvertisedEndpoint {
            endpoint: bound.to_string(),
            kind,
        }];
    }
    let dual_stack = bound.is_ipv6();
    let mut addresses: Vec<IpAddr> = Vec::new();
    for address in interfaces {
        let address = match address {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(*address, IpAddr::V4),
            v4 => *v4,
        };
        if is_advertisable(address)
            && (dual_stack || address.is_ipv4())
            && !addresses.contains(&address)
        {
            addresses.push(address);
        }
    }
    addresses.sort_by_key(IpAddr::is_ipv6);
    addresses
        .into_iter()
        .take(MAX_PAIRING_ENDPOINTS)
        .map(|address| AdvertisedEndpoint {
            endpoint: SocketAddr::new(address, port).to_string(),
            kind: classify(address),
        })
        .collect()
}

/// Whether a client on another machine could reach `address`: not
/// loopback, unspecified, multicast, broadcast or link-local.
fn is_advertisable(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local())
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (v6.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn classify(address: IpAddr) -> EndpointKind {
    match address {
        IpAddr::V4(v4) => {
            let [first, second, ..] = v4.octets();
            if first == 100 && (second & 0xc0) == 64 {
                EndpointKind::Overlay
            } else if v4.is_private() {
                EndpointKind::Lan
            } else {
                EndpointKind::Public
            }
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            if segments[..3] == [0xfd7a, 0x115c, 0xa1e0] {
                EndpointKind::Overlay
            } else if (segments[0] & 0xfe00) == 0xfc00 {
                EndpointKind::Lan
            } else {
                EndpointKind::Public
            }
        }
    }
}

/// The addresses of this machine's interfaces that are up, loopback
/// excluded.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn interface_addresses() -> Vec<IpAddr> {
    let mut list: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head it allocates, freed below.
    if unsafe { libc::getifaddrs(&mut list) } != 0 {
        return Vec::new();
    }
    let mut addresses = Vec::new();
    let mut cursor = list;
    while !cursor.is_null() {
        // SAFETY: each node is valid until freeifaddrs.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        let up = entry.ifa_flags & libc::IFF_UP as libc::c_uint != 0;
        let loopback = entry.ifa_flags & libc::IFF_LOOPBACK as libc::c_uint != 0;
        if entry.ifa_addr.is_null() || !up || loopback {
            continue;
        }
        // SAFETY: ifa_addr is non-null and its family names its layout.
        match i32::from(unsafe { (*entry.ifa_addr).sa_family }) {
            libc::AF_INET => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in>() };
                addresses.push(IpAddr::V4(Ipv4Addr::from(u32::from_be(
                    address.sin_addr.s_addr,
                ))));
            }
            libc::AF_INET6 => {
                let address = unsafe { &*entry.ifa_addr.cast::<libc::sockaddr_in6>() };
                addresses.push(IpAddr::V6(Ipv6Addr::from(address.sin6_addr.s6_addr)));
            }
            _ => {}
        }
    }
    // SAFETY: list came from getifaddrs and no node is used after this.
    unsafe { libc::freeifaddrs(list) };
    addresses
}

/// This platform lists no interfaces, so links name configured endpoints only.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn interface_addresses() -> Vec<IpAddr> {
    Vec::new()
}

/// What a serving listener publishes beside the settings, so a command in
/// another process can mint links that name the live endpoints.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteListenerStatus {
    pub listen: SocketAddr,
    pub endpoints: Vec<AdvertisedEndpoint>,
}

/// Reads the status a serving listener published, if one did.
pub fn read_listener_status(directory: &Path) -> io::Result<Option<RemoteListenerStatus>> {
    read_private(&directory.join(LISTENER_FILE))?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(io::Error::other))
        .transpose()
}

pub(super) fn write_listener_status(
    directory: &Path,
    status: &RemoteListenerStatus,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(status).map_err(io::Error::other)?;
    write_private(&directory.join(LISTENER_FILE), &bytes)
}

pub(super) fn remove_listener_status(directory: &Path) -> io::Result<()> {
    match std::fs::remove_file(directory.join(LISTENER_FILE)) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "muniment-remote-settings-{name}-{}",
            uuid::Uuid::now_v7()
        ));
        super::super::remote_identity::ensure_private_directory(&path).unwrap();
        path
    }

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn settings_default_to_off_and_round_trip_owner_only() {
        let directory = directory("store");
        assert_eq!(
            load_remote_settings(&directory).unwrap(),
            RemoteAccessSettings::default()
        );
        let settings = RemoteAccessSettings {
            enabled: true,
            listen: Some("127.0.0.1:7444".parse().unwrap()),
            endpoints: vec!["runtime.example.net:7444".into()],
        };
        save_remote_settings(&directory, &settings).unwrap();
        assert_eq!(load_remote_settings(&directory).unwrap(), settings);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = directory.join(SETTINGS_FILE);
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_remote_settings(&directory).is_err());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_malformed_settings_file_fails_to_load() {
        let directory = directory("malformed");
        for bytes in [
            &br#"{"version":2,"enabled":true,"listen":null,"endpoints":[]}"#[..],
            br#"{"version":1,"enabled":true,"listen":null,"endpoints":["no-port"]}"#,
            br#"{"version":1,"enabled":true,"listen":null,"endpoints":[],"extra":1}"#,
        ] {
            write_private(&directory.join(SETTINGS_FILE), bytes).unwrap();
            assert!(load_remote_settings(&directory).is_err());
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn overrides_replace_only_what_they_name() {
        let stored = RemoteAccessSettings {
            enabled: false,
            listen: None,
            endpoints: vec!["198.51.100.1:7443".into()],
        };
        let overrides = RemoteSettingsOverrides {
            enabled: Some(true),
            listen: Some("[::]:9443".parse().unwrap()),
            endpoints: None,
        };
        let applied = overrides.apply(stored.clone());
        assert!(applied.enabled);
        assert_eq!(applied.listen, Some("[::]:9443".parse().unwrap()));
        assert_eq!(applied.endpoints, stored.endpoints);
        assert_eq!(
            RemoteSettingsOverrides::default().apply(stored.clone()),
            stored
        );
    }

    #[test]
    fn the_default_listen_address_is_port_7443_on_every_interface() {
        let candidates = RemoteAccessSettings::default().listen_candidates();
        assert!(candidates.iter().all(|address| address.port() == 7443));
        assert!(candidates
            .iter()
            .all(|address| address.ip().is_unspecified()));
        assert!(candidates
            .last()
            .is_some_and(|address| address.ip() == Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn endpoints_list_usable_interfaces_with_the_bound_port_and_label_them() {
        let interfaces = [
            ip("127.0.0.1"),
            ip("169.254.3.4"),
            ip("192.0.2.10"),
            IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3)),
            ip("100.101.102.103"),
            ip("::1"),
            ip("fe80::1"),
            ip("fd7a:115c:a1e0::5"),
            ip("fd00::7"),
            ip("2001:db8::9"),
            ip("::ffff:192.0.2.10"),
            ip("192.0.2.10"),
        ];
        let listed = advertised_endpoints(&[], "[::]:7443".parse().unwrap(), &interfaces);
        let pairs: Vec<(&str, EndpointKind)> = listed
            .iter()
            .map(|endpoint| (endpoint.endpoint.as_str(), endpoint.kind))
            .collect();
        let private = format!("{}:7443", Ipv4Addr::new(10, 1, 2, 3));
        assert_eq!(
            pairs,
            vec![
                ("192.0.2.10:7443", EndpointKind::Public),
                (private.as_str(), EndpointKind::Lan),
                ("100.101.102.103:7443", EndpointKind::Overlay),
                ("[fd7a:115c:a1e0::5]:7443", EndpointKind::Overlay),
                ("[fd00::7]:7443", EndpointKind::Lan),
                ("[2001:db8::9]:7443", EndpointKind::Public),
            ]
        );
        assert!(listed
            .iter()
            .all(|endpoint| is_valid_endpoint(&endpoint.endpoint)));

        let ipv4_only = advertised_endpoints(&[], "0.0.0.0:9000".parse().unwrap(), &interfaces);
        assert_eq!(ipv4_only.len(), 3);
        assert!(ipv4_only.iter().all(
            |endpoint| endpoint.endpoint.ends_with(":9000") && !endpoint.endpoint.contains('[')
        ));
    }

    #[test]
    fn configured_and_bound_addresses_win_and_the_list_is_bounded() {
        let configured = vec!["runtime.example.net:7443".to_owned()];
        assert_eq!(
            advertised_endpoints(
                &configured,
                "[::]:7443".parse().unwrap(),
                &[ip("192.0.2.1")]
            ),
            vec![AdvertisedEndpoint {
                endpoint: "runtime.example.net:7443".into(),
                kind: EndpointKind::Configured,
            }]
        );
        assert_eq!(
            advertised_endpoints(&[], "127.0.0.1:5000".parse().unwrap(), &[ip("192.0.2.1")]),
            vec![AdvertisedEndpoint {
                endpoint: "127.0.0.1:5000".into(),
                kind: EndpointKind::Loopback,
            }]
        );
        let many: Vec<IpAddr> = (1..=20)
            .map(|host| IpAddr::V4(Ipv4Addr::new(198, 51, 100, host)))
            .collect();
        assert_eq!(
            advertised_endpoints(&[], "0.0.0.0:7443".parse().unwrap(), &many).len(),
            MAX_PAIRING_ENDPOINTS
        );
        assert!(advertised_endpoints(&[], "0.0.0.0:7443".parse().unwrap(), &[]).is_empty());
    }

    #[test]
    fn listener_status_round_trips_and_clears() {
        let directory = directory("status");
        assert_eq!(read_listener_status(&directory).unwrap(), None);
        let status = RemoteListenerStatus {
            listen: "[::]:7443".parse().unwrap(),
            endpoints: vec![AdvertisedEndpoint {
                endpoint: "192.0.2.1:7443".into(),
                kind: EndpointKind::Public,
            }],
        };
        write_listener_status(&directory, &status).unwrap();
        assert_eq!(read_listener_status(&directory).unwrap(), Some(status));
        remove_listener_status(&directory).unwrap();
        remove_listener_status(&directory).unwrap();
        assert_eq!(read_listener_status(&directory).unwrap(), None);
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn this_machine_lists_no_loopback_interface_address() {
        assert!(interface_addresses()
            .iter()
            .all(|address| !address.is_loopback()));
    }
}
