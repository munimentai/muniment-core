//! Remote access for the headless host: its environment overrides and the
//! `pair`, `devices`, `revoke` and `info` commands. The commands work on the
//! state directory, so they run beside a `serve` in another process.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use muniment_core::attach::{
    advertised_endpoints, interface_addresses, is_valid_endpoint, load_remote_settings,
    read_listener_status, InstallKind, PairingLinkRequest, RemoteAccess, RemoteAccessOptions,
    RemoteRouteOptions, RemoteSettingsOverrides, MAX_PAIRING_ENDPOINTS, REMOTE_SCOPES,
};
use muniment_core::serde_json::{self, json, Value};

/// The state root's directory for the remote identity, store and settings.
const REMOTE_DIRECTORY_NAME: &str = "remote";

/// The variables a host sets over the stored remote access settings, and
/// the one that names a container install.
const ACCESS_VARIABLE: &str = "MUNIMENT_REMOTE_ACCESS";
const LISTEN_VARIABLE: &str = "MUNIMENT_REMOTE_LISTEN";
const ENDPOINTS_VARIABLE: &str = "MUNIMENT_REMOTE_ENDPOINTS";
const INSTALL_KIND_VARIABLE: &str = "MUNIMENT_INSTALL_KIND";

/// The remote access directory under `state`.
pub fn remote_directory(state: &Path) -> PathBuf {
    state.join(REMOTE_DIRECTORY_NAME)
}

/// `container` when the image says so, `server` otherwise.
pub fn install_kind() -> Result<InstallKind, String> {
    install_kind_from(env(INSTALL_KIND_VARIABLE).as_deref())
}

fn install_kind_from(value: Option<&str>) -> Result<InstallKind, String> {
    match value {
        None | Some("") | Some("server") => Ok(InstallKind::Server),
        Some("container") => Ok(InstallKind::Container),
        Some(other) => Err(format!(
            "{INSTALL_KIND_VARIABLE} must be server or container, not {other}"
        )),
    }
}

/// The overrides `MUNIMENT_REMOTE_ACCESS` (`on` or `off`),
/// `MUNIMENT_REMOTE_LISTEN` (`address:port`) and `MUNIMENT_REMOTE_ENDPOINTS`
/// (a comma list of `host:port`) set.
pub fn overrides_from_env() -> Result<RemoteSettingsOverrides, String> {
    overrides_from(
        env(ACCESS_VARIABLE).as_deref(),
        env(LISTEN_VARIABLE).as_deref(),
        env(ENDPOINTS_VARIABLE).as_deref(),
    )
}

fn overrides_from(
    access: Option<&str>,
    listen: Option<&str>,
    endpoints: Option<&str>,
) -> Result<RemoteSettingsOverrides, String> {
    let enabled = match access.map(str::trim) {
        None | Some("") => None,
        Some("on" | "true" | "1") => Some(true),
        Some("off" | "false" | "0") => Some(false),
        Some(other) => return Err(format!("{ACCESS_VARIABLE} must be on or off, not {other}")),
    };
    let listen = match listen.map(str::trim).filter(|value| !value.is_empty()) {
        None => None,
        Some(value) => Some(value.parse::<SocketAddr>().map_err(|_| {
            format!("{LISTEN_VARIABLE} must be an IP address and port, such as 0.0.0.0:7443")
        })?),
    };
    let endpoints: Vec<String> = endpoints
        .unwrap_or_default()
        .split(',')
        .map(str::trim)
        .filter(|endpoint| !endpoint.is_empty())
        .map(str::to_owned)
        .collect();
    if endpoints.len() > MAX_PAIRING_ENDPOINTS
        || !endpoints.iter().all(|endpoint| is_valid_endpoint(endpoint))
    {
        return Err(format!(
            "{ENDPOINTS_VARIABLE} must list at most eight host:port endpoints"
        ));
    }
    Ok(RemoteSettingsOverrides {
        enabled,
        listen,
        endpoints: (!endpoints.is_empty()).then_some(endpoints),
    })
}

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok()
}

/// What the server says about itself to remote clients.
pub fn access_options() -> Result<RemoteAccessOptions, String> {
    Ok(RemoteAccessOptions {
        runtime_name: None,
        runtime_version: env!("CARGO_PKG_VERSION").into(),
        install_kind: install_kind()?,
    })
}

/// The remote route `serve` starts.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn route_options() -> Result<RemoteRouteOptions, String> {
    Ok(RemoteRouteOptions {
        access: access_options()?,
        overrides: overrides_from_env()?,
    })
}

/// Opens the remote access of the runtime whose state lives in `state`.
pub fn open_access(state: &Path) -> Result<RemoteAccess, String> {
    RemoteAccess::open(remote_directory(state), access_options()?)
        .map_err(|error| error.to_string())
}

/// One line that names the runtime and where its listener binds. It
/// carries no secret.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn describe_for_log(state: &Path) -> Result<String, String> {
    let access = open_access(state)?;
    let settings = effective_settings(state)?;
    let listen = if settings.enabled {
        settings
            .listen_candidates()
            .first()
            .map_or_else(String::new, ToString::to_string)
    } else {
        "off".into()
    };
    Ok(format!(
        "runtime_id={} fingerprint={} listen={listen}",
        access.runtime_info().runtime_id,
        access.certificate_fingerprint()
    ))
}

fn effective_settings(state: &Path) -> Result<muniment_core::attach::RemoteAccessSettings, String> {
    let stored = load_remote_settings(&remote_directory(state))
        .map_err(|error| format!("the remote access settings could not be read: {error}"))?;
    Ok(overrides_from_env()?.apply(stored))
}

/// The endpoints a new link names: those the serving listener published,
/// or, while nothing serves, those the settings and interfaces give.
fn link_endpoints(state: &Path) -> Result<Vec<String>, String> {
    let directory = remote_directory(state);
    if let Some(status) = read_listener_status(&directory)
        .map_err(|error| format!("the listener status could not be read: {error}"))?
    {
        return Ok(status
            .endpoints
            .into_iter()
            .map(|endpoint| endpoint.endpoint)
            .collect());
    }
    let settings = effective_settings(state)?;
    if !settings.enabled {
        return Err(format!(
            "remote access is off: turn it on in the settings or set {ACCESS_VARIABLE}=on"
        ));
    }
    let bound = settings
        .listen_candidates()
        .first()
        .copied()
        .ok_or("remote access has no listen address")?;
    Ok(
        advertised_endpoints(&settings.endpoints, bound, &interface_addresses())
            .into_iter()
            .map(|endpoint| endpoint.endpoint)
            .collect(),
    )
}

/// `pair [--scopes s1,s2] [--json]`: prints a one-time pairing link.
pub fn pair(state: &Path, args: &[String]) -> Result<(), String> {
    let mut json_output = false;
    let mut scopes = None;
    let mut rest = args.iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--json" => json_output = true,
            "--scopes" => {
                let list = rest.next().ok_or("--scopes needs a comma list")?;
                scopes = Some(parse_scopes(list)?);
            }
            other => return Err(format!("pair: unexpected argument {other}")),
        }
    }
    let endpoints = link_endpoints(state)?;
    if endpoints.is_empty() {
        return Err(format!(
            "no endpoint to advertise: set {ENDPOINTS_VARIABLE} to the host:port clients reach"
        ));
    }
    let access = open_access(state)?;
    let created = access
        .create_pairing_link(PairingLinkRequest {
            scopes,
            endpoints: Some(endpoints),
        })
        .map_err(|error| format!("the pairing link could not be created: {error}"))?;
    if json_output {
        let info = access.runtime_info();
        print_json(&json!({
            "link": created.link.to_uri(),
            "expires_at": created.expires_at,
            "scopes": created.scopes,
            "endpoints": created.link.endpoints,
            "fingerprint": access.certificate_fingerprint().to_hex(),
            "runtime_id": info.runtime_id,
            "runtime_name": info.runtime_name,
        }))
    } else {
        println!("{}", created.link.to_uri());
        Ok(())
    }
}

fn parse_scopes(list: &str) -> Result<BTreeSet<String>, String> {
    let scopes: BTreeSet<String> = list
        .split(',')
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
        .collect();
    if scopes.is_empty()
        || !scopes
            .iter()
            .all(|scope| REMOTE_SCOPES.contains(&scope.as_str()))
    {
        return Err(format!(
            "scopes must come from {}",
            REMOTE_SCOPES.join(", ")
        ));
    }
    Ok(scopes)
}

/// `devices [--json]`: lists the paired devices.
pub fn devices(state: &Path, args: &[String]) -> Result<(), String> {
    let json_output = json_flag("devices", args)?;
    let devices = open_access(state)?
        .list_devices()
        .map_err(|error| format!("the devices could not be read: {error}"))?;
    if json_output {
        return print_json(&json!({"devices": devices}));
    }
    for device in devices {
        println!(
            "{}  {}  kind={} scopes={} paired={} last_seen={}",
            device.device_id,
            device.name,
            device.kind,
            device.scopes.into_iter().collect::<Vec<_>>().join(","),
            device.created_at,
            device.last_seen_at.as_deref().unwrap_or("never"),
        );
    }
    Ok(())
}

/// `revoke <device-id>`: revokes a paired device. A live session of the
/// device closes within a second.
pub fn revoke(state: &Path, args: &[String]) -> Result<(), String> {
    let [device_id] = args else {
        return Err("revoke needs one device id".into());
    };
    let revoked = open_access(state)?
        .revoke_device(device_id)
        .map_err(|_| format!("{device_id} is not a device id"))?;
    if !revoked {
        return Err(format!("no paired device has the id {device_id}"));
    }
    println!("revoked {device_id}");
    Ok(())
}

/// `info [--json]`: prints the runtime's identity and remote access state.
pub fn info(state: &Path, args: &[String]) -> Result<(), String> {
    let json_output = json_flag("info", args)?;
    let access = open_access(state)?;
    let runtime = access.runtime_info();
    let settings = effective_settings(state)?;
    let status = read_listener_status(&remote_directory(state))
        .map_err(|error| format!("the listener status could not be read: {error}"))?;
    let body = json!({
        "runtime_id": runtime.runtime_id,
        "runtime_name": runtime.runtime_name,
        "runtime_version": runtime.runtime_version,
        "install_kind": runtime.install_kind,
        "certificate_sha256": access.certificate_fingerprint().to_hex(),
        "remote_access": {
            "enabled": settings.enabled,
            "listen": settings.listen_candidates().first().map(ToString::to_string),
            "configured_endpoints": settings.endpoints,
            "listening": status.as_ref().map(|status| status.listen.to_string()),
            "endpoints": status.map(|status| status.endpoints).unwrap_or_default(),
        },
        "update_request": access.requested_update(),
    });
    if json_output {
        return print_json(&body);
    }
    for key in [
        "runtime_id",
        "runtime_name",
        "runtime_version",
        "install_kind",
        "certificate_sha256",
    ] {
        println!("{key}={}", plain(&body[key]));
    }
    let remote = &body["remote_access"];
    for key in ["enabled", "listen", "listening"] {
        println!("remote_{key}={}", plain(&remote[key]));
    }
    for endpoint in remote["endpoints"].as_array().into_iter().flatten() {
        println!(
            "remote_endpoint={} kind={}",
            plain(&endpoint["endpoint"]),
            plain(&endpoint["kind"])
        );
    }
    if let Some(version) = body["update_request"]["version"].as_str() {
        println!("update_requested={version}");
    }
    Ok(())
}

fn json_flag(command: &str, args: &[String]) -> Result<bool, String> {
    match args {
        [] => Ok(false),
        [flag] if flag == "--json" => Ok(true),
        [other, ..] => Err(format!("{command}: unexpected argument {other}")),
    }
}

fn plain(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "none".into(),
        other => other.to_string(),
    }
}

fn print_json(value: &Value) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_install_kind_is_server_unless_the_image_names_a_container() {
        assert_eq!(install_kind_from(None), Ok(InstallKind::Server));
        assert_eq!(install_kind_from(Some("")), Ok(InstallKind::Server));
        assert_eq!(
            install_kind_from(Some("container")),
            Ok(InstallKind::Container)
        );
        assert!(install_kind_from(Some("desktop")).is_err());
    }

    #[test]
    fn overrides_parse_from_the_environment_values() {
        assert_eq!(
            overrides_from(None, None, None),
            Ok(RemoteSettingsOverrides::default())
        );
        assert_eq!(
            overrides_from(
                Some("on"),
                Some("0.0.0.0:7443"),
                Some(" 127.0.0.1:7443 , runtime.example.net:7443,")
            ),
            Ok(RemoteSettingsOverrides {
                enabled: Some(true),
                listen: Some("0.0.0.0:7443".parse().unwrap()),
                endpoints: Some(vec![
                    "127.0.0.1:7443".into(),
                    "runtime.example.net:7443".into()
                ]),
            })
        );
        assert_eq!(
            overrides_from(Some("off"), Some(""), Some("")).unwrap(),
            RemoteSettingsOverrides {
                enabled: Some(false),
                ..RemoteSettingsOverrides::default()
            }
        );
        assert!(overrides_from(Some("maybe"), None, None).is_err());
        assert!(overrides_from(None, Some("runtime:7443"), None).is_err());
        assert!(overrides_from(None, None, Some("no-port")).is_err());
        let nine = (1..=9)
            .map(|port| format!("192.0.2.1:{port}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(overrides_from(None, None, Some(&nine)).is_err());
    }

    #[test]
    fn scopes_parse_from_a_comma_list_of_known_scopes() {
        assert_eq!(
            parse_scopes("thread.read, runtime.admin").unwrap(),
            BTreeSet::from(["runtime.admin".to_owned(), "thread.read".to_owned()])
        );
        assert!(parse_scopes("").is_err());
        assert!(parse_scopes("thread.read,root").is_err());
    }
}
