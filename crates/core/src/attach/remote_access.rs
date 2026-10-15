//! Pairing links, paired devices and update requests of the remote attach
//! route.
//!
//! The store keeps only SHA-256 hashes of pairing and device secrets. Every
//! change runs under an exclusive lock on a file beside the store, reads the
//! store fresh, and replaces it atomically, so a second process that opens the
//! same directory, such as a command that prints a pairing link, sees and
//! makes consistent changes.

use std::collections::{BTreeSet, HashSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use fs2::FileExt;
use muniment_attach::{
    default_pairing_scopes, is_lowercase_hex, is_valid_display_name, is_valid_endpoint,
    CertificateFingerprint, Id, InstallKind, Operation, PairingLink, ProtocolError, Request,
    RuntimeInfo, DEVICE_SECRET_HEX_LENGTH, MAX_PAIRING_ENDPOINTS, PAIRING_SECRET_HEX_LENGTH,
    REMOTE_SCOPES, SCOPE_RUNTIME_ADMIN,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::remote_identity::{
    ensure_private_directory, read_private, write_private, RemoteIdentity,
};

/// How long a pairing link stays redeemable.
pub const PAIRING_LINK_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// The most pairing links that may wait for redemption at once.
pub const MAX_OUTSTANDING_PAIRINGS: usize = 16;
/// The most devices one runtime pairs.
pub const MAX_PAIRED_DEVICES: usize = 64;
const ACCESS_FILE: &str = "access.json";
const LOCK_FILE: &str = "access.lock";
const UPDATE_FILE: &str = "runtime-update.json";
const MAX_VERSION_LENGTH: usize = 64;

/// What a runtime host says about itself when it opens remote access.
#[derive(Clone, Debug)]
pub struct RemoteAccessOptions {
    /// The display name clients see. `None` keeps the stored name.
    pub runtime_name: Option<String>,
    /// The version the runtime announces.
    pub runtime_version: String,
    pub install_kind: InstallKind,
}

/// What a pairing link grants and where it points.
#[derive(Clone, Debug, Default)]
pub struct PairingLinkRequest {
    /// The scopes to grant. `None` grants read and write without pairing
    /// management.
    pub scopes: Option<BTreeSet<String>>,
    /// The endpoints to name. `None` names the advertised endpoints.
    pub endpoints: Option<Vec<String>>,
}

/// A new pairing link. The link holds the only copy of its secret.
#[derive(Clone, Debug)]
pub struct CreatedPairingLink {
    pub link: PairingLink,
    pub pairing_id: String,
    pub expires_at: String,
    pub scopes: BTreeSet<String>,
}

/// One paired device as the owner sees it. It carries no secret.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct PairedDevice {
    pub device_id: String,
    pub name: String,
    pub kind: String,
    pub scopes: BTreeSet<String>,
    pub created_at: String,
    pub last_seen_at: Option<String>,
}

/// A version a client asked the host to install.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RuntimeUpdateRequest {
    pub version: String,
    pub requested_at: String,
    /// The device id of a remote requester, or `local` for the owner.
    pub requested_by: String,
}

/// Why remote access could not open.
#[derive(Debug)]
pub struct RemoteAccessOpenError(std::io::Error);

impl fmt::Display for RemoteAccessOpenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "remote access could not open: {}", self.0)
    }
}

impl std::error::Error for RemoteAccessOpenError {}

pub(super) struct IssuedDevice {
    pub(super) device_id: String,
    pub(super) secret: String,
    pub(super) scopes: BTreeSet<String>,
}

pub(super) struct AuthenticatedDevice {
    pub(super) device_id: String,
    pub(super) scopes: BTreeSet<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessFile {
    version: u32,
    devices: Vec<StoredDevice>,
    pairings: Vec<StoredPairing>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredDevice {
    device_id: String,
    secret_sha256: String,
    name: String,
    kind: String,
    scopes: BTreeSet<String>,
    created_at: String,
    last_seen_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredPairing {
    pairing_id: String,
    secret_sha256: String,
    scopes: BTreeSet<String>,
    created_at: String,
    expires_at: String,
}

type Clock = dyn Fn() -> DateTime<Utc> + Send + Sync;

/// The identity the local desktop route announces. One runtime serves per
/// process, and the local admission runs before any per-connection service
/// exists, so the identity is process-wide.
static LOCAL_RUNTIME_INFO: Mutex<Option<RuntimeInfo>> = Mutex::new(None);

/// The runtime identity a local desktop welcome carries, once a host
/// announced one.
pub(super) fn local_runtime_info() -> Option<RuntimeInfo> {
    lock(&LOCAL_RUNTIME_INFO).clone()
}

/// The remote attach state one runtime shares between its listener and its
/// local owner: identity, pairing links, paired devices and update requests.
#[derive(Clone)]
pub struct RemoteAccess {
    inner: Arc<Inner>,
}

struct Inner {
    directory: PathBuf,
    identity: RemoteIdentity,
    server_config: Arc<rustls::ServerConfig>,
    runtime_version: String,
    install_kind: InstallKind,
    endpoints: Mutex<Vec<String>>,
    revoked: Mutex<HashSet<String>>,
    update_subscribers: Mutex<Vec<mpsc::Sender<RuntimeUpdateRequest>>>,
    clock: Box<Clock>,
}

impl fmt::Debug for RemoteAccess {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RemoteAccess")
            .field("runtime_id", &self.inner.identity.runtime_id)
            .field("fingerprint", &self.inner.identity.fingerprint)
            .finish()
    }
}

impl RemoteAccess {
    /// Opens remote access under `directory`, creating the identity on first
    /// use. Hosts pass `<state root>/remote`.
    pub fn open(
        directory: impl AsRef<Path>,
        options: RemoteAccessOptions,
    ) -> Result<Self, RemoteAccessOpenError> {
        Self::open_with_clock(directory, options, Box::new(Utc::now))
    }

    #[doc(hidden)]
    pub fn open_with_clock(
        directory: impl AsRef<Path>,
        options: RemoteAccessOptions,
        clock: Box<Clock>,
    ) -> Result<Self, RemoteAccessOpenError> {
        let directory = directory.as_ref().to_path_buf();
        ensure_private_directory(&directory).map_err(RemoteAccessOpenError)?;
        let lock = lock_file(&directory, true).map_err(RemoteAccessOpenError)?;
        let identity = RemoteIdentity::load_or_create(&directory, options.runtime_name.as_deref())
            .map_err(RemoteAccessOpenError)?;
        drop(lock);
        let server_config = identity
            .server_config()
            .map_err(|error| RemoteAccessOpenError(std::io::Error::other(error)))?;
        let access = Self {
            inner: Arc::new(Inner {
                directory,
                identity,
                server_config,
                runtime_version: options.runtime_version,
                install_kind: options.install_kind,
                endpoints: Mutex::new(Vec::new()),
                revoked: Mutex::new(HashSet::new()),
                update_subscribers: Mutex::new(Vec::new()),
                clock,
            }),
        };
        // A store that does not parse fails the open rather than the first pairing.
        access
            .read_store()
            .map_err(|_| RemoteAccessOpenError(std::io::ErrorKind::InvalidData.into()))?;
        Ok(access)
    }

    /// The runtime's id, display name, version and install kind.
    pub fn runtime_info(&self) -> RuntimeInfo {
        RuntimeInfo {
            runtime_id: self.inner.identity.runtime_id.clone(),
            runtime_name: self.inner.identity.runtime_name.clone(),
            runtime_version: self.inner.runtime_version.clone(),
            install_kind: Some(self.inner.install_kind),
        }
    }

    /// The SHA-256 of the listener's certificate, which pairing links carry.
    pub fn certificate_fingerprint(&self) -> CertificateFingerprint {
        self.inner.identity.fingerprint
    }

    /// Sets the `host:port` endpoints pairing links name by default. An
    /// empty list leaves a link to name its own.
    pub fn set_advertised_endpoints(&self, endpoints: Vec<String>) -> Result<(), ProtocolError> {
        if !endpoints.is_empty() {
            validate_endpoints(&endpoints)?;
        }
        *lock(&self.inner.endpoints) = endpoints;
        Ok(())
    }

    /// The directory that holds the identity, the store and the settings.
    pub(super) fn directory(&self) -> &Path {
        &self.inner.directory
    }

    /// Announces this runtime's id, name, version and install kind in the
    /// welcome of every later local desktop session in this process.
    pub fn announce_on_local_route(&self) {
        *lock(&LOCAL_RUNTIME_INFO) = Some(self.runtime_info());
    }

    pub fn advertised_endpoints(&self) -> Vec<String> {
        lock(&self.inner.endpoints).clone()
    }

    pub(super) fn server_config(&self) -> Arc<rustls::ServerConfig> {
        Arc::clone(&self.inner.server_config)
    }

    /// Creates a pairing link as the runtime owner, who holds every scope.
    pub fn create_pairing_link(
        &self,
        request: PairingLinkRequest,
    ) -> Result<CreatedPairingLink, ProtocolError> {
        self.create_pairing_link_for(request, &all_scopes())
    }

    /// Creates a pairing link for a caller holding `granted`. The link can
    /// carry only scopes the caller holds.
    pub(super) fn create_pairing_link_for(
        &self,
        request: PairingLinkRequest,
        granted: &BTreeSet<String>,
    ) -> Result<CreatedPairingLink, ProtocolError> {
        let scopes = request.scopes.unwrap_or_else(default_pairing_scopes);
        if scopes.is_empty()
            || !scopes
                .iter()
                .all(|scope| REMOTE_SCOPES.contains(&scope.as_str()))
        {
            return Err(ProtocolError::invalid_request());
        }
        if !scopes.is_subset(granted) {
            return Err(ProtocolError::unauthorized());
        }
        let endpoints = match request.endpoints {
            Some(endpoints) => endpoints,
            None => self.advertised_endpoints(),
        };
        validate_endpoints(&endpoints)?;
        let secret = random_hex::<16>()?;
        let pairing_id = uuid::Uuid::new_v4().to_string();
        let secret_sha256 = sha256_hex(&secret);
        let expires_at = self.transact(|store, now| {
            if store.pairings.len() >= MAX_OUTSTANDING_PAIRINGS {
                return Err(ProtocolError::invalid_request_with_reason(
                    "Too many pairing links are waiting. Wait for one to expire.",
                ));
            }
            let lifetime = chrono::Duration::from_std(PAIRING_LINK_LIFETIME)
                .map_err(|_| ProtocolError::persistence_failed())?;
            let expires_at = timestamp(now + lifetime);
            store.pairings.push(StoredPairing {
                pairing_id: pairing_id.clone(),
                secret_sha256,
                scopes: scopes.clone(),
                created_at: timestamp(now),
                expires_at: expires_at.clone(),
            });
            Ok(expires_at)
        })??;
        let info = self.runtime_info();
        Ok(CreatedPairingLink {
            link: PairingLink {
                runtime_id: Id::new(info.runtime_id)
                    .map_err(|_| ProtocolError::persistence_failed())?,
                runtime_name: info.runtime_name,
                endpoints,
                fingerprint: self.certificate_fingerprint(),
                secret,
            },
            pairing_id,
            expires_at,
            scopes,
        })
    }

    /// Lists the paired devices, oldest first.
    pub fn list_devices(&self) -> Result<Vec<PairedDevice>, ProtocolError> {
        Ok(self
            .read_store()?
            .devices
            .into_iter()
            .map(|device| PairedDevice {
                device_id: device.device_id,
                name: device.name,
                kind: device.kind,
                scopes: device.scopes,
                created_at: device.created_at,
                last_seen_at: device.last_seen_at,
            })
            .collect())
    }

    /// Revokes a device and answers whether it was paired. Its live sessions
    /// in this process close on their next turn, and those in another
    /// process close at their next store check.
    pub fn revoke_device(&self, device_id: &str) -> Result<bool, ProtocolError> {
        if Id::new(device_id).is_err() {
            return Err(ProtocolError::invalid_request());
        }
        let removed = self.transact(|store, _| {
            let before = store.devices.len();
            store.devices.retain(|device| device.device_id != device_id);
            store.devices.len() != before
        })?;
        lock(&self.inner.revoked).insert(device_id.to_owned());
        if removed {
            crate::runtime_eprintln!(
                "muniment-runtime: remote device revoked device_id={device_id}"
            );
        }
        Ok(removed)
    }

    /// Records a version for the host's updater and tells each subscriber.
    /// The runtime itself installs nothing.
    pub fn request_update(
        &self,
        version: &str,
        requested_by: &str,
    ) -> Result<RuntimeUpdateRequest, ProtocolError> {
        if !is_valid_version(version) {
            return Err(ProtocolError::invalid_request());
        }
        let request = RuntimeUpdateRequest {
            version: version.to_owned(),
            requested_at: timestamp((self.inner.clock)()),
            requested_by: requested_by.to_owned(),
        };
        let bytes =
            serde_json::to_vec(&request).map_err(|_| ProtocolError::persistence_failed())?;
        write_private(&self.inner.directory.join(UPDATE_FILE), &bytes)
            .map_err(|_| ProtocolError::persistence_failed())?;
        lock(&self.inner.update_subscribers)
            .retain(|subscriber| subscriber.send(request.clone()).is_ok());
        crate::runtime_eprintln!(
            "muniment-runtime: runtime update requested version={version} requested_by={requested_by}"
        );
        Ok(request)
    }

    /// The last recorded update request, if the host has not cleared it.
    pub fn requested_update(&self) -> Option<RuntimeUpdateRequest> {
        read_private(&self.inner.directory.join(UPDATE_FILE))
            .ok()
            .flatten()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
    }

    /// Clears the recorded request after the host applies or refuses it.
    pub fn clear_update_request(&self) -> std::io::Result<()> {
        match std::fs::remove_file(self.inner.directory.join(UPDATE_FILE)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        }
    }

    /// Receives each update request recorded after this call.
    pub fn update_requests(&self) -> mpsc::Receiver<RuntimeUpdateRequest> {
        let (sender, receiver) = mpsc::channel();
        lock(&self.inner.update_subscribers).push(sender);
        receiver
    }

    /// Redeems a pairing secret once. Requested scopes narrow the link's
    /// scopes. A request that keeps no scope fails without spending the link.
    pub(super) fn redeem_pairing(
        &self,
        secret: &str,
        kind: &str,
        device_name: Option<&str>,
        requested: Option<&BTreeSet<String>>,
    ) -> Result<IssuedDevice, ProtocolError> {
        if !is_lowercase_hex(secret, PAIRING_SECRET_HEX_LENGTH) {
            return Err(ProtocolError::unauthorized());
        }
        let presented = sha256_hex(secret);
        let device_id = uuid::Uuid::new_v4().to_string();
        let device_secret = random_hex::<32>()?;
        let name = device_name
            .filter(|name| is_valid_display_name(name))
            .unwrap_or(kind)
            .to_owned();
        let device_hash = sha256_hex(&device_secret);
        let kind = kind.to_owned();
        let scopes = self.transact(|store, now| {
            let mut found = None;
            for (index, pairing) in store.pairings.iter().enumerate() {
                if super::secret_eq(&presented, &pairing.secret_sha256) {
                    found = Some(index);
                }
            }
            let index = found.ok_or_else(ProtocolError::unauthorized)?;
            let scopes: BTreeSet<String> = match requested {
                Some(requested) => store.pairings[index]
                    .scopes
                    .intersection(requested)
                    .cloned()
                    .collect(),
                None => store.pairings[index].scopes.clone(),
            };
            if scopes.is_empty() || store.devices.len() >= MAX_PAIRED_DEVICES {
                return Err(ProtocolError::unauthorized());
            }
            store.pairings.remove(index);
            store.devices.push(StoredDevice {
                device_id: device_id.clone(),
                secret_sha256: device_hash,
                name,
                kind,
                scopes: scopes.clone(),
                created_at: timestamp(now),
                last_seen_at: Some(timestamp(now)),
            });
            Ok(scopes)
        })??;
        crate::runtime_eprintln!("muniment-runtime: remote device paired device_id={device_id}");
        Ok(IssuedDevice {
            device_id,
            secret: device_secret,
            scopes,
        })
    }

    /// Checks a device credential and records when the device was last seen.
    pub(super) fn authenticate_device(
        &self,
        device_id: &str,
        secret: &str,
    ) -> Result<AuthenticatedDevice, ProtocolError> {
        if Id::new(device_id).is_err()
            || !is_lowercase_hex(secret, DEVICE_SECRET_HEX_LENGTH)
            || lock(&self.inner.revoked).contains(device_id)
        {
            return Err(ProtocolError::unauthorized());
        }
        let presented = sha256_hex(secret);
        self.transact(|store, now| {
            let device = store
                .devices
                .iter_mut()
                .find(|device| device.device_id == device_id);
            // An unknown id costs the same comparison as a wrong secret.
            let expected = device
                .as_ref()
                .map_or_else(|| "0".repeat(64), |device| device.secret_sha256.clone());
            let matched = super::secret_eq(&presented, &expected);
            match device {
                Some(device) if matched => {
                    device.last_seen_at = Some(timestamp(now));
                    Ok(AuthenticatedDevice {
                        device_id: device.device_id.clone(),
                        scopes: device.scopes.clone(),
                    })
                }
                _ => Err(ProtocolError::unauthorized()),
            }
        })?
    }

    /// Whether a device revoked in this process.
    pub(super) fn revoked_here(&self, device_id: &str) -> bool {
        lock(&self.inner.revoked).contains(device_id)
    }

    /// Whether a device is still paired, read from the store.
    pub(super) fn device_paired(&self, device_id: &str) -> bool {
        !self.revoked_here(device_id)
            && self.read_store().is_ok_and(|store| {
                store
                    .devices
                    .iter()
                    .any(|device| device.device_id == device_id)
            })
    }

    fn read_store(&self) -> Result<AccessFile, ProtocolError> {
        let _lock = lock_file(&self.inner.directory, false)
            .map_err(|_| ProtocolError::persistence_failed())?;
        load_store(&self.inner.directory)
    }

    fn transact<T>(
        &self,
        update: impl FnOnce(&mut AccessFile, DateTime<Utc>) -> T,
    ) -> Result<T, ProtocolError> {
        let _lock = lock_file(&self.inner.directory, true)
            .map_err(|_| ProtocolError::persistence_failed())?;
        let mut store = load_store(&self.inner.directory)?;
        let before = store.clone();
        let now = (self.inner.clock)();
        store.pairings.retain(|pairing| {
            DateTime::parse_from_rfc3339(&pairing.expires_at).is_ok_and(|expires| expires > now)
        });
        let result = update(&mut store, now);
        if store != before {
            let bytes =
                serde_json::to_vec(&store).map_err(|_| ProtocolError::persistence_failed())?;
            write_private(&self.inner.directory.join(ACCESS_FILE), &bytes)
                .map_err(|_| ProtocolError::persistence_failed())?;
        }
        Ok(result)
    }
}

/// Runs a remote access operation for a caller holding `granted`, whether
/// the runtime owner on the local desktop route or a paired device.
pub(super) fn dispatch_remote_operation(
    access: &RemoteAccess,
    request: &Request,
    granted: &BTreeSet<String>,
    requested_by: &str,
) -> Result<Value, ProtocolError> {
    request.validate_idempotency_key()?;
    let admin = || {
        if granted.contains(SCOPE_RUNTIME_ADMIN) {
            Ok(())
        } else {
            Err(ProtocolError::unauthorized())
        }
    };
    let body = &request.body;
    match request.operation {
        Operation::RuntimeInfo => {
            empty_body(body)?;
            let mut info = serde_json::to_value(access.runtime_info())
                .map_err(|_| ProtocolError::persistence_failed())?;
            info["certificate_sha256"] = json!(access.certificate_fingerprint().to_hex());
            info["update_request"] = json!(access.requested_update());
            Ok(info)
        }
        Operation::RemotePairingCreate => {
            admin()?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Body {
                #[serde(default)]
                scopes: Option<BTreeSet<String>>,
                #[serde(default)]
                endpoints: Option<Vec<String>>,
            }
            let body: Body = serde_json::from_value(body.clone())
                .map_err(|_| ProtocolError::invalid_request())?;
            let created = access.create_pairing_link_for(
                PairingLinkRequest {
                    scopes: body.scopes,
                    endpoints: body.endpoints,
                },
                granted,
            )?;
            Ok(json!({
                "link": created.link.to_uri(),
                "pairing_id": created.pairing_id,
                "expires_at": created.expires_at,
                "scopes": created.scopes,
            }))
        }
        Operation::RemoteDeviceList => {
            admin()?;
            empty_body(body)?;
            Ok(json!({"devices": access.list_devices()?}))
        }
        Operation::RemoteDeviceRevoke => {
            admin()?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Body {
                device_id: String,
            }
            let body: Body = serde_json::from_value(body.clone())
                .map_err(|_| ProtocolError::invalid_request())?;
            Ok(json!({"revoked": access.revoke_device(&body.device_id)?}))
        }
        Operation::RuntimeUpdate => {
            admin()?;
            #[derive(serde::Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Body {
                version: String,
            }
            let body: Body = serde_json::from_value(body.clone())
                .map_err(|_| ProtocolError::invalid_request())?;
            let request = access.request_update(&body.version, requested_by)?;
            Ok(json!({"version": request.version, "requested_at": request.requested_at}))
        }
        _ => Err(ProtocolError::unsupported_operation()),
    }
}

/// Whether the operation belongs to remote access rather than the desktop service.
pub(super) fn is_remote_access_operation(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::RuntimeInfo
            | Operation::RemotePairingCreate
            | Operation::RemoteDeviceList
            | Operation::RemoteDeviceRevoke
            | Operation::RuntimeUpdate
    )
}

fn empty_body(body: &Value) -> Result<(), ProtocolError> {
    if body == &json!({}) {
        Ok(())
    } else {
        Err(ProtocolError::invalid_request())
    }
}

pub(super) fn all_scopes() -> BTreeSet<String> {
    REMOTE_SCOPES
        .iter()
        .map(|scope| (*scope).to_owned())
        .collect()
}

fn validate_endpoints(endpoints: &[String]) -> Result<(), ProtocolError> {
    if endpoints.is_empty()
        || endpoints.len() > MAX_PAIRING_ENDPOINTS
        || !endpoints.iter().all(|endpoint| is_valid_endpoint(endpoint))
    {
        return Err(ProtocolError::invalid_request_with_reason(
            "Name one to eight host:port endpoints for the pairing link.",
        ));
    }
    Ok(())
}

fn is_valid_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_VERSION_LENGTH
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+'))
}

fn load_store(directory: &Path) -> Result<AccessFile, ProtocolError> {
    let Some(bytes) = read_private(&directory.join(ACCESS_FILE))
        .map_err(|_| ProtocolError::persistence_failed())?
    else {
        return Ok(AccessFile {
            version: 1,
            ..AccessFile::default()
        });
    };
    let store: AccessFile =
        serde_json::from_slice(&bytes).map_err(|_| ProtocolError::persistence_failed())?;
    if store_is_valid(&store) {
        Ok(store)
    } else {
        Err(ProtocolError::persistence_failed())
    }
}

fn store_is_valid(store: &AccessFile) -> bool {
    let scopes_valid = |scopes: &BTreeSet<String>| {
        !scopes.is_empty()
            && scopes
                .iter()
                .all(|scope| REMOTE_SCOPES.contains(&scope.as_str()))
    };
    let time_valid = |time: &str| DateTime::parse_from_rfc3339(time).is_ok();
    store.version == 1
        && store.devices.len() <= MAX_PAIRED_DEVICES
        && store.pairings.len() <= MAX_OUTSTANDING_PAIRINGS
        && store.devices.iter().all(|device| {
            Id::new(device.device_id.as_str()).is_ok()
                && is_lowercase_hex(&device.secret_sha256, 64)
                && is_valid_display_name(&device.name)
                && is_valid_display_name(&device.kind)
                && scopes_valid(&device.scopes)
                && time_valid(&device.created_at)
                && device.last_seen_at.as_deref().is_none_or(time_valid)
        })
        && store.pairings.iter().all(|pairing| {
            Id::new(pairing.pairing_id.as_str()).is_ok()
                && is_lowercase_hex(&pairing.secret_sha256, 64)
                && scopes_valid(&pairing.scopes)
                && time_valid(&pairing.created_at)
                && time_valid(&pairing.expires_at)
        })
}

fn lock_file(directory: &Path, exclusive: bool) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(directory.join(LOCK_FILE))?;
    if exclusive {
        file.lock_exclusive()?;
    } else {
        FileExt::lock_shared(&file)?;
    }
    Ok(file)
}

fn sha256_hex(secret: &str) -> String {
    super::desktop_dispatch::hex(&Sha256::digest(secret.as_bytes()))
}

fn random_hex<const N: usize>() -> Result<String, ProtocolError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| ProtocolError::persistence_failed())?;
    Ok(super::desktop_dispatch::hex(&bytes))
}

fn timestamp(time: DateTime<Utc>) -> String {
    time.to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
