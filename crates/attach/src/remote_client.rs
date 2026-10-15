//! The client side of the remote attach route: TLS pinned to one runtime
//! certificate, pairing-link redemption, and reconnection with the stored
//! device credential.

use std::collections::BTreeSet;
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::client::AuthorizationSummary;
use crate::client_stream::{read_value, write_all_before};
use crate::desktop_client::DesktopClient;
use crate::protocol_helpers::{fresh_nonce, fresh_request_id, map_frame_error, parse_message};
use crate::{
    encode_frame, is_lowercase_hex, is_valid_display_name, Authorization, CertificateFingerprint,
    Client, ClientError, DeviceCredential, ErrorCode, ErrorEnvelope, Hello, Id, PairingLink,
    PairingRedemption, Protocol, RemoteClientAuthorizedGrant, TlsStream, VersionRange, Welcome,
    DEVICE_SECRET_HEX_LENGTH, REMOTE_SCOPES,
};

const MAX_EXPIRES_AT: u64 = 8 * 60 * 60;
const MAX_IDLE_TIMEOUT: u64 = 15 * 60;

/// Why a remote runtime could not be reached or admitted this client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemoteConnectError {
    /// No endpoint accepted a TCP connection and a TLS handshake.
    Unreachable,
    /// An endpoint answered with a certificate other than the pinned one, and
    /// no endpoint answered with the pinned one.
    CertificateMismatch,
    /// The runtime answered with a different runtime id than the link or the
    /// saved record names.
    RuntimeMismatch,
    /// The runtime refused the pairing secret or the device credential.
    Unauthorized,
    /// The attach exchange failed after the TLS handshake.
    Client(ClientError),
}

impl std::fmt::Display for RemoteConnectError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable => formatter.write_str("no runtime endpoint answered"),
            Self::CertificateMismatch => {
                formatter.write_str("the runtime's certificate does not match its pin")
            }
            Self::RuntimeMismatch => formatter.write_str("a different runtime answered"),
            Self::Unauthorized => formatter.write_str("the runtime refused this device"),
            Self::Client(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RemoteConnectError {}

impl From<ClientError> for RemoteConnectError {
    fn from(error: ClientError) -> Self {
        Self::Client(error)
    }
}

/// How this client names itself to a remote runtime.
#[derive(Clone, Debug)]
pub struct RemoteClientOptions {
    /// The client kind, such as `desktop-client` or `cli`.
    pub kind: String,
    pub version: String,
    /// The name the runtime owner sees in the device list.
    pub device_name: Option<String>,
    /// Scopes to ask for when pairing. They narrow the link's scopes.
    pub scopes: Option<BTreeSet<String>>,
    /// The bound on each network step and each request.
    pub io_timeout: Duration,
}

/// What a client keeps about one paired runtime. It holds the device secret,
/// so the file it lives in is readable by its owner only.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteRuntimeRecord {
    pub runtime_id: Id,
    pub runtime_name: String,
    pub endpoints: Vec<String>,
    pub fingerprint: CertificateFingerprint,
    pub credential: DeviceCredential,
    pub scopes: BTreeSet<String>,
}

impl std::fmt::Debug for RemoteRuntimeRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RemoteRuntimeRecord")
            .field("runtime_id", &self.runtime_id)
            .field("runtime_name", &self.runtime_name)
            .field("endpoints", &self.endpoints)
            .field("fingerprint", &self.fingerprint)
            .field("credential", &self.credential)
            .field("scopes", &self.scopes)
            .finish()
    }
}

impl RemoteRuntimeRecord {
    /// Writes the record through a new owner-only file that replaces `path`.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        std::fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".remote-runtime-{}.tmp", fresh_nonce_io()?));
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let file = options.open(&temporary)?;
            serde_json::to_writer(&file, self).map_err(io::Error::other)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    /// Reads a record. On Unix a file that its group or others can read is refused.
    pub fn load(path: &Path) -> io::Result<Self> {
        let file = std::fs::File::open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if file.metadata()?.mode() & 0o077 != 0 {
                return Err(io::ErrorKind::PermissionDenied.into());
            }
        }
        let record: Self = serde_json::from_reader(file).map_err(io::Error::other)?;
        let valid = is_lowercase_hex(&record.credential.secret, DEVICE_SECRET_HEX_LENGTH)
            && is_valid_display_name(&record.runtime_name)
            && !record.endpoints.is_empty()
            && record.endpoints.iter().all(|e| crate::is_valid_endpoint(e));
        if valid {
            Ok(record)
        } else {
            Err(io::ErrorKind::InvalidData.into())
        }
    }
}

fn fresh_nonce_io() -> io::Result<String> {
    fresh_nonce().map_err(|_| io::Error::other("randomness is unavailable"))
}

/// Accepts exactly the certificate whose SHA-256 is pinned and checks the
/// handshake signatures with its key, so a server must hold that key.
#[derive(Debug)]
struct PinnedRuntimeCertificate {
    fingerprint: CertificateFingerprint,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl rustls::client::danger::ServerCertVerifier for PinnedRuntimeCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        if CertificateFingerprint::of_certificate(end_entity.as_ref()) == self.fingerprint {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // The configuration offers TLS 1.3 only.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        signature: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A TLS 1.3 client configuration that trusts only the pinned certificate
/// and keeps no session tickets.
pub fn pinned_client_config(fingerprint: CertificateFingerprint) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("the ring provider supports TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedRuntimeCertificate {
            fingerprint,
            provider,
        }))
        .with_no_client_auth();
    config.resumption = rustls::client::Resumption::disabled();
    Arc::new(config)
}

/// Connects to the first endpoint that completes a TLS handshake with the
/// pinned certificate.
pub fn connect_pinned(
    endpoints: &[String],
    fingerprint: CertificateFingerprint,
    timeout: Duration,
) -> Result<TlsStream, RemoteConnectError> {
    let config = pinned_client_config(fingerprint);
    let mut mismatch = false;
    for endpoint in endpoints {
        match connect_endpoint(endpoint, &config, timeout) {
            Ok(stream) => return Ok(stream),
            Err(RemoteConnectError::CertificateMismatch) => mismatch = true,
            Err(_) => {}
        }
    }
    Err(if mismatch {
        RemoteConnectError::CertificateMismatch
    } else {
        RemoteConnectError::Unreachable
    })
}

fn connect_endpoint(
    endpoint: &str,
    config: &Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<TlsStream, RemoteConnectError> {
    if !crate::is_valid_endpoint(endpoint) {
        return Err(RemoteConnectError::Unreachable);
    }
    let host = endpoint
        .rsplit_once(':')
        .map(|(host, _)| host.trim_start_matches('[').trim_end_matches(']'))
        .ok_or(RemoteConnectError::Unreachable)?;
    let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| RemoteConnectError::Unreachable)?;
    let addresses = endpoint
        .to_socket_addrs()
        .map_err(|_| RemoteConnectError::Unreachable)?;
    let deadline = Instant::now() + timeout;
    let mut result = Err(RemoteConnectError::Unreachable);
    for address in addresses {
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
        else {
            break;
        };
        let Ok(socket) = TcpStream::connect_timeout(&address, remaining) else {
            continue;
        };
        let _ = socket.set_nodelay(true);
        let connection = rustls::ClientConnection::new(Arc::clone(config), server_name.clone())
            .map_err(|_| RemoteConnectError::Unreachable)?;
        let mut stream = TlsStream::new(connection, socket);
        match stream.handshake_before(deadline) {
            Ok(()) => return Ok(stream),
            Err(error) if is_certificate_error(&error) => {
                result = Err(RemoteConnectError::CertificateMismatch);
            }
            Err(_) => {}
        }
    }
    result
}

fn is_certificate_error(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|error| matches!(error, rustls::Error::InvalidCertificate(_)))
}

/// Redeems a pairing link once and answers the admitted client with the
/// record to save for later connections.
pub fn pair_with_link(
    link: &PairingLink,
    options: &RemoteClientOptions,
) -> Result<(DesktopClient, RemoteRuntimeRecord), RemoteConnectError> {
    let stream = connect_pinned(&link.endpoints, link.fingerprint, options.io_timeout)?;
    let pairing = PairingRedemption {
        secret: link.secret.clone(),
        device_name: options.device_name.clone(),
        scopes: options.scopes.clone(),
    };
    let (client, credential) = handshake_remote(
        stream,
        options,
        &link.runtime_id,
        Id::new(fresh_request_id()?.as_str()).map_err(|_| ClientError::UnexpectedMessage)?,
        None,
        Some(pairing),
    )?;
    let credential =
        credential.ok_or(RemoteConnectError::Client(ClientError::UnexpectedMessage))?;
    let scopes = client.remote_scopes().cloned().unwrap_or_default();
    let record = RemoteRuntimeRecord {
        runtime_id: link.runtime_id.clone(),
        runtime_name: client.runtime_info().map_or_else(
            || link.runtime_name.clone(),
            |info| info.runtime_name.clone(),
        ),
        endpoints: link.endpoints.clone(),
        fingerprint: link.fingerprint,
        credential,
        scopes,
    };
    Ok((client, record))
}

/// Connects to a paired runtime with its saved device credential.
pub fn connect_remote_runtime(
    record: &RemoteRuntimeRecord,
    options: &RemoteClientOptions,
) -> Result<DesktopClient, RemoteConnectError> {
    let stream = connect_pinned(&record.endpoints, record.fingerprint, options.io_timeout)?;
    let (client, credential) = handshake_remote(
        stream,
        options,
        &record.runtime_id,
        record.credential.device_id.clone(),
        Some(record.credential.secret.clone()),
        None,
    )?;
    if credential.is_some() {
        return Err(ClientError::UnexpectedMessage.into());
    }
    Ok(client)
}

fn handshake_remote(
    mut stream: TlsStream,
    options: &RemoteClientOptions,
    runtime_id: &Id,
    client_id: Id,
    credential: Option<String>,
    pairing: Option<PairingRedemption>,
) -> Result<(DesktopClient, Option<DeviceCredential>), RemoteConnectError> {
    let deadline = || Instant::now() + options.io_timeout;
    let hello = Hello {
        protocol: Protocol,
        client: Client {
            kind: options.kind.clone(),
            version: options.version.clone(),
        },
        supported: VersionRange { min: 1, max: 1 },
        client_nonce: fresh_nonce()?,
        authorized_client_id: client_id,
        authorized_client_credential: credential,
        pairing,
    };
    let bytes = encode_frame(&hello).map_err(map_frame_error)?;
    write_all_before(&mut stream, &bytes, deadline())?;

    let welcome: Welcome = parse_message(admission_value(&mut stream, deadline())?)?;
    if welcome.selected != 1
        || welcome.authorization != Authorization::Authorized
        || !is_lowercase_hex(&welcome.server_nonce, 32)
    {
        return Err(ClientError::UnexpectedMessage.into());
    }
    if welcome
        .runtime
        .as_ref()
        .is_none_or(|runtime| runtime.runtime_id != runtime_id.as_str())
    {
        return Err(RemoteConnectError::RuntimeMismatch);
    }

    let grant: RemoteClientAuthorizedGrant =
        parse_message(admission_value(&mut stream, deadline())?)?;
    let scopes_valid = !grant.scopes.is_empty()
        && grant
            .scopes
            .iter()
            .all(|scope| REMOTE_SCOPES.contains(&scope.as_str()));
    let credential_valid = grant
        .device_credential
        .as_ref()
        .is_none_or(|credential| is_lowercase_hex(&credential.secret, DEVICE_SECRET_HEX_LENGTH));
    if !scopes_valid
        || !credential_valid
        || grant.workspace_scopes.len() > 1
        || !is_lowercase_hex(&grant.capability, 64)
        || grant.expires_at == 0
        || grant.expires_at > MAX_EXPIRES_AT
        || grant.idle_timeout_seconds == 0
        || grant.idle_timeout_seconds > MAX_IDLE_TIMEOUT
    {
        return Err(ClientError::UnexpectedMessage.into());
    }
    let client = DesktopClient::admitted(
        Box::new(stream),
        welcome,
        grant.profile_id,
        grant.workspace_scopes,
        grant.capability,
        AuthorizationSummary {
            expires_in_seconds: grant.expires_at,
            idle_timeout_seconds: grant.idle_timeout_seconds,
        },
        Some(grant.scopes),
        options.io_timeout,
    );
    Ok((client, grant.device_credential))
}

/// Reads one admission message. A refusal from the runtime ends the exchange
/// as `Unauthorized`.
fn admission_value(stream: &mut TlsStream, deadline: Instant) -> Result<Value, RemoteConnectError> {
    let value = read_value(stream, deadline)?;
    if value.get("ok") == Some(&Value::Bool(false)) {
        let error: ErrorEnvelope =
            serde_json::from_value(value).map_err(|_| ClientError::MalformedFrame)?;
        return Err(match error.error.code() {
            ErrorCode::Unauthorized => RemoteConnectError::Unauthorized,
            ErrorCode::ProtocolIncompatible => ClientError::ProtocolIncompatible.into(),
            _ => ClientError::UnexpectedMessage.into(),
        });
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_saved_record_is_owner_only_and_round_trips() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-record-{}", fresh_nonce().unwrap()));
        let path = directory.join("runtime.json");
        let record = RemoteRuntimeRecord {
            runtime_id: Id::new("018f0000-0000-7000-8000-000000000042").unwrap(),
            runtime_name: "Box".into(),
            endpoints: vec!["127.0.0.1:7443".into()],
            fingerprint: CertificateFingerprint::of_certificate(b"der"),
            credential: DeviceCredential {
                device_id: Id::new("018f0000-0000-7000-8000-000000000043").unwrap(),
                secret: "cd".repeat(32),
            },
            scopes: BTreeSet::from([crate::SCOPE_THREAD_READ.to_owned()]),
        };
        record.save(&path).unwrap();
        assert_eq!(RemoteRuntimeRecord::load(&path).unwrap(), record);
        assert!(!format!("{record:?}").contains(&"cd".repeat(32)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert_eq!(
                RemoteRuntimeRecord::load(&path).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }
}
