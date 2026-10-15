//! The remote listener's TLS identity and the runtime's id and display name.
//!
//! The first open generates an ECDSA P-256 key and a self-signed certificate.
//! Clients pin the certificate's SHA-256, so the identity is never replaced
//! once written: a missing certificate or key beside an existing identity
//! record fails the open instead of silently changing the fingerprint.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use muniment_attach::{is_valid_display_name, CertificateFingerprint, Id};

const IDENTITY_FILE: &str = "identity.json";
const CERTIFICATE_FILE: &str = "identity-certificate.der";
const KEY_FILE: &str = "identity-key.der";
/// The display name a runtime takes when its host names none.
pub const DEFAULT_RUNTIME_NAME: &str = "Muniment runtime";

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityRecord {
    version: u32,
    runtime_id: String,
    runtime_name: String,
}

pub(super) struct RemoteIdentity {
    pub(super) runtime_id: String,
    pub(super) runtime_name: String,
    pub(super) certificate: Vec<u8>,
    key: Vec<u8>,
    pub(super) fingerprint: CertificateFingerprint,
}

impl RemoteIdentity {
    /// Loads the identity under `directory`, or creates it on first use. A
    /// valid `name` replaces the stored display name.
    pub(super) fn load_or_create(directory: &Path, name: Option<&str>) -> io::Result<Self> {
        let record_path = directory.join(IDENTITY_FILE);
        let identity = match read_private(&record_path)? {
            Some(bytes) => {
                let record: IdentityRecord = serde_json::from_slice(&bytes)
                    .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
                if record.version != 1
                    || Id::new(record.runtime_id.as_str()).is_err()
                    || !is_valid_display_name(&record.runtime_name)
                {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let certificate = read_private(&directory.join(CERTIFICATE_FILE))?
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                let key = read_private(&directory.join(KEY_FILE))?
                    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidData))?;
                Self {
                    runtime_id: record.runtime_id,
                    runtime_name: record.runtime_name,
                    fingerprint: CertificateFingerprint::of_certificate(&certificate),
                    certificate,
                    key,
                }
            }
            None => Self::create(directory)?,
        };
        let mut identity = identity;
        // The configuration check proves the key signs for the certificate.
        identity
            .server_config()
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        if let Some(name) = name.filter(|name| is_valid_display_name(name)) {
            if name != identity.runtime_name {
                identity.runtime_name = name.to_owned();
                identity.write_record(directory)?;
            }
        }
        Ok(identity)
    }

    fn create(directory: &Path) -> io::Result<Self> {
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map_err(io::Error::other)?;
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).map_err(io::Error::other)?;
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, DEFAULT_RUNTIME_NAME);
        let certificate = params.self_signed(&key).map_err(io::Error::other)?;
        let identity = Self {
            runtime_id: uuid::Uuid::new_v4().to_string(),
            runtime_name: DEFAULT_RUNTIME_NAME.to_owned(),
            fingerprint: CertificateFingerprint::of_certificate(certificate.der()),
            certificate: certificate.der().to_vec(),
            key: key.serialize_der(),
        };
        write_private(&directory.join(KEY_FILE), &identity.key)?;
        write_private(&directory.join(CERTIFICATE_FILE), &identity.certificate)?;
        // The record is written last, so a partial first run starts over.
        identity.write_record(directory)?;
        Ok(identity)
    }

    fn write_record(&self, directory: &Path) -> io::Result<()> {
        let record = serde_json::to_vec(&IdentityRecord {
            version: 1,
            runtime_id: self.runtime_id.clone(),
            runtime_name: self.runtime_name.clone(),
        })
        .map_err(io::Error::other)?;
        write_private(&directory.join(IDENTITY_FILE), &record)
    }

    /// A TLS 1.3 server configuration with this identity, no session tickets
    /// and no session cache.
    pub(super) fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, rustls::Error> {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(
                self.certificate.clone(),
            )],
            rustls::pki_types::PrivateKeyDer::Pkcs8(self.key.clone().into()),
        )?;
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Arc::new(config))
    }
}

/// Creates `directory` and, on Unix, makes it readable by its owner only.
pub(super) fn ensure_private_directory(directory: &Path) -> io::Result<()> {
    std::fs::create_dir_all(directory)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Reads a file the runtime wrote for its owner. `None` means it does not
/// exist. On Unix a file another user owns, or that its group or others can
/// read, is refused.
pub(super) fn read_private(path: &Path) -> io::Result<Option<Vec<u8>>> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
    }
    let mut bytes = Vec::new();
    io::Read::read_to_end(&mut file, &mut bytes)?;
    Ok(Some(bytes))
}

/// Replaces `path` with `bytes` through a new owner-only file.
pub(super) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary = temporary_path(path);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let written = options
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| crate::atomic_file::replace(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

fn temporary_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    path.with_file_name(format!(".{name}.{}.tmp", uuid::Uuid::now_v7()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "muniment-remote-identity-{name}-{}",
            uuid::Uuid::now_v7()
        ));
        ensure_private_directory(&directory).unwrap();
        directory
    }

    #[test]
    fn the_identity_is_created_once_and_reloaded_unchanged() {
        let directory = directory("reload");
        let created = RemoteIdentity::load_or_create(&directory, None).unwrap();
        assert!(Id::new(created.runtime_id.as_str()).is_ok());
        assert_eq!(created.runtime_name, DEFAULT_RUNTIME_NAME);
        assert_eq!(
            created.fingerprint,
            CertificateFingerprint::of_certificate(&created.certificate)
        );
        let reloaded = RemoteIdentity::load_or_create(&directory, Some("Build box")).unwrap();
        assert_eq!(reloaded.runtime_id, created.runtime_id);
        assert_eq!(reloaded.fingerprint, created.fingerprint);
        assert_eq!(reloaded.runtime_name, "Build box");
        #[cfg(unix)]
        for file in [IDENTITY_FILE, CERTIFICATE_FILE, KEY_FILE] {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(directory.join(file))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_missing_key_fails_closed_instead_of_changing_the_fingerprint() {
        let directory = directory("missing-key");
        RemoteIdentity::load_or_create(&directory, None).unwrap();
        std::fs::remove_file(directory.join(KEY_FILE)).unwrap();
        assert!(RemoteIdentity::load_or_create(&directory, None).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_key_others_can_read_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let directory = directory("mode");
        RemoteIdentity::load_or_create(&directory, None).unwrap();
        std::fs::set_permissions(
            directory.join(KEY_FILE),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert_eq!(
            RemoteIdentity::load_or_create(&directory, None)
                .err()
                .unwrap()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_dir_all(directory).unwrap();
    }
}
