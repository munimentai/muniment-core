//! Linux desktop client admission.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use muniment_attach::ProtocolError;

use super::desktop_admission::{admit_desktop_client_over_stream, write_protocol_error};
use super::linux::{CompanionProvenance, PeerCredentials};
use super::{verify_accepted_desktop_peer, Approval, DesktopClientAdmissionError};
use crate::browser_control::LinuxProcReader;

/// Authority and provenance carried by an admitted desktop client session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DesktopClientSession {
    pub capability: String,
    pub workspace: String,
    pub client_identity: String,
    pub provenance: CompanionProvenance,
}

/// Admits a verified desktop client and returns its connection capability.
pub fn admit_desktop_client(
    mut stream: UnixStream,
    peer_credentials: PeerCredentials,
    expected_desktop_executable: &Path,
    process_reader: &dyn LinuxProcReader,
    runtime_version: &str,
    approval: Option<Approval>,
    timeout: Duration,
) -> Result<(UnixStream, DesktopClientSession), DesktopClientAdmissionError> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or(DesktopClientAdmissionError::Timeout)?;
    let peer_authorized = verify_accepted_desktop_peer(
        &peer_credentials,
        expected_desktop_executable,
        process_reader,
    )
    .is_ok();
    if !peer_authorized {
        write_protocol_error(&mut stream, ProtocolError::unauthorized(), deadline);
        return Err(DesktopClientAdmissionError::PeerUnauthorized);
    }

    let admitted = admit_desktop_client_over_stream(
        &mut stream,
        runtime_version,
        approval.as_ref(),
        deadline,
    )?;

    Ok((
        stream,
        DesktopClientSession {
            capability: admitted.capability,
            workspace: admitted.workspace,
            client_identity: admitted.client_identity,
            provenance: CompanionProvenance {
                profile: approval
                    .map_or_else(|| "desktop-owner".into(), |approval| approval.profile),
                companion_kind: admitted.companion_kind,
                companion_version: admitted.companion_version,
                peer_uid: peer_credentials.uid,
                peer_pid: peer_credentials.pid as u32,
            },
        },
    ))
}
