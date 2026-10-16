//! The relay encryption contract `muniment.relay-encryption/1`.
//!
//! A desktop and the phone paired with it agree on two directional keys at
//! pairing (revision 2 of the pairing contract) and seal every session event
//! and command the cloud relay carries between them. The relay reads only the
//! plaintext header of each sealed payload. This module holds the agreement,
//! the key derivation, sealing and opening, and the replay window; it makes no
//! network call and stores nothing.

use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, hkdf, hmac};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use zeroize::{Zeroize, Zeroizing};

/// The contract version every sealed payload and header carries.
pub const CONTRACT_VERSION: &str = "muniment.relay-encryption/1";

/// The pairing revision that exchanges the agreement keys.
pub const PAIRING_CONTRACT_VERSION: &str = "muniment.remote-control-pairing/2";

/// How many command counters below the highest accepted one stay acceptable.
pub const REPLAY_WINDOW: u64 = 64;

/// The largest serialized sealed event.
pub const MAX_SEALED_EVENT_BYTES: usize = 64 * 1024;

/// The longest steer or follow-up text, in UTF-8 bytes.
pub const MAX_COMMAND_TEXT_BYTES: usize = 16 * 1024;

/// The most messages one directional key seals. A random 96-bit nonce stays
/// safe up to this count.
pub const MAX_MESSAGES_PER_KEY: u64 = 1 << 32;

const PROOF_LABEL: &str = "muniment.relay-encryption/1 mobile-agreement";
const INFO_LABEL: &str = "muniment.relay-encryption/1 ";
const NONCE_LENGTH: usize = 12;
const KEY_LENGTH: usize = 32;

/// Why an agreement, a seal or an open failed. No variant carries key
/// material or message content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayCryptoError {
    /// A value does not match the contract shapes.
    Malformed,
    /// The ciphertext does not authenticate under the key and the header.
    AuthenticationFailed,
    /// The opened message does not bind to its header or envelope.
    BindingMismatch,
    /// A returned agreement key is not the one this side sent.
    KeyMismatch,
    /// The phone's proof does not verify under the pairing secret.
    ProofInvalid,
    /// The key agreement produced the all-zero secret.
    Agreement,
    /// The key sealed its last allowed message.
    Exhausted,
    /// The system random source failed.
    Random,
}

impl fmt::Display for RelayCryptoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Malformed => "the relay payload does not match the contract",
            Self::AuthenticationFailed => "the relay payload did not authenticate",
            Self::BindingMismatch => "the relay payload does not match its header",
            Self::KeyMismatch => "the paired agreement key is not this device's key",
            Self::ProofInvalid => "the phone's agreement proof did not verify",
            Self::Agreement => "the key agreement failed",
            Self::Exhausted => "the relay key sealed its last message",
            Self::Random => "the system random source failed",
        })
    }
}

impl std::error::Error for RelayCryptoError {}

/// Encodes bytes as unpadded base64url.
pub fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn decode_exact<const N: usize>(value: &str) -> Result<[u8; N], RelayCryptoError> {
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| RelayCryptoError::Malformed)?,
    );
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| RelayCryptoError::Malformed)
}

fn random<const N: usize>() -> Result<[u8; N], RelayCryptoError> {
    let mut bytes = [0; N];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| RelayCryptoError::Random)?;
    Ok(bytes)
}

/// One direction's AES-256-GCM key. It erases itself when dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct DirectionKey([u8; KEY_LENGTH]);

impl DirectionKey {
    pub fn from_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        Self(bytes)
    }

    /// Decodes a base64url key.
    pub fn decode(value: &str) -> Result<Self, RelayCryptoError> {
        decode_exact(value).map(Self)
    }

    /// The key as base64url, for the keychain alone.
    pub fn encode(&self) -> String {
        encode(&self.0)
    }

    fn aead(&self) -> aead::LessSafeKey {
        aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &self.0)
                .expect("an AES-256-GCM key is 32 bytes"),
        )
    }
}

impl Drop for DirectionKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for DirectionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectionKey(<redacted>)")
    }
}

/// The two directional keys of one pair.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayKeys {
    /// The pair's lowercase UUID.
    pub pair_id: String,
    pub desktop_to_phone: DirectionKey,
    pub phone_to_desktop: DirectionKey,
}

impl fmt::Debug for RelayKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayKeys")
            .field("pair_id", &self.pair_id)
            .field("desktop_to_phone", &"<redacted>")
            .field("phone_to_desktop", &"<redacted>")
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRelayKeys {
    contract_version: String,
    pair_id: String,
    desktop_to_phone_key: String,
    phone_to_desktop_key: String,
}

impl Drop for StoredRelayKeys {
    fn drop(&mut self) {
        self.desktop_to_phone_key.zeroize();
        self.phone_to_desktop_key.zeroize();
    }
}

impl RelayKeys {
    /// The keys as one JSON secret for a keychain entry.
    pub fn to_secret(&self) -> Zeroizing<String> {
        let stored = StoredRelayKeys {
            contract_version: CONTRACT_VERSION.to_owned(),
            pair_id: self.pair_id.clone(),
            desktop_to_phone_key: self.desktop_to_phone.encode(),
            phone_to_desktop_key: self.phone_to_desktop.encode(),
        };
        Zeroizing::new(serde_json::to_string(&stored).expect("relay keys serialize"))
    }

    /// Reads keys a keychain entry holds.
    pub fn from_secret(secret: &str) -> Result<Self, RelayCryptoError> {
        let stored: StoredRelayKeys =
            serde_json::from_str(secret).map_err(|_| RelayCryptoError::Malformed)?;
        if stored.contract_version != CONTRACT_VERSION || !valid_uuid(&stored.pair_id) {
            return Err(RelayCryptoError::Malformed);
        }
        Ok(Self {
            pair_id: stored.pair_id.clone(),
            desktop_to_phone: DirectionKey::decode(&stored.desktop_to_phone_key)?,
            phone_to_desktop: DirectionKey::decode(&stored.phone_to_desktop_key)?,
        })
    }
}

/// The 32-byte secret the desktop shows only in the QR code. It erases itself
/// when dropped.
pub struct PairingSecret([u8; KEY_LENGTH]);

impl PairingSecret {
    pub fn generate() -> Result<Self, RelayCryptoError> {
        random().map(Self)
    }

    pub fn decode(value: &str) -> Result<Self, RelayCryptoError> {
        decode_exact(value).map(Self)
    }

    /// The secret as base64url, for the QR code alone.
    pub fn encode(&self) -> String {
        encode(&self.0)
    }
}

impl Drop for PairingSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for PairingSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PairingSecret(<redacted>)")
    }
}

/// One side's X25519 agreement key pair for one pairing attempt. The private
/// key erases itself when dropped.
pub struct AgreementKeyPair {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl AgreementKeyPair {
    pub fn generate() -> Result<Self, RelayCryptoError> {
        let bytes = Zeroizing::new(random::<KEY_LENGTH>()?);
        Ok(Self::from_private_bytes(*bytes))
    }

    /// A key pair from a known private key, as the contract vectors give one.
    pub fn from_private_bytes(bytes: [u8; KEY_LENGTH]) -> Self {
        let secret = x25519_dalek::StaticSecret::from(bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// The public key as base64url.
    pub fn public_key(&self) -> String {
        encode(self.public.as_bytes())
    }

    /// `X25519(own private key, peer public key)`, refusing the all-zero result.
    pub fn agree(&self, peer_public_key: &str) -> Result<Zeroizing<[u8; 32]>, RelayCryptoError> {
        let peer = x25519_dalek::PublicKey::from(decode_exact::<KEY_LENGTH>(peer_public_key)?);
        let shared = self.secret.diffie_hellman(&peer);
        if !shared.was_contributory() {
            return Err(RelayCryptoError::Agreement);
        }
        Ok(Zeroizing::new(*shared.as_bytes()))
    }
}

impl fmt::Debug for AgreementKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgreementKeyPair")
            .field("public", &self.public_key())
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// The six lines the phone's proof covers, joined by `0A`.
pub fn proof_transcript(
    desktop_device_id: &str,
    mobile_device_id: &str,
    challenge: &str,
    desktop_agreement_key: &str,
    mobile_agreement_key: &str,
) -> String {
    [
        PROOF_LABEL,
        desktop_device_id,
        mobile_device_id,
        challenge,
        desktop_agreement_key,
        mobile_agreement_key,
    ]
    .join("\n")
}

/// `HMAC-SHA256(pairing_secret, transcript)` as base64url.
pub fn agreement_proof(secret: &PairingSecret, transcript: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, &secret.0);
    encode(hmac::sign(&key, transcript.as_bytes()).as_ref())
}

/// Verifies a proof in constant time.
pub fn verify_agreement_proof(secret: &PairingSecret, transcript: &str, proof: &str) -> bool {
    let Ok(tag) = decode_exact::<32>(proof) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, &secret.0);
    hmac::verify(&key, transcript.as_bytes(), &tag).is_ok()
}

/// The HKDF info for one direction: the label, the direction, `00`, the pair
/// id and both raw agreement keys.
pub fn key_info(
    direction: &str,
    pair_id: &str,
    desktop_agreement_key: &[u8; 32],
    mobile_agreement_key: &[u8; 32],
) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO_LABEL.len() + direction.len() + 1 + pair_id.len() + 64);
    info.extend_from_slice(INFO_LABEL.as_bytes());
    info.extend_from_slice(direction.as_bytes());
    info.push(0);
    info.extend_from_slice(pair_id.as_bytes());
    info.extend_from_slice(desktop_agreement_key);
    info.extend_from_slice(mobile_agreement_key);
    info
}

struct KeyLength;

impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        KEY_LENGTH
    }
}

/// Derives both directional keys from the shared secret.
pub fn derive_relay_keys(
    shared: &[u8; 32],
    secret: &PairingSecret,
    pair_id: &str,
    desktop_agreement_key: &str,
    mobile_agreement_key: &str,
) -> Result<RelayKeys, RelayCryptoError> {
    if !valid_uuid(pair_id) {
        return Err(RelayCryptoError::Malformed);
    }
    if shared.iter().all(|byte| *byte == 0) {
        return Err(RelayCryptoError::Agreement);
    }
    let desktop = decode_exact::<32>(desktop_agreement_key)?;
    let mobile = decode_exact::<32>(mobile_agreement_key)?;
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &secret.0).extract(shared);
    let expand = |direction: &str| -> Result<DirectionKey, RelayCryptoError> {
        let info = key_info(direction, pair_id, &desktop, &mobile);
        let mut key = [0; KEY_LENGTH];
        prk.expand(&[&info], KeyLength)
            .and_then(|okm| okm.fill(&mut key))
            .map_err(|_| RelayCryptoError::Agreement)?;
        Ok(DirectionKey(key))
    };
    Ok(RelayKeys {
        pair_id: pair_id.to_owned(),
        desktop_to_phone: expand("desktop-to-phone")?,
        phone_to_desktop: expand("phone-to-desktop")?,
    })
}

/// The pair the cloud returns once the phone authorizes, as the desktop
/// checks it.
#[derive(Clone, Copy, Debug)]
pub struct AuthorizedAgreement<'a> {
    pub pair_id: &'a str,
    pub desktop_device_id: &'a str,
    pub mobile_device_id: &'a str,
    pub desktop_agreement_key: &'a str,
    pub mobile_agreement_key: &'a str,
    pub mobile_agreement_proof: &'a str,
}

/// The desktop's agreement material for one pairing challenge: its key pair,
/// the pairing secret, and the challenge the cloud issued. Dropping it erases
/// the private key and the secret.
pub struct DesktopAgreement {
    key_pair: AgreementKeyPair,
    secret: PairingSecret,
    challenge: Option<String>,
}

impl fmt::Debug for DesktopAgreement {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DesktopAgreement")
            .field("agreement_key", &self.key_pair.public_key())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl DesktopAgreement {
    /// Fresh agreement material from the system random source.
    pub fn generate() -> Result<Self, RelayCryptoError> {
        Ok(Self::from_parts(
            AgreementKeyPair::generate()?,
            PairingSecret::generate()?,
        ))
    }

    pub fn from_parts(key_pair: AgreementKeyPair, secret: PairingSecret) -> Self {
        Self {
            key_pair,
            secret,
            challenge: None,
        }
    }

    /// The agreement public key the challenge request carries.
    pub fn agreement_key(&self) -> String {
        self.key_pair.public_key()
    }

    /// The pairing secret for the QR code alone.
    pub fn pairing_secret(&self) -> String {
        self.secret.encode()
    }

    /// Records the challenge the cloud issued, which the proof covers.
    pub fn set_challenge(&mut self, challenge: &str) {
        self.challenge = Some(challenge.to_owned());
    }

    /// Checks the authorized pair and derives the relay keys. The pair must
    /// carry this side's agreement key and a proof that verifies under the
    /// pairing secret. The agreement material is erased either way.
    pub fn complete(self, pair: &AuthorizedAgreement<'_>) -> Result<RelayKeys, RelayCryptoError> {
        let challenge = self
            .challenge
            .as_deref()
            .ok_or(RelayCryptoError::Malformed)?;
        if pair.desktop_agreement_key != self.key_pair.public_key() {
            return Err(RelayCryptoError::KeyMismatch);
        }
        decode_exact::<32>(pair.mobile_agreement_key)?;
        let transcript = proof_transcript(
            pair.desktop_device_id,
            pair.mobile_device_id,
            challenge,
            pair.desktop_agreement_key,
            pair.mobile_agreement_key,
        );
        if !verify_agreement_proof(&self.secret, &transcript, pair.mobile_agreement_proof) {
            return Err(RelayCryptoError::ProofInvalid);
        }
        let shared = self.key_pair.agree(pair.mobile_agreement_key)?;
        derive_relay_keys(
            &shared,
            &self.secret,
            pair.pair_id,
            pair.desktop_agreement_key,
            pair.mobile_agreement_key,
        )
    }
}

/// Whether a value is a lowercase UUID string.
pub fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
}

/// Whether a value is a relay identifier: 8 to 128 ASCII letters, digits, `_` or `-`.
pub fn valid_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// Whether a value is a UTC timestamp with exactly three fractional digits and `Z`.
pub fn valid_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    let shape = bytes.len() == 24
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            4 | 7 => *byte == b'-',
            10 => *byte == b'T',
            13 | 16 => *byte == b':',
            19 => *byte == b'.',
            23 => *byte == b'Z',
            _ => byte.is_ascii_digit(),
        });
    shape && chrono::DateTime::parse_from_rfc3339(value).is_ok()
}

/// Formats a time as the contract's timestamp.
pub fn timestamp(time: chrono::DateTime<chrono::Utc>) -> String {
    time.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()
}

fn valid_positive(value: &str) -> bool {
    (1..=19).contains(&value.len())
        && !value.starts_with('0')
        && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(deserializer)
}

/// The phase an event header reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Running,
    WaitingForPermission,
    Completed,
    Failed,
    Cancelled,
}

impl Phase {
    pub fn terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// The pending permission gate an event header carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GateWindow {
    pub gate_id: String,
    pub requested_at: String,
    pub expires_at: String,
}

/// The plaintext header of a sealed event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventHeader {
    pub contract_version: String,
    pub header_type: String,
    pub session_id: String,
    pub run_id: String,
    pub sequence: String,
    pub phase: Phase,
    #[serde(deserialize_with = "required_nullable")]
    pub permission: Option<GateWindow>,
    pub occurred_at: String,
}

impl EventHeader {
    pub fn new(
        session_id: &str,
        run_id: &str,
        sequence: u64,
        phase: Phase,
        permission: Option<GateWindow>,
        occurred_at: &str,
    ) -> Self {
        Self {
            contract_version: CONTRACT_VERSION.to_owned(),
            header_type: "event".to_owned(),
            session_id: session_id.to_owned(),
            run_id: run_id.to_owned(),
            sequence: sequence.to_string(),
            phase,
            permission,
            occurred_at: occurred_at.to_owned(),
        }
    }

    fn validate(&self) -> Result<(), RelayCryptoError> {
        let permission_valid = match (&self.permission, self.phase) {
            (Some(gate), Phase::WaitingForPermission) => {
                valid_id(&gate.gate_id)
                    && valid_timestamp(&gate.requested_at)
                    && valid_timestamp(&gate.expires_at)
            }
            (None, phase) => phase != Phase::WaitingForPermission,
            (Some(_), _) => false,
        };
        let valid = self.contract_version == CONTRACT_VERSION
            && self.header_type == "event"
            && valid_id(&self.session_id)
            && valid_id(&self.run_id)
            && valid_positive(&self.sequence)
            && permission_valid
            && valid_timestamp(&self.occurred_at);
        valid.then_some(()).ok_or(RelayCryptoError::Malformed)
    }
}

/// What a phone command asks the desktop to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    Stop,
    Steer,
    FollowUp,
    PermissionAnswer,
}

impl CommandKind {
    /// The session relay envelope type that carries this kind.
    pub fn envelope_type(self) -> &'static str {
        match self {
            Self::Stop => "command.interrupt",
            Self::Steer => "command.steer",
            Self::FollowUp => "command.follow_up",
            Self::PermissionAnswer => "permission.answer",
        }
    }
}

/// The plaintext header of a sealed command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandHeader {
    pub contract_version: String,
    pub header_type: String,
    pub command_kind: CommandKind,
    pub command_id: String,
    pub session_id: String,
    pub run_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub gate_id: Option<String>,
    pub created_at: String,
    pub expires_at: String,
}

impl CommandHeader {
    fn validate(&self) -> Result<(), RelayCryptoError> {
        let gate_valid = match (&self.gate_id, self.command_kind) {
            (Some(gate_id), CommandKind::PermissionAnswer) => valid_id(gate_id),
            (None, kind) => kind != CommandKind::PermissionAnswer,
            (Some(_), _) => false,
        };
        let valid = self.contract_version == CONTRACT_VERSION
            && self.header_type == "command"
            && valid_id(&self.command_id)
            && valid_id(&self.session_id)
            && valid_id(&self.run_id)
            && gate_valid
            && valid_timestamp(&self.created_at)
            && valid_timestamp(&self.expires_at);
        valid.then_some(()).ok_or(RelayCryptoError::Malformed)
    }
}

/// How a permission gate closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Allow,
    Deny,
    Expired,
    Cancelled,
}

/// A phone's answer to a permission gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnswerDecision {
    Allow,
    Deny,
}

/// Why a phone asks to stop a run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    UserRequested,
}

/// The sealed content of an event.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum EventContent {
    #[serde(rename = "session.title")]
    SessionTitle { title: String },
    #[serde(rename = "assistant.delta")]
    AssistantDelta { text: String },
    #[serde(rename = "tool.activity")]
    ToolActivity { summary: String },
    #[serde(rename = "run.status")]
    RunStatus {
        #[serde(deserialize_with = "required_nullable")]
        detail: Option<String>,
    },
    #[serde(rename = "permission.ask")]
    PermissionAsk {
        gate_id: String,
        kind: String,
        summary: String,
        request_digest: String,
    },
    #[serde(rename = "permission.resolved")]
    PermissionResolved {
        gate_id: String,
        decision: GateDecision,
    },
}

impl EventContent {
    fn validate(&self) -> Result<(), RelayCryptoError> {
        let bounded = |value: &str, minimum: usize, maximum: usize| {
            let length = value.chars().count();
            length >= minimum && length <= maximum
        };
        let valid = match self {
            Self::SessionTitle { title } => bounded(title, 0, 160),
            Self::AssistantDelta { text } => !text.is_empty(),
            Self::ToolActivity { summary } => bounded(summary, 1, 2048),
            Self::RunStatus { detail } => detail
                .as_deref()
                .is_none_or(|detail| bounded(detail, 1, 280)),
            Self::PermissionAsk {
                gate_id,
                kind,
                summary,
                request_digest,
            } => {
                valid_id(gate_id)
                    && (1..=32).contains(&kind.len())
                    && kind
                        .bytes()
                        .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                    && bounded(summary, 1, 2048)
                    && valid_digest(request_digest)
            }
            Self::PermissionResolved { gate_id, .. } => valid_id(gate_id),
        };
        valid.then_some(()).ok_or(RelayCryptoError::Malformed)
    }
}

/// The sealed content of a command.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandContent {
    Stop {
        reason: StopReason,
    },
    Steer {
        text: String,
    },
    FollowUp {
        text: String,
    },
    PermissionAnswer {
        gate_id: String,
        decision: AnswerDecision,
        request_digest: String,
    },
}

impl CommandContent {
    pub fn kind(&self) -> CommandKind {
        match self {
            Self::Stop { .. } => CommandKind::Stop,
            Self::Steer { .. } => CommandKind::Steer,
            Self::FollowUp { .. } => CommandKind::FollowUp,
            Self::PermissionAnswer { .. } => CommandKind::PermissionAnswer,
        }
    }

    fn validate(&self) -> Result<(), RelayCryptoError> {
        let text_valid = |text: &str| {
            text.chars().count() >= 1 && text.chars().count() <= MAX_COMMAND_TEXT_BYTES
        };
        let valid = match self {
            Self::Stop { .. } => true,
            Self::Steer { text } | Self::FollowUp { text } => text_valid(text),
            Self::PermissionAnswer {
                gate_id,
                request_digest,
                ..
            } => valid_id(gate_id) && valid_digest(request_digest),
        };
        valid.then_some(()).ok_or(RelayCryptoError::Malformed)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plaintext<C> {
    counter: String,
    content: C,
}

/// A sealed payload: the contract version, the plaintext header, a nonce and
/// the AES-256-GCM ciphertext with its tag.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed<H> {
    pub contract_version: String,
    pub header: H,
    pub nonce: String,
    pub ciphertext: String,
}

pub type SealedEvent = Sealed<EventHeader>;
pub type SealedCommand = Sealed<CommandHeader>;

/// Serializes a JSON value with object members sorted by key at every depth
/// and no whitespace, as the ECMAScript `JSON.stringify` of a sorted object.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|left, right| left.0.encode_utf16().cmp(right.0.encode_utf16()));
            out.push('{');
            for (index, (key, item)) in entries.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("a key serializes"));
                out.push(':');
                write_canonical(item, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).expect("a scalar serializes")),
    }
}

/// The associated data of a header: its canonical JSON.
pub fn associated_data<H: Serialize>(header: &H) -> String {
    canonical_json(&serde_json::to_value(header).expect("a header serializes"))
}

fn seal_bytes<H: Serialize + Clone>(
    key: &DirectionKey,
    header: &H,
    plaintext: &[u8],
    nonce: [u8; NONCE_LENGTH],
) -> Sealed<H> {
    let aad = associated_data(header);
    let mut in_out = plaintext.to_vec();
    key.aead()
        .seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_bytes()),
            &mut in_out,
        )
        .expect("AES-256-GCM seals a bounded plaintext");
    let sealed = Sealed {
        contract_version: CONTRACT_VERSION.to_owned(),
        header: header.clone(),
        nonce: encode(&nonce),
        ciphertext: encode(&in_out),
    };
    in_out.zeroize();
    sealed
}

fn plaintext_bytes<C: Serialize>(counter: u64, content: &C) -> Zeroizing<Vec<u8>> {
    Zeroizing::new(
        serde_json::to_vec(&Plaintext {
            counter: counter.to_string(),
            content,
        })
        .expect("relay content serializes"),
    )
}

/// Seals plaintext bytes under a given nonce. The contract vectors use it;
/// every sender draws a fresh random nonce through [`seal_event`] or
/// [`seal_command`].
pub fn seal_with_nonce<H: Serialize + Clone>(
    key: &DirectionKey,
    header: &H,
    plaintext: &[u8],
    nonce: &str,
) -> Result<Sealed<H>, RelayCryptoError> {
    Ok(seal_bytes(
        key,
        header,
        plaintext,
        decode_exact::<NONCE_LENGTH>(nonce)?,
    ))
}

/// Seals one event with a fresh nonce. `counter` is the sender's next counter
/// for this direction.
pub fn seal_event(
    key: &DirectionKey,
    header: &EventHeader,
    counter: u64,
    content: &EventContent,
) -> Result<SealedEvent, RelayCryptoError> {
    header.validate()?;
    content.validate()?;
    check_counter(counter)?;
    if let EventContent::PermissionAsk { gate_id, .. } = content {
        if header.permission.as_ref().map(|gate| &gate.gate_id) != Some(gate_id) {
            return Err(RelayCryptoError::BindingMismatch);
        }
    }
    let sealed = seal_bytes(
        key,
        header,
        &plaintext_bytes(counter, content),
        random::<NONCE_LENGTH>()?,
    );
    let size = serde_json::to_vec(&sealed).map_or(usize::MAX, |bytes| bytes.len());
    if size > MAX_SEALED_EVENT_BYTES {
        return Err(RelayCryptoError::Malformed);
    }
    Ok(sealed)
}

/// Seals one command with a fresh nonce.
pub fn seal_command(
    key: &DirectionKey,
    header: &CommandHeader,
    counter: u64,
    content: &CommandContent,
) -> Result<SealedCommand, RelayCryptoError> {
    header.validate()?;
    content.validate()?;
    check_counter(counter)?;
    Ok(seal_bytes(
        key,
        header,
        &plaintext_bytes(counter, content),
        random::<NONCE_LENGTH>()?,
    ))
}

fn check_counter(counter: u64) -> Result<(), RelayCryptoError> {
    match counter {
        0 => Err(RelayCryptoError::Malformed),
        counter if counter > MAX_MESSAGES_PER_KEY => Err(RelayCryptoError::Exhausted),
        _ => Ok(()),
    }
}

fn open_bytes<H: Serialize>(
    key: &DirectionKey,
    sealed: &Sealed<H>,
) -> Result<Zeroizing<Vec<u8>>, RelayCryptoError> {
    if sealed.contract_version != CONTRACT_VERSION {
        return Err(RelayCryptoError::Malformed);
    }
    let nonce = decode_exact::<NONCE_LENGTH>(&sealed.nonce)?;
    let mut in_out = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(&sealed.ciphertext)
            .map_err(|_| RelayCryptoError::Malformed)?,
    );
    if in_out.len() < 16 {
        return Err(RelayCryptoError::Malformed);
    }
    let aad = associated_data(&sealed.header);
    let length = key
        .aead()
        .open_in_place(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(aad.as_bytes()),
            &mut in_out,
        )
        .map_err(|_| RelayCryptoError::AuthenticationFailed)?
        .len();
    in_out.truncate(length);
    Ok(in_out)
}

fn parse_plaintext<C: for<'de> Deserialize<'de>>(
    bytes: &[u8],
) -> Result<(u64, C), RelayCryptoError> {
    let plaintext: Plaintext<C> =
        serde_json::from_slice(bytes).map_err(|_| RelayCryptoError::Malformed)?;
    if !valid_positive(&plaintext.counter) {
        return Err(RelayCryptoError::Malformed);
    }
    let counter = plaintext
        .counter
        .parse()
        .map_err(|_| RelayCryptoError::Malformed)?;
    Ok((counter, plaintext.content))
}

/// An opened event: the sender's counter and the content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedEvent {
    pub counter: u64,
    pub content: EventContent,
}

/// Opens one event the relay delivered for the session `envelope_session_id`.
pub fn open_event(
    key: &DirectionKey,
    sealed: &SealedEvent,
    envelope_session_id: &str,
) -> Result<OpenedEvent, RelayCryptoError> {
    sealed.header.validate()?;
    let bytes = open_bytes(key, sealed)?;
    let (counter, content) = parse_plaintext::<EventContent>(&bytes)?;
    content.validate()?;
    if sealed.header.session_id != envelope_session_id {
        return Err(RelayCryptoError::BindingMismatch);
    }
    if let EventContent::PermissionAsk { gate_id, .. } = &content {
        let gate = sealed.header.permission.as_ref();
        if sealed.header.phase != Phase::WaitingForPermission
            || gate.map(|gate| &gate.gate_id) != Some(gate_id)
        {
            return Err(RelayCryptoError::BindingMismatch);
        }
    }
    Ok(OpenedEvent { counter, content })
}

/// The relay envelope fields a command binds to.
#[derive(Clone, Copy, Debug)]
pub struct CommandEnvelope<'a> {
    pub envelope_type: &'a str,
    pub session_id: &'a str,
    pub message_id: &'a str,
}

/// An opened command: the sender's counter and the content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedCommand {
    pub counter: u64,
    pub content: CommandContent,
}

/// Opens one command and checks that it binds to its header and envelope.
/// The caller still checks the counter, the expiry and the target run.
pub fn open_command(
    key: &DirectionKey,
    sealed: &SealedCommand,
    envelope: CommandEnvelope<'_>,
) -> Result<OpenedCommand, RelayCryptoError> {
    sealed.header.validate()?;
    if envelope.envelope_type != sealed.header.command_kind.envelope_type() {
        return Err(RelayCryptoError::BindingMismatch);
    }
    let bytes = open_bytes(key, sealed)?;
    let (counter, content) = parse_plaintext::<CommandContent>(&bytes)?;
    content.validate()?;
    let header = &sealed.header;
    let gate_matches = match &content {
        CommandContent::PermissionAnswer { gate_id, .. } => {
            header.gate_id.as_deref() == Some(gate_id.as_str())
        }
        _ => true,
    };
    if header.session_id != envelope.session_id
        || header.command_id != envelope.message_id
        || content.kind() != header.command_kind
        || !gate_matches
    {
        return Err(RelayCryptoError::BindingMismatch);
    }
    Ok(OpenedCommand { counter, content })
}

/// The desktop's window of accepted command counters: the highest accepted
/// counter and which of the 63 below it were accepted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReplayWindow {
    pub highest: u64,
    /// Bit `n` marks `highest - n` as accepted.
    pub accepted: u64,
}

impl ReplayWindow {
    /// Whether `counter` would be accepted now.
    pub fn admits(&self, counter: u64) -> bool {
        if counter == 0 {
            return false;
        }
        if counter > self.highest {
            return true;
        }
        let offset = self.highest - counter;
        offset < REPLAY_WINDOW && self.accepted & (1 << offset) == 0
    }

    /// Accepts `counter` when the window admits it. A counter above the
    /// highest moves the window; one within the 64 values at its top that was
    /// not accepted yet fills its slot. Every other counter is a replay.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.admits(counter) {
            return false;
        }
        if counter > self.highest {
            let shift = counter - self.highest;
            self.accepted = if shift >= REPLAY_WINDOW {
                0
            } else {
                self.accepted << shift
            };
            self.accepted |= 1;
            self.highest = counter;
        } else {
            self.accepted |= 1 << (self.highest - counter);
        }
        true
    }
}

/// A sender's counter for one direction. It reserves values in blocks, so a
/// caller persists the reserved high-water mark before it uses a value and a
/// restart resumes above every value used.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendCounter {
    next: u64,
    reserved: u64,
}

/// How many counter values one persisted reservation covers.
pub const COUNTER_BLOCK: u64 = 1024;

impl SendCounter {
    /// A counter that resumes after the persisted mark `reserved`.
    pub fn resume(reserved: u64) -> Self {
        Self {
            next: reserved + 1,
            reserved,
        }
    }

    /// The next counter value. When it passes the reservation, `persist` must
    /// first store the new mark; a failed store uses no value.
    pub fn next<E>(&mut self, persist: impl FnOnce(u64) -> Result<(), E>) -> Result<u64, E>
    where
        E: From<RelayCryptoError>,
    {
        let value = self.next.max(1);
        if value > MAX_MESSAGES_PER_KEY {
            return Err(RelayCryptoError::Exhausted.into());
        }
        if value > self.reserved {
            let reserved = value + COUNTER_BLOCK - 1;
            persist(reserved)?;
            self.reserved = reserved;
        }
        self.next = value + 1;
        Ok(value)
    }

    /// The reserved high-water mark.
    pub fn reserved(&self) -> u64 {
        self.reserved
    }
}

#[cfg(test)]
mod tests;
