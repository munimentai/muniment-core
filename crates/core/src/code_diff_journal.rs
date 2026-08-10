//! CAS storage and atomic journal publication for code-diff proposals.

use crate::cas::{CasError, ContentHash, LocalCas};
use crate::journal::{
    CasReference, EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
};
use crate::write_plan::{WritePlan, WritePlanError, MEDIA_TYPE as WRITE_PLAN_MEDIA_TYPE};
use chrono::{SecondsFormat, Utc};
use muniment_code_diff::{canonical_bytes, CanonicalBytesError, CodeDiff, ValidationError};
use serde_json::Error as JsonError;
use std::collections::BTreeMap;
use std::fmt;
use uuid::Uuid;

pub const WRITE_PLAN_EVENT_TYPE: &str = "code.write-plan.staged";
pub const DIFF_EVENT_TYPE: &str = "code.diff.proposed";
pub const EVENT_VERSION: u32 = 1;
pub const DIFF_MEDIA_TYPE: &str = "application/vnd.muniment.code-diff.v1+json";

#[derive(Debug)]
pub enum StageCodeDiffError {
    WritePlan(WritePlanError),
    CodeDiff(CanonicalBytesError),
    Cas(CasError),
    Journal(JournalError),
    ObjectTooLarge,
    SequenceOverflow,
}

impl fmt::Display for StageCodeDiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WritePlan(error) => write!(f, "write plan encoding failed: {error}"),
            Self::CodeDiff(error) => write!(f, "code diff encoding failed: {error}"),
            Self::Cas(error) => write!(f, "proposal CAS storage failed: {error}"),
            Self::Journal(error) => write!(f, "proposal journal append failed: {error}"),
            Self::ObjectTooLarge => f.write_str("proposal object length exceeds the journal limit"),
            Self::SequenceOverflow => {
                f.write_str("proposal event sequence exceeds the journal limit")
            }
        }
    }
}

impl std::error::Error for StageCodeDiffError {}

#[derive(Debug)]
pub enum LoadCodeDiffError {
    Journal(JournalError),
    BrokenEventLink,
    InvalidEventPayload,
    WrongMediaType {
        expected: &'static str,
        actual: String,
    },
    InvalidCasReference(CasError),
    MissingCasObject(ContentHash),
    TamperedCasObject {
        expected: ContentHash,
        actual: ContentHash,
    },
    Cas(CasError),
    StoredLengthMismatch,
    WritePlan(WritePlanError),
    CodeDiffJson(JsonError),
    CodeDiffValidation(ValidationError),
    NonCanonicalCodeDiff,
    CodeDiffEncoding(CanonicalBytesError),
}

impl fmt::Display for LoadCodeDiffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(f, "proposal journal read failed: {error}"),
            Self::BrokenEventLink => f.write_str("proposal events have a broken link"),
            Self::InvalidEventPayload => {
                f.write_str("proposal event does not contain a CAS reference")
            }
            Self::WrongMediaType { expected, actual } => {
                write!(f, "proposal media type is {actual}, expected {expected}")
            }
            Self::InvalidCasReference(error) => {
                write!(f, "proposal CAS reference is invalid: {error}")
            }
            Self::MissingCasObject(hash) => write!(f, "proposal CAS object is missing: {hash}"),
            Self::TamperedCasObject { expected, actual } => {
                write!(f, "proposal CAS object {expected} has hash {actual}")
            }
            Self::Cas(error) => write!(f, "proposal CAS read failed: {error}"),
            Self::StoredLengthMismatch => {
                f.write_str("proposal CAS object length does not match its reference")
            }
            Self::WritePlan(error) => write!(f, "stored write plan is invalid: {error}"),
            Self::CodeDiffJson(error) => write!(f, "stored code diff JSON is invalid: {error}"),
            Self::CodeDiffValidation(error) => write!(f, "stored code diff is invalid: {error}"),
            Self::NonCanonicalCodeDiff => f.write_str("stored code diff is not canonical"),
            Self::CodeDiffEncoding(error) => write!(f, "stored code diff encoding failed: {error}"),
        }
    }
}

impl std::error::Error for LoadCodeDiffError {}

/// Loads and verifies the proposal linked to an effect.
pub fn load_code_diff_proposal(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    effect_id: &str,
) -> Result<Option<(WritePlan, CodeDiff)>, LoadCodeDiffError> {
    let events = journal.events(run_id).map_err(LoadCodeDiffError::Journal)?;
    let plan_events: Vec<_> = events
        .iter()
        .filter(|event| {
            event.event_type == WRITE_PLAN_EVENT_TYPE
                && event.correlation_id.as_deref() == Some(effect_id)
        })
        .collect();
    let diff_event = events.iter().rev().find(|event| {
        event.event_type == DIFF_EVENT_TYPE && event.correlation_id.as_deref() == Some(effect_id)
    });

    let Some(diff_event) = diff_event else {
        return if plan_events.is_empty() {
            Ok(None)
        } else {
            Err(LoadCodeDiffError::BrokenEventLink)
        };
    };
    let plan_event = plan_events
        .into_iter()
        .find(|event| diff_event.causation_id.as_deref() == Some(event.event_id.as_str()))
        .ok_or(LoadCodeDiffError::BrokenEventLink)?;

    let (plan_bytes, plan_hash) = load_proposal_object(cas, plan_event, WRITE_PLAN_MEDIA_TYPE)?;
    let write_plan = WritePlan::decode_verified(&plan_bytes, &hash_bytes(&plan_hash))
        .map_err(LoadCodeDiffError::WritePlan)?;
    let (diff_bytes, _) = load_proposal_object(cas, diff_event, DIFF_MEDIA_TYPE)?;
    let code_diff: CodeDiff =
        serde_json::from_slice(&diff_bytes).map_err(LoadCodeDiffError::CodeDiffJson)?;
    code_diff
        .validate()
        .map_err(LoadCodeDiffError::CodeDiffValidation)?;
    let encoded = canonical_bytes(&code_diff).map_err(LoadCodeDiffError::CodeDiffEncoding)?;
    if encoded != diff_bytes {
        return Err(LoadCodeDiffError::NonCanonicalCodeDiff);
    }
    Ok(Some((write_plan, code_diff)))
}

fn load_proposal_object(
    cas: &LocalCas,
    event: &EventEnvelope,
    expected_media_type: &'static str,
) -> Result<(Vec<u8>, ContentHash), LoadCodeDiffError> {
    let EventPayload::Cas { payload_cas } = &event.payload else {
        return Err(LoadCodeDiffError::InvalidEventPayload);
    };
    if payload_cas.media_type != expected_media_type {
        return Err(LoadCodeDiffError::WrongMediaType {
            expected: expected_media_type,
            actual: payload_cas.media_type.clone(),
        });
    }
    let hash = payload_cas
        .sha256
        .parse()
        .map_err(LoadCodeDiffError::InvalidCasReference)?;
    let bytes = match cas.get_verified(&hash) {
        Ok(bytes) => bytes,
        Err(CasError::NotFound(hash)) => return Err(LoadCodeDiffError::MissingCasObject(hash)),
        Err(CasError::Corrupt { expected, actual }) => {
            return Err(LoadCodeDiffError::TamperedCasObject { expected, actual });
        }
        Err(error) => return Err(LoadCodeDiffError::Cas(error)),
    };
    if u64::try_from(bytes.len()).ok() != Some(payload_cas.byte_length) {
        return Err(LoadCodeDiffError::StoredLengthMismatch);
    }
    Ok((bytes, hash))
}

fn hash_bytes(hash: &ContentHash) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (index, pair) in hash.as_str().as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]);
    }
    bytes
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("ContentHash contains lowercase hexadecimal"),
    }
}

/// Stores a validated proposal and appends its linked journal events atomically.
pub fn stage_code_diff_proposal(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    effect_id: &str,
    write_plan: &WritePlan,
    code_diff: &CodeDiff,
) -> Result<(), StageCodeDiffError> {
    let plan_bytes = write_plan.encode().map_err(StageCodeDiffError::WritePlan)?;
    let diff_bytes = canonical_bytes(code_diff).map_err(StageCodeDiffError::CodeDiff)?;
    let plan_length =
        u64::try_from(plan_bytes.len()).map_err(|_| StageCodeDiffError::ObjectTooLarge)?;
    let diff_length =
        u64::try_from(diff_bytes.len()).map_err(|_| StageCodeDiffError::ObjectTooLarge)?;

    let plan_hash = cas.put(&plan_bytes).map_err(StageCodeDiffError::Cas)?;
    let diff_hash = cas.put(&diff_bytes).map_err(StageCodeDiffError::Cas)?;
    let current_events = journal
        .events(run_id)
        .map_err(StageCodeDiffError::Journal)?;
    let expected_last_seq = current_events.last().map_or(0, |event| event.run_seq);
    let plan_seq = expected_last_seq
        .checked_add(1)
        .ok_or(StageCodeDiffError::SequenceOverflow)?;
    let diff_seq = expected_last_seq
        .checked_add(2)
        .ok_or(StageCodeDiffError::SequenceOverflow)?;
    let plan_event_id = Uuid::now_v7().to_string();

    let plan_event = proposal_event(
        plan_event_id.clone(),
        run_id,
        plan_seq,
        WRITE_PLAN_EVENT_TYPE,
        effect_id,
        None,
        CasReference {
            sha256: plan_hash.to_string(),
            media_type: WRITE_PLAN_MEDIA_TYPE.into(),
            byte_length: plan_length,
        },
    );
    let diff_event = proposal_event(
        Uuid::now_v7().to_string(),
        run_id,
        diff_seq,
        DIFF_EVENT_TYPE,
        effect_id,
        Some(plan_event_id),
        CasReference {
            sha256: diff_hash.to_string(),
            media_type: DIFF_MEDIA_TYPE.into(),
            byte_length: diff_length,
        },
    );
    journal
        .append_batch(expected_last_seq, &[plan_event, diff_event])
        .map_err(StageCodeDiffError::Journal)
}

fn proposal_event(
    event_id: String,
    run_id: &str,
    run_seq: u64,
    event_type: &str,
    effect_id: &str,
    causation_id: Option<String>,
    payload_cas: CasReference,
) -> EventEnvelope {
    EventEnvelope {
        event_id,
        run_id: run_id.into(),
        run_seq,
        event_type: event_type.into(),
        event_version: EVENT_VERSION,
        envelope_version: 1,
        recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        occurred_at: None,
        correlation_id: Some(effect_id.into()),
        causation_id,
        payload: EventPayload::Cas { payload_cas },
        provenance: Provenance {
            source: "muniment-desktop".into(),
            source_version: env!("CARGO_PKG_VERSION").into(),
            actor_id: None,
            device_id: None,
            rpc_request_id: None,
            capability_versions: None,
            extra: BTreeMap::new(),
        },
        extra: BTreeMap::new(),
    }
}
