//! CAS storage and atomic journal publication for code-diff proposals.

use crate::cas::{CasError, ContentHash, LocalCas};
use crate::code_diff::{compute_code_diff, ComputeCodeDiffError};
use crate::code_diff_staging::{
    stage_proposed_operations, ProposedOperation, StageProposedOperationsError,
};
use crate::journal::{
    reducer::{PermissionGate, PermissionRequest},
    CasReference, EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
};
use crate::write_plan::{
    WriteOperation, WritePlan, WritePlanError, MEDIA_TYPE as WRITE_PLAN_MEDIA_TYPE,
};
use chrono::{SecondsFormat, Utc};
use muniment_code_diff::{canonical_bytes, CanonicalBytesError, CodeDiff, ValidationError};
use serde_json::Error as JsonError;
use sha2::{Digest, Sha256};
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
pub enum ComposeCodeDiffProposalError {
    Staging(StageProposedOperationsError),
    Diff(ComputeCodeDiffError),
    Persistence(StageCodeDiffError),
}

impl fmt::Display for ComposeCodeDiffProposalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Staging(error) => write!(f, "proposal staging failed: {error}"),
            Self::Diff(error) => write!(f, "code diff computation failed: {error}"),
            Self::Persistence(error) => write!(f, "proposal persistence failed: {error}"),
        }
    }
}

impl std::error::Error for ComposeCodeDiffProposalError {}

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

#[derive(Debug)]
pub enum AppendCodeDiffPermissionError {
    Load(LoadCodeDiffError),
    ProposalNotFound,
    Truncated,
    BrokenEventLink,
    SequenceOverflow,
    Journal(JournalError),
}

impl fmt::Display for AppendCodeDiffPermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Load(error) => write!(f, "stored proposal load failed: {error}"),
            Self::ProposalNotFound => f.write_str("stored proposal was not found"),
            Self::Truncated => f.write_str("a truncated code diff cannot open a permission gate"),
            Self::BrokenEventLink => f.write_str("proposal events have a broken link"),
            Self::SequenceOverflow => {
                f.write_str("permission event sequence exceeds the journal limit")
            }
            Self::Journal(error) => write!(f, "permission journal append failed: {error}"),
        }
    }
}

impl std::error::Error for AppendCodeDiffPermissionError {}

#[derive(Debug)]
pub enum VerifyCodeDiffPermissionError {
    NotCodeDiffGate,
    GateIdMismatch { expected: String, actual: String },
    EffectIdMismatch { expected: String, actual: String },
    CodeDiffIdMismatch { expected: String, actual: String },
    DiffHashMismatch { expected: String, actual: String },
    WritePlanHashMismatch { expected: String, actual: String },
    WritePlanEncoding(WritePlanError),
    CodeDiffEncoding(CanonicalBytesError),
    Load(LoadCodeDiffError),
    ProposalNotFound,
    Truncated,
}

impl fmt::Display for VerifyCodeDiffPermissionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCodeDiffGate => f.write_str("pending permission gate is not a code diff"),
            Self::GateIdMismatch { expected, actual } => {
                write!(f, "permission gate id is {actual}, expected {expected}")
            }
            Self::EffectIdMismatch { expected, actual } => {
                write!(f, "effect id is {actual}, expected {expected}")
            }
            Self::CodeDiffIdMismatch { expected, actual } => {
                write!(f, "code diff id is {actual}, expected {expected}")
            }
            Self::DiffHashMismatch { expected, actual } => {
                write!(f, "code diff hash is {actual}, expected {expected}")
            }
            Self::WritePlanHashMismatch { expected, actual } => {
                write!(f, "write plan hash is {actual}, expected {expected}")
            }
            Self::WritePlanEncoding(error) => {
                write!(f, "loaded write plan encoding failed: {error}")
            }
            Self::CodeDiffEncoding(error) => {
                write!(f, "loaded code diff encoding failed: {error}")
            }
            Self::Load(error) => write!(f, "stored proposal load failed: {error}"),
            Self::ProposalNotFound => f.write_str("stored proposal was not found"),
            Self::Truncated => f.write_str("a truncated code diff cannot authorize a write"),
        }
    }
}

impl std::error::Error for VerifyCodeDiffPermissionError {}

#[derive(Clone, Copy, Debug)]
pub struct CodeDiffPermissionAnswer<'a> {
    pub gate_id: &'a str,
    pub effect_id: &'a str,
    pub code_diff_id: &'a str,
    pub diff_sha256: &'a str,
    pub write_plan_sha256: &'a str,
}

/// Verifies a code-diff permission answer against its pending stored proposal.
pub fn verify_code_diff_permission_answer(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    pending_gate: &PermissionGate,
    answer: CodeDiffPermissionAnswer<'_>,
) -> Result<(WritePlan, CodeDiff), VerifyCodeDiffPermissionError> {
    if answer.gate_id != pending_gate.gate_id {
        return Err(VerifyCodeDiffPermissionError::GateIdMismatch {
            expected: pending_gate.gate_id.clone(),
            actual: answer.gate_id.into(),
        });
    }
    let PermissionRequest::CodeDiff {
        effect_id,
        code_diff_id,
        diff_sha256,
        write_plan_sha256,
    } = &pending_gate.request
    else {
        return Err(VerifyCodeDiffPermissionError::NotCodeDiffGate);
    };
    if answer.effect_id != effect_id {
        return Err(VerifyCodeDiffPermissionError::EffectIdMismatch {
            expected: effect_id.clone(),
            actual: answer.effect_id.into(),
        });
    }
    if answer.code_diff_id != code_diff_id {
        return Err(VerifyCodeDiffPermissionError::CodeDiffIdMismatch {
            expected: code_diff_id.clone(),
            actual: answer.code_diff_id.into(),
        });
    }
    if answer.diff_sha256 != diff_sha256 {
        return Err(VerifyCodeDiffPermissionError::DiffHashMismatch {
            expected: diff_sha256.clone(),
            actual: answer.diff_sha256.into(),
        });
    }
    if answer.write_plan_sha256 != write_plan_sha256 {
        return Err(VerifyCodeDiffPermissionError::WritePlanHashMismatch {
            expected: write_plan_sha256.clone(),
            actual: answer.write_plan_sha256.into(),
        });
    }

    let (write_plan, code_diff) = load_code_diff_proposal(journal, cas, run_id, effect_id)
        .map_err(VerifyCodeDiffPermissionError::Load)?
        .ok_or(VerifyCodeDiffPermissionError::ProposalNotFound)?;
    let loaded_plan_hash = encoded_sha256(
        &write_plan
            .encode()
            .map_err(VerifyCodeDiffPermissionError::WritePlanEncoding)?,
    );
    if loaded_plan_hash != answer.write_plan_sha256 {
        return Err(VerifyCodeDiffPermissionError::WritePlanHashMismatch {
            expected: loaded_plan_hash,
            actual: answer.write_plan_sha256.into(),
        });
    }
    let loaded_diff_hash = encoded_sha256(
        &canonical_bytes(&code_diff).map_err(VerifyCodeDiffPermissionError::CodeDiffEncoding)?,
    );
    if loaded_diff_hash != answer.diff_sha256 {
        return Err(VerifyCodeDiffPermissionError::DiffHashMismatch {
            expected: loaded_diff_hash,
            actual: answer.diff_sha256.into(),
        });
    }
    if code_diff.truncated {
        return Err(VerifyCodeDiffPermissionError::Truncated);
    }
    if code_diff.id != answer.code_diff_id {
        return Err(VerifyCodeDiffPermissionError::CodeDiffIdMismatch {
            expected: code_diff.id,
            actual: answer.code_diff_id.into(),
        });
    }
    Ok((write_plan, code_diff))
}

fn encoded_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Opens a permission gate bound to a stored proposal pair.
pub fn append_code_diff_permission_request(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    effect_id: &str,
) -> Result<PermissionGate, AppendCodeDiffPermissionError> {
    let (_, code_diff) = load_code_diff_proposal(journal, cas, run_id, effect_id)
        .map_err(AppendCodeDiffPermissionError::Load)?
        .ok_or(AppendCodeDiffPermissionError::ProposalNotFound)?;
    if code_diff.truncated {
        return Err(AppendCodeDiffPermissionError::Truncated);
    }

    let events = journal
        .events(run_id)
        .map_err(AppendCodeDiffPermissionError::Journal)?;
    let diff_event = events
        .iter()
        .rev()
        .find(|event| {
            event.event_type == DIFF_EVENT_TYPE
                && event.correlation_id.as_deref() == Some(effect_id)
        })
        .ok_or(AppendCodeDiffPermissionError::BrokenEventLink)?;
    let plan_event = events
        .iter()
        .find(|event| {
            event.event_type == WRITE_PLAN_EVENT_TYPE
                && diff_event.causation_id.as_deref() == Some(event.event_id.as_str())
        })
        .ok_or(AppendCodeDiffPermissionError::BrokenEventLink)?;
    let EventPayload::Cas {
        payload_cas: diff_cas,
    } = &diff_event.payload
    else {
        return Err(AppendCodeDiffPermissionError::BrokenEventLink);
    };
    let EventPayload::Cas {
        payload_cas: plan_cas,
    } = &plan_event.payload
    else {
        return Err(AppendCodeDiffPermissionError::BrokenEventLink);
    };
    let gate = PermissionGate {
        gate_id: Uuid::now_v7().to_string(),
        request: PermissionRequest::CodeDiff {
            effect_id: effect_id.into(),
            code_diff_id: code_diff.id,
            diff_sha256: diff_cas.sha256.clone(),
            write_plan_sha256: plan_cas.sha256.clone(),
        },
    };
    let expected_last_seq = events.last().map_or(0, |event| event.run_seq);
    let run_seq = expected_last_seq
        .checked_add(1)
        .ok_or(AppendCodeDiffPermissionError::SequenceOverflow)?;
    let event = EventEnvelope {
        event_id: Uuid::now_v7().to_string(),
        run_id: run_id.into(),
        run_seq,
        event_type: "permission.requested".into(),
        event_version: EVENT_VERSION,
        envelope_version: 1,
        recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::AutoSi, true),
        occurred_at: None,
        correlation_id: Some(effect_id.into()),
        causation_id: Some(diff_event.event_id.clone()),
        payload: EventPayload::Inline {
            payload_json: serde_json::to_value(&gate).expect("permission gates serialize"),
        },
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
    };
    journal
        .append(expected_last_seq, &event)
        .map_err(AppendCodeDiffPermissionError::Journal)?;
    Ok(gate)
}

/// Loads and verifies the proposal linked to an effect.
pub fn load_code_diff_proposal(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    effect_id: &str,
) -> Result<Option<(WritePlan, CodeDiff)>, LoadCodeDiffError> {
    Ok(
        load_code_diff_proposal_with_references(journal, cas, run_id, effect_id)?
            .map(|(write_plan, code_diff, _, _)| (write_plan, code_diff)),
    )
}

fn load_code_diff_proposal_with_references(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    effect_id: &str,
) -> Result<Option<(WritePlan, CodeDiff, ContentHash, ContentHash)>, LoadCodeDiffError> {
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
    let (diff_bytes, diff_hash) = load_proposal_object(cas, diff_event, DIFF_MEDIA_TYPE)?;
    let code_diff: CodeDiff =
        serde_json::from_slice(&diff_bytes).map_err(LoadCodeDiffError::CodeDiffJson)?;
    code_diff
        .validate()
        .map_err(LoadCodeDiffError::CodeDiffValidation)?;
    let encoded = canonical_bytes(&code_diff).map_err(LoadCodeDiffError::CodeDiffEncoding)?;
    if encoded != diff_bytes {
        return Err(LoadCodeDiffError::NonCanonicalCodeDiff);
    }
    Ok(Some((write_plan, code_diff, diff_hash, plan_hash)))
}

/// Loads a verified diff for a pending code-diff gate.
pub fn load_pending_code_diff(
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    gate: &Option<PermissionGate>,
) -> Option<CodeDiff> {
    let Some(PermissionGate {
        request:
            PermissionRequest::CodeDiff {
                effect_id,
                code_diff_id,
                diff_sha256,
                write_plan_sha256,
            },
        ..
    }) = gate
    else {
        return None;
    };
    load_code_diff_proposal_with_references(journal, cas, run_id, effect_id)
        .ok()
        .flatten()
        .and_then(|(_, diff, diff_hash, plan_hash)| {
            (diff.id == *code_diff_id
                && diff_hash.to_string() == *diff_sha256
                && plan_hash.to_string() == *write_plan_sha256)
                .then_some(diff)
        })
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

/// Composes and stores a proposal from a validated write plan and current tree.
pub fn compose_code_diff_proposal(
    write_plan: &WritePlan,
    current: &BTreeMap<String, Vec<u8>>,
    journal: &mut RunJournal,
    cas: &LocalCas,
    run_id: &str,
    effect_id: &str,
) -> Result<CodeDiff, ComposeCodeDiffProposalError> {
    let operations: Vec<_> = write_plan
        .operations()
        .iter()
        .map(|operation| match operation {
            WriteOperation::Write { target, output, .. } => ProposedOperation::Write {
                path: target.path().to_owned(),
                output: output.clone(),
            },
            WriteOperation::Rename { source, target } => ProposedOperation::Rename {
                source: source.path().to_owned(),
                target: target.path().to_owned(),
            },
            WriteOperation::Delete { target } => ProposedOperation::Delete {
                path: target.path().to_owned(),
            },
        })
        .collect();
    let staged = stage_proposed_operations(current, &operations)
        .map_err(ComposeCodeDiffProposalError::Staging)?;
    let code_diff =
        compute_code_diff(current, &staged).map_err(ComposeCodeDiffProposalError::Diff)?;
    stage_code_diff_proposal(journal, cas, run_id, effect_id, write_plan, &code_diff)
        .map_err(ComposeCodeDiffProposalError::Persistence)?;
    Ok(code_diff)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_plan::{ObservedPath, ObservedState, StableFileIdentity};
    use std::fs;
    use std::path::PathBuf;

    struct TestStore {
        root: PathBuf,
        journal: RunJournal,
        cas: LocalCas,
    }

    impl TestStore {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .join(format!("muniment-code-diff-producer-{}", Uuid::now_v7()));
            fs::create_dir_all(&root).unwrap();
            let journal = RunJournal::open(root.join("runs.sqlite3")).unwrap();
            let cas = LocalCas::open(&root.join("cas")).unwrap();
            Self { root, journal, cas }
        }
    }

    impl Drop for TestStore {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn absent(path: impl Into<String>) -> ObservedPath {
        ObservedPath::new(path, ObservedState::Absent, StableFileIdentity::new(1, 1))
    }

    fn write(path: impl Into<String>, output: &[u8]) -> WriteOperation {
        WriteOperation::Write {
            target: absent(path),
            output: output.to_vec(),
            mode: 0o644,
        }
    }

    fn proposal() -> (
        TestStore,
        WritePlan,
        CodeDiff,
        PermissionGate,
        String,
        String,
    ) {
        let mut store = TestStore::new();
        let plan = WritePlan::new(vec![write("new.txt", b"new\n")]).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let effect_id = Uuid::now_v7().to_string();
        let diff = compose_code_diff_proposal(
            &plan,
            &BTreeMap::new(),
            &mut store.journal,
            &store.cas,
            &run_id,
            &effect_id,
        )
        .unwrap();
        let gate = append_code_diff_permission_request(
            &mut store.journal,
            &store.cas,
            &run_id,
            &effect_id,
        )
        .unwrap();
        (store, plan, diff, gate, run_id, effect_id)
    }

    fn code_diff_answers(gate: &PermissionGate) -> (String, String, String, String, String) {
        let PermissionRequest::CodeDiff {
            effect_id,
            code_diff_id,
            diff_sha256,
            write_plan_sha256,
        } = &gate.request
        else {
            panic!("expected a code diff gate");
        };
        (
            gate.gate_id.clone(),
            effect_id.clone(),
            code_diff_id.clone(),
            diff_sha256.clone(),
            write_plan_sha256.clone(),
        )
    }

    fn verify(
        store: &mut TestStore,
        run_id: &str,
        gate: &PermissionGate,
    ) -> Result<(WritePlan, CodeDiff), VerifyCodeDiffPermissionError> {
        let (gate_id, effect_id, code_diff_id, diff_hash, plan_hash) = code_diff_answers(gate);
        verify_code_diff_permission_answer(
            &mut store.journal,
            &store.cas,
            run_id,
            gate,
            CodeDiffPermissionAnswer {
                gate_id: &gate_id,
                effect_id: &effect_id,
                code_diff_id: &code_diff_id,
                diff_sha256: &diff_hash,
                write_plan_sha256: &plan_hash,
            },
        )
    }

    fn object_path(store: &TestStore, hash: &str) -> PathBuf {
        store
            .root
            .join("cas/objects")
            .join(&hash[..2])
            .join(&hash[2..])
    }

    #[test]
    fn verifies_a_permission_answer_and_returns_the_stored_pair() {
        let (mut store, plan, diff, gate, run_id, _) = proposal();

        assert_eq!(verify(&mut store, &run_id, &gate).unwrap(), (plan, diff));
    }

    #[test]
    fn rejects_each_answered_identifier_mismatch() {
        let (mut store, _, _, gate, run_id, _) = proposal();
        let (gate_id, effect_id, diff_id, diff_hash, plan_hash) = code_diff_answers(&gate);
        let cases = [
            (
                "wrong",
                effect_id.as_str(),
                diff_id.as_str(),
                diff_hash.as_str(),
                plan_hash.as_str(),
                0,
            ),
            (
                gate_id.as_str(),
                "wrong",
                diff_id.as_str(),
                diff_hash.as_str(),
                plan_hash.as_str(),
                1,
            ),
            (
                gate_id.as_str(),
                effect_id.as_str(),
                "wrong",
                diff_hash.as_str(),
                plan_hash.as_str(),
                2,
            ),
            (
                gate_id.as_str(),
                effect_id.as_str(),
                diff_id.as_str(),
                "wrong",
                plan_hash.as_str(),
                3,
            ),
            (
                gate_id.as_str(),
                effect_id.as_str(),
                diff_id.as_str(),
                diff_hash.as_str(),
                "wrong",
                4,
            ),
        ];

        for (
            answered_gate,
            answered_effect,
            answered_diff,
            answered_diff_hash,
            answered_plan_hash,
            kind,
        ) in cases
        {
            let error = verify_code_diff_permission_answer(
                &mut store.journal,
                &store.cas,
                &run_id,
                &gate,
                CodeDiffPermissionAnswer {
                    gate_id: answered_gate,
                    effect_id: answered_effect,
                    code_diff_id: answered_diff,
                    diff_sha256: answered_diff_hash,
                    write_plan_sha256: answered_plan_hash,
                },
            )
            .unwrap_err();
            assert!(matches!(
                (kind, error),
                (0, VerifyCodeDiffPermissionError::GateIdMismatch { .. })
                    | (1, VerifyCodeDiffPermissionError::EffectIdMismatch { .. })
                    | (2, VerifyCodeDiffPermissionError::CodeDiffIdMismatch { .. })
                    | (3, VerifyCodeDiffPermissionError::DiffHashMismatch { .. })
                    | (
                        4,
                        VerifyCodeDiffPermissionError::WritePlanHashMismatch { .. }
                    )
            ));
        }
    }

    #[test]
    fn rejects_a_non_code_diff_pending_gate() {
        let (mut store, _, _, mut gate, run_id, _) = proposal();
        gate.request = PermissionRequest::Confirm {
            title: "Confirm".into(),
            message: "Confirm".into(),
            timeout: None,
        };

        let error = verify_code_diff_permission_answer(
            &mut store.journal,
            &store.cas,
            &run_id,
            &gate,
            CodeDiffPermissionAnswer {
                gate_id: &gate.gate_id,
                effect_id: "effect",
                code_diff_id: "diff",
                diff_sha256: "diff-hash",
                write_plan_sha256: "plan-hash",
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            VerifyCodeDiffPermissionError::NotCodeDiffGate
        ));
    }

    #[test]
    fn rejects_a_missing_proposal_object() {
        let (mut store, _, _, gate, run_id, _) = proposal();
        let (_, _, _, diff_hash, _) = code_diff_answers(&gate);
        store.cas.remove(&diff_hash.parse().unwrap()).unwrap();

        let error = verify(&mut store, &run_id, &gate).unwrap_err();

        assert!(matches!(
            error,
            VerifyCodeDiffPermissionError::Load(LoadCodeDiffError::MissingCasObject(_))
        ));
    }

    #[test]
    fn rejects_a_tampered_proposal_object() {
        let (mut store, _, _, gate, run_id, _) = proposal();
        let (_, _, _, _, plan_hash) = code_diff_answers(&gate);
        fs::write(object_path(&store, &plan_hash), b"tampered").unwrap();

        let error = verify(&mut store, &run_id, &gate).unwrap_err();

        assert!(matches!(
            error,
            VerifyCodeDiffPermissionError::Load(LoadCodeDiffError::TamperedCasObject { .. })
        ));
    }

    #[test]
    fn rejects_a_truncated_proposal() {
        let mut store = TestStore::new();
        let plan = WritePlan::new(vec![write("new.txt", b"new\n")]).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let effect_id = Uuid::now_v7().to_string();
        let mut diff = compute_code_diff(
            &BTreeMap::new(),
            &BTreeMap::from([("new.txt".into(), b"new\n".to_vec())]),
        )
        .unwrap();
        diff.truncated = true;
        stage_code_diff_proposal(
            &mut store.journal,
            &store.cas,
            &run_id,
            &effect_id,
            &plan,
            &diff,
        )
        .unwrap();
        let events = store.journal.events(&run_id).unwrap();
        let EventPayload::Cas {
            payload_cas: plan_cas,
        } = &events[0].payload
        else {
            unreachable!();
        };
        let EventPayload::Cas {
            payload_cas: diff_cas,
        } = &events[1].payload
        else {
            unreachable!();
        };
        let gate = PermissionGate {
            gate_id: Uuid::now_v7().to_string(),
            request: PermissionRequest::CodeDiff {
                effect_id,
                code_diff_id: diff.id,
                diff_sha256: diff_cas.sha256.clone(),
                write_plan_sha256: plan_cas.sha256.clone(),
            },
        };

        let error = verify(&mut store, &run_id, &gate).unwrap_err();

        assert!(matches!(error, VerifyCodeDiffPermissionError::Truncated));
    }

    #[test]
    fn rejects_a_decoded_code_diff_id_mismatch() {
        let (mut store, _, _, mut gate, run_id, _) = proposal();
        let PermissionRequest::CodeDiff { code_diff_id, .. } = &mut gate.request else {
            unreachable!();
        };
        *code_diff_id = "different-diff".into();

        let error = verify(&mut store, &run_id, &gate).unwrap_err();

        assert!(matches!(
            error,
            VerifyCodeDiffPermissionError::CodeDiffIdMismatch { .. }
        ));
    }

    #[test]
    fn rejects_gate_hashes_that_do_not_name_the_loaded_pair() {
        let (mut store, _, _, mut gate, run_id, _) = proposal();
        let PermissionRequest::CodeDiff { diff_sha256, .. } = &mut gate.request else {
            unreachable!();
        };
        *diff_sha256 = "different-diff-hash".into();
        let error = verify(&mut store, &run_id, &gate).unwrap_err();
        assert!(matches!(
            error,
            VerifyCodeDiffPermissionError::DiffHashMismatch { .. }
        ));

        let (mut store, _, _, mut gate, run_id, _) = proposal();
        let PermissionRequest::CodeDiff {
            write_plan_sha256, ..
        } = &mut gate.request
        else {
            unreachable!();
        };
        *write_plan_sha256 = "different-plan-hash".into();
        let error = verify(&mut store, &run_id, &gate).unwrap_err();
        assert!(matches!(
            error,
            VerifyCodeDiffPermissionError::WritePlanHashMismatch { .. }
        ));
    }

    #[test]
    fn composes_and_loads_the_stored_proposal_pair() {
        let mut store = TestStore::new();
        let plan = WritePlan::new(vec![
            write("new.txt", b"new\n"),
            WriteOperation::Rename {
                source: ObservedPath::new(
                    "old.txt",
                    ObservedState::File {
                        byte_length: 4,
                        sha256: [1; 32],
                        mode: 0o644,
                        identity: StableFileIdentity::new(1, 2),
                    },
                    StableFileIdentity::new(1, 1),
                ),
                target: absent("moved.txt"),
            },
        ])
        .unwrap();
        let current = BTreeMap::from([("old.txt".to_owned(), b"old\n".to_vec())]);
        let run_id = Uuid::now_v7().to_string();
        let effect_id = Uuid::now_v7().to_string();

        let diff = compose_code_diff_proposal(
            &plan,
            &current,
            &mut store.journal,
            &store.cas,
            &run_id,
            &effect_id,
        )
        .unwrap();
        let loaded =
            load_code_diff_proposal(&mut store.journal, &store.cas, &run_id, &effect_id).unwrap();

        assert_eq!(loaded, Some((plan, diff)));
    }

    #[test]
    fn reports_the_staging_failure() {
        let mut store = TestStore::new();
        let plan = WritePlan::new(vec![WriteOperation::Delete {
            target: ObservedPath::new(
                "missing.txt",
                ObservedState::File {
                    byte_length: 1,
                    sha256: [1; 32],
                    mode: 0o644,
                    identity: StableFileIdentity::new(1, 2),
                },
                StableFileIdentity::new(1, 1),
            ),
        }])
        .unwrap();

        let error = compose_code_diff_proposal(
            &plan,
            &BTreeMap::new(),
            &mut store.journal,
            &store.cas,
            "run",
            "effect",
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ComposeCodeDiffProposalError::Staging(
                StageProposedOperationsError::DeleteTargetMissing(path)
            ) if path == "missing.txt"
        ));
    }

    #[test]
    fn reports_the_diff_failure() {
        let mut store = TestStore::new();
        let plan = WritePlan::new(
            (0..201)
                .map(|index| write(format!("{index}.txt"), b"new"))
                .collect(),
        )
        .unwrap();

        let error = compose_code_diff_proposal(
            &plan,
            &BTreeMap::new(),
            &mut store.journal,
            &store.cas,
            "run",
            "effect",
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ComposeCodeDiffProposalError::Diff(ComputeCodeDiffError::TooManyChangedFiles)
        ));
    }
}
