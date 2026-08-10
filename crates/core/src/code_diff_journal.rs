//! CAS storage and atomic journal publication for code-diff proposals.

use crate::cas::{CasError, LocalCas};
use crate::journal::{
    CasReference, EventEnvelope, EventPayload, JournalError, Provenance, RunJournal,
};
use crate::write_plan::{WritePlan, WritePlanError, MEDIA_TYPE as WRITE_PLAN_MEDIA_TYPE};
use chrono::{SecondsFormat, Utc};
use muniment_code_diff::{canonical_bytes, CanonicalBytesError, CodeDiff};
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
