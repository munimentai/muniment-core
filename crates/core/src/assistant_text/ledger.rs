//! Byte attribution for ordered assistant text envelopes.

use std::{collections::VecDeque, ops::Range};

/// A resolved envelope and the parts of its original span that may be released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub run_seq: u64,
    pub released_ranges: Vec<Range<u64>>,
}

/// Stable failures from ledger input validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LedgerError {
    ZeroLengthEnvelope,
    StreamOffsetOverflow,
    BoundaryRegressed,
    BoundaryPastStream,
    InvalidWithheldRange,
    WithheldRangePastBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Envelope {
    run_seq: u64,
    kind: EnvelopeKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum EnvelopeKind {
    Spanned(Range<u64>),
    Withheld,
}

/// Records envelope spans and attributes resolved bytes back to them.
#[derive(Debug, Default)]
pub struct Ledger {
    stream_end: u64,
    resolved_up_to: u64,
    envelopes: VecDeque<Envelope>,
    withheld_ranges: Vec<Range<u64>>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the next nonempty envelope in the concatenated stream.
    pub fn push(&mut self, run_seq: u64, byte_len: u64) -> Result<(), LedgerError> {
        if byte_len == 0 {
            return Err(LedgerError::ZeroLengthEnvelope);
        }
        let end = self
            .stream_end
            .checked_add(byte_len)
            .ok_or(LedgerError::StreamOffsetOverflow)?;
        self.envelopes.push_back(Envelope {
            run_seq,
            kind: EnvelopeKind::Spanned(self.stream_end..end),
        });
        self.stream_end = end;
        Ok(())
    }

    /// Records a withheld envelope without adding bytes to the stream.
    pub fn push_withheld(&mut self, run_seq: u64) {
        self.envelopes.push_back(Envelope {
            run_seq,
            kind: EnvelopeKind::Withheld,
        });
    }

    /// Resolves a stream prefix and emits every envelope completed by it.
    pub fn resolve(
        &mut self,
        released_up_to: u64,
        withheld_ranges: &[Range<u64>],
    ) -> Result<Vec<Projection>, LedgerError> {
        self.validate_resolve(released_up_to, withheld_ranges)?;

        self.withheld_ranges.extend_from_slice(withheld_ranges);
        self.withheld_ranges.sort_by_key(|range| range.start);
        self.resolved_up_to = released_up_to;

        let completed = self
            .envelopes
            .iter()
            .take_while(|envelope| match &envelope.kind {
                EnvelopeKind::Spanned(span) => span.end <= released_up_to,
                EnvelopeKind::Withheld => true,
            })
            .count();
        let mut projections = Vec::with_capacity(completed);
        for envelope in self.envelopes.drain(..completed) {
            projections.push(Projection {
                run_seq: envelope.run_seq,
                released_ranges: match envelope.kind {
                    EnvelopeKind::Spanned(span) => released_parts(&span, &self.withheld_ranges),
                    EnvelopeKind::Withheld => Vec::new(),
                },
            });
        }
        if let Some(first_pending) = self.envelopes.front() {
            let pending_start = match &first_pending.kind {
                EnvelopeKind::Spanned(span) => span.start,
                EnvelopeKind::Withheld => self.resolved_up_to,
            };
            self.withheld_ranges
                .retain(|range| range.end > pending_start);
        } else {
            self.withheld_ranges.clear();
        }
        Ok(projections)
    }

    fn validate_resolve(
        &self,
        released_up_to: u64,
        withheld_ranges: &[Range<u64>],
    ) -> Result<(), LedgerError> {
        if released_up_to < self.resolved_up_to {
            return Err(LedgerError::BoundaryRegressed);
        }
        if released_up_to > self.stream_end {
            return Err(LedgerError::BoundaryPastStream);
        }
        for range in withheld_ranges {
            if range.start >= range.end {
                return Err(LedgerError::InvalidWithheldRange);
            }
            if range.end > released_up_to {
                return Err(LedgerError::WithheldRangePastBoundary);
            }
        }
        Ok(())
    }
}

fn released_parts(span: &Range<u64>, withheld_ranges: &[Range<u64>]) -> Vec<Range<u64>> {
    let mut released = Vec::new();
    let mut cursor = span.start;
    for withheld in withheld_ranges {
        let start = withheld.start.max(span.start);
        let end = withheld.end.min(span.end);
        if start >= end || end <= cursor {
            continue;
        }
        if cursor < start {
            released.push(cursor..start);
        }
        cursor = cursor.max(end);
    }
    if cursor < span.end {
        released.push(cursor..span.end);
    }
    released
}
