//! Stateful projection of ordered assistant text envelopes.

use super::{
    ledger::{Ledger, LedgerError, Projection as LedgerProjection},
    scan_with_workspace_for_projector, Match,
};
use crate::journal::content_disclosure::{read_content_disclosure, ContentDisclosure};
use serde_json::Value;
use std::{
    collections::VecDeque,
    ops::Range,
    path::{Path, PathBuf},
};

const MAX_UNRESOLVED_SUFFIX: usize = 65_535;

/// One assistant text envelope after redaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Projection {
    pub run_seq: u64,
    pub text: Option<String>,
    pub withheld: bool,
}

/// Stable failures from projector input validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProjectorError {
    Finished,
    InvalidStreamOffset,
    Ledger(LedgerError),
}

impl From<LedgerError> for ProjectorError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

/// Retains the unresolved suffix needed to redact matches across envelopes.
pub struct Projector<C> {
    approved_workspace: PathBuf,
    canonicalize: C,
    content: String,
    content_candidate_free: bool,
    content_start: u64,
    stream_end: u64,
    ledger: Ledger,
    released: VecDeque<ReleasedSpan>,
    withhold_from: Option<u64>,
    finished: bool,
}

struct ReleasedSpan {
    start: u64,
    bytes: Vec<u8>,
    offset: usize,
}

impl<C> Projector<C> {
    pub fn new(approved_workspace: impl Into<PathBuf>, canonicalize: C) -> Self {
        Self {
            approved_workspace: approved_workspace.into(),
            canonicalize,
            content: String::new(),
            content_candidate_free: true,
            content_start: 0,
            stream_end: 0,
            ledger: Ledger::new(),
            released: VecDeque::new(),
            withhold_from: None,
            finished: false,
        }
    }

    /// Appends one committed delta and returns newly completed projections.
    pub fn push<E>(
        &mut self,
        run_seq: u64,
        text: &str,
        payload: &Value,
    ) -> Result<Vec<Projection>, ProjectorError>
    where
        C: FnMut(&Path) -> Result<PathBuf, E>,
    {
        if self.finished {
            return Err(ProjectorError::Finished);
        }
        if matches!(
            read_content_disclosure(payload),
            ContentDisclosure::Withheld(_)
        ) {
            self.ledger.push_withheld(run_seq);
            if self.withhold_from.is_some() {
                return self.resolve(self.stream_end, &[]);
            }
            return self.scan_and_resolve(false);
        }
        let byte_len =
            u64::try_from(text.len()).map_err(|_| ProjectorError::InvalidStreamOffset)?;
        self.ledger.push(run_seq, byte_len)?;
        self.stream_end = self
            .stream_end
            .checked_add(byte_len)
            .ok_or(ProjectorError::InvalidStreamOffset)?;

        if let Some(withhold_from) = self.withhold_from {
            return self.resolve(
                self.stream_end,
                std::slice::from_ref(&(withhold_from..self.stream_end)),
            );
        }

        if self.content_candidate_free
            && candidate_free(text)
            && !(self.content.ends_with('\\') && text.starts_with('\\'))
        {
            self.content.push_str(text);
            let mut boundary = self.content.len().saturating_sub(MAX_UNRESOLVED_SUFFIX);
            while !self.content.is_char_boundary(boundary) {
                boundary -= 1;
            }
            let global_boundary = self.global_offset(boundary)?;
            self.remember_span(0..boundary);
            let projections = self.resolve(global_boundary, &[])?;
            self.content.drain(..boundary);
            self.content_start = global_boundary;
            return Ok(projections);
        }

        self.content.push_str(text);
        self.scan_and_resolve(false)
    }

    /// Resolves the safe prefix while retaining an unresolved suffix.
    pub fn flush<E>(&mut self) -> Result<Vec<Projection>, ProjectorError>
    where
        C: FnMut(&Path) -> Result<PathBuf, E>,
    {
        if self.finished {
            return Err(ProjectorError::Finished);
        }
        self.scan_and_resolve(false)
    }

    /// Resolves the terminal suffix and returns every remaining projection.
    pub fn finish<E>(&mut self) -> Result<Vec<Projection>, ProjectorError>
    where
        C: FnMut(&Path) -> Result<PathBuf, E>,
    {
        if self.finished {
            return Err(ProjectorError::Finished);
        }
        self.finished = true;
        if let Some(withhold_from) = self.withhold_from {
            return self.resolve(
                self.stream_end,
                std::slice::from_ref(&(withhold_from..self.stream_end)),
            );
        }
        self.scan_and_resolve(true)
    }

    fn scan_and_resolve<E>(&mut self, complete: bool) -> Result<Vec<Projection>, ProjectorError>
    where
        C: FnMut(&Path) -> Result<PathBuf, E>,
    {
        let scan = scan_with_workspace_for_projector(
            &self.content,
            complete,
            &self.approved_workspace,
            &mut self.canonicalize,
        );
        if let Some(start) = scan.withhold_from {
            let local_start = start;
            let start = self.global_offset(local_start)?;
            self.withhold_from = Some(start);
            let end = self.stream_end;
            let mut withheld: Vec<_> = scan
                .matches
                .iter()
                .filter_map(|matched| local_range_to_global(self.content_start, &matched.range))
                .collect();
            withheld.push(start..end);
            self.remember_released(local_start, &scan.matches, false);
            self.content.clear();
            self.content_candidate_free = true;
            self.content_start = end;
            return self.resolve(end, &withheld);
        }

        let mut boundary = scan.retention_offset;
        if !complete {
            for matched in &scan.matches {
                if matched.range.start < boundary && boundary < matched.range.end {
                    if matched.range.end == self.content.len() {
                        boundary = matched.range.start;
                    } else {
                        boundary = matched.range.end;
                    }
                }
            }
        }

        let global_boundary = self.global_offset(boundary)?;
        let final_matches: Vec<_> = scan
            .matches
            .iter()
            .filter(|matched| complete || matched.range.end < self.content.len())
            .filter_map(|matched| local_range_to_global(self.content_start, &matched.range))
            .filter(|range| range.end <= global_boundary)
            .collect();
        self.remember_released(boundary, &scan.matches, complete);
        let projections = self.resolve(global_boundary, &final_matches)?;
        self.content.drain(..boundary);
        self.content_candidate_free = candidate_free(&self.content);
        self.content_start = global_boundary;
        Ok(projections)
    }

    fn remember_released(&mut self, boundary: usize, matches: &[Match], complete: bool) {
        let mut withheld: Vec<_> = matches
            .iter()
            .filter(|matched| complete || matched.range.end < self.content.len())
            .map(|matched| matched.range.clone())
            .collect();
        withheld.sort_by_key(|range| range.start);
        let mut cursor = 0;
        for range in withheld {
            let start = range.start.min(boundary);
            if cursor < start {
                self.remember_span(cursor..start);
            }
            cursor = cursor.max(range.end.min(boundary));
        }
        if cursor < boundary {
            self.remember_span(cursor..boundary);
        }
    }

    fn remember_span(&mut self, range: Range<usize>) {
        let start = self.content_start + range.start as u64;
        let bytes = &self.content.as_bytes()[range];
        if let Some(last) = self.released.back_mut() {
            if last.start + (last.bytes.len() - last.offset) as u64 == start {
                last.bytes.extend_from_slice(bytes);
                return;
            }
        }
        self.released.push_back(ReleasedSpan {
            start,
            bytes: bytes.to_vec(),
            offset: 0,
        });
    }

    fn resolve(
        &mut self,
        boundary: u64,
        withheld: &[Range<u64>],
    ) -> Result<Vec<Projection>, ProjectorError> {
        let projections = self.ledger.resolve(boundary, withheld)?;
        Ok(projections
            .into_iter()
            .map(|projection| self.project(projection))
            .collect())
    }

    fn project(&mut self, projection: LedgerProjection) -> Projection {
        let mut bytes = Vec::new();
        for range in projection.released_ranges {
            self.take_released(range, &mut bytes);
        }
        let text = (!bytes.is_empty())
            .then(|| String::from_utf8(bytes).expect("scanner boundaries preserve UTF-8"));
        Projection {
            run_seq: projection.run_seq,
            withheld: text.is_none(),
            text,
        }
    }

    fn take_released(&mut self, range: Range<u64>, output: &mut Vec<u8>) {
        while let Some(mut span) = self.released.pop_front() {
            let remaining_len = span.bytes.len() - span.offset;
            let end = span.start + remaining_len as u64;
            if end <= range.start {
                continue;
            }
            if span.start >= range.end {
                self.released.push_front(span);
                break;
            }
            let start = usize::try_from(range.start.saturating_sub(span.start)).unwrap();
            let take_end =
                usize::try_from((range.end - span.start).min(remaining_len as u64)).unwrap();
            output.extend_from_slice(&span.bytes[span.offset + start..span.offset + take_end]);
            if take_end < remaining_len {
                span.start += take_end as u64;
                span.offset += take_end;
                self.released.push_front(span);
                break;
            }
        }
    }

    fn global_offset(&self, local: usize) -> Result<u64, ProjectorError> {
        self.content_start
            .checked_add(u64::try_from(local).map_err(|_| ProjectorError::InvalidStreamOffset)?)
            .ok_or(ProjectorError::InvalidStreamOffset)
    }
}

fn candidate_free(text: &str) -> bool {
    let bytes = text.as_bytes();
    !bytes
        .iter()
        .any(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'-' | b'_'))
        && !bytes.windows(2).any(|pair| pair == b"\\\\")
}

fn local_range_to_global(start: u64, range: &Range<usize>) -> Option<Range<u64>> {
    Some(start.checked_add(range.start as u64)?..start.checked_add(range.end as u64)?)
}
