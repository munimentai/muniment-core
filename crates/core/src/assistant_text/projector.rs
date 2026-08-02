//! Stateful projection of ordered assistant text envelopes.

use super::{
    ledger::{Ledger, LedgerError, Projection as LedgerProjection},
    scan_with_workspace, Match,
};
use crate::journal::content_disclosure::{read_content_disclosure, ContentDisclosure};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ops::Range,
    path::{Path, PathBuf},
};

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
    content_start: u64,
    stream_end: u64,
    ledger: Ledger,
    released: BTreeMap<u64, u8>,
    withhold_from: Option<u64>,
    finished: bool,
}

impl<C> Projector<C> {
    pub fn new(approved_workspace: impl Into<PathBuf>, canonicalize: C) -> Self {
        Self {
            approved_workspace: approved_workspace.into(),
            canonicalize,
            content: String::new(),
            content_start: 0,
            stream_end: 0,
            ledger: Ledger::new(),
            released: BTreeMap::new(),
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

        self.content.push_str(text);
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
        let scan = scan_with_workspace(
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
            for (offset, byte) in self.content.as_bytes()[..local_start]
                .iter()
                .copied()
                .enumerate()
            {
                if !scan
                    .matches
                    .iter()
                    .any(|matched| matched.range.contains(&offset))
                {
                    self.released
                        .insert(self.content_start + offset as u64, byte);
                }
            }
            self.content.clear();
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
        self.content_start = global_boundary;
        Ok(projections)
    }

    fn remember_released(&mut self, boundary: usize, matches: &[Match], complete: bool) {
        let withheld: Vec<_> = matches
            .iter()
            .filter(|matched| complete || matched.range.end < self.content.len())
            .map(|matched| matched.range.clone())
            .collect();
        for (offset, byte) in self.content.as_bytes()[..boundary]
            .iter()
            .copied()
            .enumerate()
        {
            if !withheld.iter().any(|range| range.contains(&offset)) {
                self.released
                    .insert(self.content_start + offset as u64, byte);
            }
        }
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
            for offset in range {
                if let Some(byte) = self.released.remove(&offset) {
                    bytes.push(byte);
                }
            }
        }
        let text = (!bytes.is_empty())
            .then(|| String::from_utf8(bytes).expect("scanner boundaries preserve UTF-8"));
        Projection {
            run_seq: projection.run_seq,
            withheld: text.is_none(),
            text,
        }
    }

    fn global_offset(&self, local: usize) -> Result<u64, ProjectorError> {
        self.content_start
            .checked_add(u64::try_from(local).map_err(|_| ProjectorError::InvalidStreamOffset)?)
            .ok_or(ProjectorError::InvalidStreamOffset)
    }
}

fn local_range_to_global(start: u64, range: &Range<usize>) -> Option<Range<u64>> {
    Some(start.checked_add(range.start as u64)?..start.checked_add(range.end as u64)?)
}
