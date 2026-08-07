//! Secret rejection for every memory write path.
//!
//! harness-spec §17 rule 7 binds every memory write path to filter secrets. A
//! write holds the whole record, so the scan here runs with `complete` set
//! true and applies only the four secret rules. It applies no workspace path
//! policy, so an absolute path in a memory record stays acceptable.

use std::{fmt, ops::Range};

use crate::assistant_text::{scan, Rule};

/// Why muniment-core rejected a memory record. It never carries matched text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MemorySecretRejection {
    /// The first rule that matched and the bytes it covers.
    Matched { rule: Rule, range: Range<usize> },
    /// An over-span secret candidate withheld these bytes through the record end.
    Withheld { range: Range<usize> },
}

impl MemorySecretRejection {
    /// The rejected byte range within the record.
    pub fn range(&self) -> Range<usize> {
        match self {
            Self::Matched { range, .. } | Self::Withheld { range } => range.clone(),
        }
    }

    /// The rule that matched, absent for an over-span secret candidate.
    pub fn rule(&self) -> Option<Rule> {
        match self {
            Self::Matched { rule, .. } => Some(*rule),
            Self::Withheld { .. } => None,
        }
    }
}

impl fmt::Display for MemorySecretRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let range = self.range();
        let subject = match self.rule() {
            Some(rule) => rule_subject(rule),
            None => "an over-span secret candidate",
        };
        write!(
            formatter,
            "The memory record carries {subject} at bytes {}..{}.",
            range.start, range.end
        )
    }
}

impl std::error::Error for MemorySecretRejection {}

/// Rejects a memory record that carries a credential.
///
/// A write holds the whole record, so the scan runs with `complete` set true.
/// The rejection reports the first offending byte range and never the text.
pub fn reject_memory_secret(content: &str) -> Result<(), MemorySecretRejection> {
    let result = scan(content, true);
    if let Some(first) = result.matches.first() {
        return Err(MemorySecretRejection::Matched {
            rule: first.rule,
            range: first.range.clone(),
        });
    }
    // The scanner stops at an over-span candidate, so every match precedes it.
    if let Some(start) = result.withhold_from {
        return Err(MemorySecretRejection::Withheld {
            range: start..content.len(),
        });
    }
    Ok(())
}

const fn rule_subject(rule: Rule) -> &'static str {
    match rule {
        Rule::SecretProviderToken => "a provider token",
        Rule::SecretJwt => "a JSON Web Token",
        Rule::SecretPemPrivateKey => "a private key block",
        Rule::SecretAssignment => "a secret assignment",
        // `scan` applies no path policy, so no path rule reaches this arm.
        Rule::PathPosixAbsolute | Rule::PathWindowsAbsolute => "an absolute path",
    }
}
