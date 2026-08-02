//! Pure scanning for the `assistant-text-v1` assistant reply rules.

use std::ops::Range;

/// A rule in the `assistant-text-v1` rule set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// A provider credential such as a GitHub or OpenAI token.
    SecretProviderToken,
    /// A JSON Web Token.
    SecretJwt,
    /// A PEM private key block.
    SecretPemPrivateKey,
    /// A secret in an assignment.
    SecretAssignment,
}

const RULE_ORDER: [Rule; 4] = [
    Rule::SecretProviderToken,
    Rule::SecretJwt,
    Rule::SecretPemPrivateKey,
    Rule::SecretAssignment,
];

/// One non-overlapping byte range selected by the scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Match {
    pub range: Range<usize>,
    pub rule: Rule,
}

/// The result of scanning the content available so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scan {
    pub matches: Vec<Match>,
    /// The first byte a streaming caller must retain for the next scan.
    pub retention_offset: usize,
    /// The first byte to withhold through the end after an over-span candidate.
    pub withhold_from: Option<usize>,
}

#[derive(Clone, Copy)]
struct Alternative {
    prefix: &'static [u8],
    min_body: usize,
    max_body: usize,
    alphabet: fn(u8) -> bool,
}

const ALTERNATIVES: [Alternative; 15] = [
    alternative(b"ghp_", 36, 508, is_alnum),
    alternative(b"gho_", 36, 508, is_alnum),
    alternative(b"ghu_", 36, 508, is_alnum),
    alternative(b"ghs_", 36, 508, is_alnum),
    alternative(b"ghr_", 36, 508, is_alnum),
    alternative(b"github_pat_", 82, 501, is_alnum_underscore),
    alternative(b"sk-", 20, 509, is_b64),
    alternative(b"sk-ant-", 20, 505, is_b64),
    alternative(b"xoxb-", 10, 504, is_alnum_hyphen),
    alternative(b"xoxa-", 10, 504, is_alnum_hyphen),
    alternative(b"xoxp-", 10, 504, is_alnum_hyphen),
    alternative(b"xoxr-", 10, 504, is_alnum_hyphen),
    alternative(b"xoxs-", 10, 504, is_alnum_hyphen),
    alternative(b"sk_live_", 16, 504, is_alnum),
    alternative(b"rk_live_", 16, 504, is_alnum),
];

const fn alternative(
    prefix: &'static [u8],
    min_body: usize,
    max_body: usize,
    alphabet: fn(u8) -> bool,
) -> Alternative {
    Alternative {
        prefix,
        min_body,
        max_body,
        alphabet,
    }
}

/// Scans assistant reply content under the `assistant-text-v1` rules.
///
/// `complete` states that no later bytes can extend the supplied content.
pub fn scan(content: &str, complete: bool) -> Scan {
    let bytes = content.as_bytes();
    let mut matches = Vec::new();
    let mut withhold_from = None;
    let mut start = 0;

    while start < bytes.len() {
        let candidates = RULE_ORDER.map(|rule| rule.candidate(bytes, start, complete));
        if candidates.contains(&RuleCandidate::OverSpan) {
            withhold_from = Some(start);
            break;
        }
        let candidates =
            candidates
                .into_iter()
                .enumerate()
                .filter_map(|(rule_order, candidate)| {
                    let RuleCandidate::Matched(end) = candidate else {
                        return None;
                    };
                    Some(Candidate { end, rule_order })
                });
        if let Some(candidate) = arbitrate(candidates) {
            matches.push(Match {
                range: start..candidate.end,
                rule: RULE_ORDER[candidate.rule_order],
            });
            start = candidate.end;
            continue;
        }
        start += 1;
    }

    let retention_offset = if complete {
        content.len()
    } else {
        let max_span = RULE_ORDER
            .iter()
            .map(|rule| rule.max_span())
            .max()
            .unwrap_or(0);
        scalar_boundary_at_or_before(
            content,
            content.len().saturating_sub(max_span.saturating_sub(1)),
        )
    };
    Scan {
        matches,
        retention_offset,
        withhold_from,
    }
}

impl Rule {
    fn candidate(self, bytes: &[u8], start: usize, complete: bool) -> RuleCandidate {
        match self {
            Self::SecretProviderToken => provider_token_candidate(bytes, start, complete),
            Self::SecretJwt => jwt_candidate(bytes, start, complete),
            Self::SecretPemPrivateKey => pem_private_key_candidate(bytes, start, complete),
            Self::SecretAssignment => assignment_candidate(bytes, start, complete),
        }
    }

    const fn max_span(self) -> usize {
        match self {
            Self::SecretProviderToken => 512,
            Self::SecretJwt => 8_192,
            Self::SecretPemPrivateKey => 65_536,
            Self::SecretAssignment => 192,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleCandidate {
    Matched(usize),
    OverSpan,
    None,
}

fn assignment_candidate(_bytes: &[u8], _start: usize, _complete: bool) -> RuleCandidate {
    RuleCandidate::None
}

fn jwt_candidate(bytes: &[u8], start: usize, complete: bool) -> RuleCandidate {
    const FIRST_MIN: usize = 17;
    const FIRST_MAX: usize = 2_726;
    const THIRD_MAX: usize = 2_724;

    if start != 0 && is_b64(bytes[start - 1]) {
        return RuleCandidate::None;
    }

    let Some(first_end) = jwt_segment_end(bytes, start, FIRST_MAX) else {
        return RuleCandidate::OverSpan;
    };
    if first_end - start < FIRST_MIN || bytes.get(first_end) != Some(&b'.') {
        return RuleCandidate::None;
    }

    let second_start = first_end + 1;
    let Some(second_end) = jwt_segment_end(bytes, second_start, FIRST_MAX) else {
        return RuleCandidate::OverSpan;
    };
    if second_end - second_start < FIRST_MIN || bytes.get(second_end) != Some(&b'.') {
        return RuleCandidate::None;
    }

    let third_start = second_end + 1;
    let Some(mut end) = jwt_segment_end(bytes, third_start, THIRD_MAX) else {
        return RuleCandidate::OverSpan;
    };
    for _ in 0..2 {
        if bytes.get(end) == Some(&b'=') {
            end += 1;
        }
    }
    if bytes.get(end) == Some(&b'=') || end < bytes.len() && is_b64(bytes[end]) {
        return RuleCandidate::None;
    }
    if end == bytes.len() && !complete {
        return RuleCandidate::None;
    }
    RuleCandidate::Matched(end)
}

fn jwt_segment_end(bytes: &[u8], start: usize, max: usize) -> Option<usize> {
    let mut end = start;
    while end < bytes.len() && end - start < max && is_b64(bytes[end]) {
        end += 1;
    }
    if end < bytes.len() && is_b64(bytes[end]) {
        None
    } else {
        Some(end)
    }
}

fn provider_token_candidate(bytes: &[u8], start: usize, complete: bool) -> RuleCandidate {
    if !has_provider_token_start_boundary(bytes, start) {
        return RuleCandidate::None;
    }
    let mut longest = None;
    let mut over_span = false;
    for alternative in alternatives_at(bytes, start) {
        match scan_alternative(bytes, start, alternative, complete) {
            RuleCandidate::Matched(end) if longest.is_none_or(|current| end > current) => {
                longest = Some(end);
            }
            RuleCandidate::OverSpan => over_span = true,
            RuleCandidate::Matched(_) | RuleCandidate::None => {}
        }
    }
    if over_span {
        RuleCandidate::OverSpan
    } else if let Some(end) = longest {
        RuleCandidate::Matched(end)
    } else {
        RuleCandidate::None
    }
}

fn pem_private_key_candidate(bytes: &[u8], start: usize, _complete: bool) -> RuleCandidate {
    const HEADER_NAMES: [&[u8]; 6] = [
        b"PRIVATE KEY",
        b"ENCRYPTED PRIVATE KEY",
        b"RSA PRIVATE KEY",
        b"DSA PRIVATE KEY",
        b"EC PRIVATE KEY",
        b"OPENSSH PRIVATE KEY",
    ];
    const BEGIN_PREFIX: &[u8] = b"-----BEGIN ";
    const BEGIN_SUFFIX: &[u8] = b"-----";
    const END_PREFIX: &[u8] = b"-----END ";
    const END_SUFFIX: &[u8] = b"-----";
    const MAX_BODY: usize = 65_460;

    if start != 0 && bytes[start - 1] != b'\n' {
        return RuleCandidate::None;
    }

    let Some(header_name) = HEADER_NAMES.into_iter().find(|header_name| {
        let candidate = &bytes[start..];
        candidate.starts_with(BEGIN_PREFIX)
            && candidate[BEGIN_PREFIX.len()..].starts_with(header_name)
            && candidate[BEGIN_PREFIX.len() + header_name.len()..].starts_with(BEGIN_SUFFIX)
    }) else {
        return RuleCandidate::None;
    };

    let begin_end = start + BEGIN_PREFIX.len() + header_name.len() + BEGIN_SUFFIX.len();
    let body_start = if bytes[begin_end..].starts_with(b"\r\n") {
        begin_end + 2
    } else if bytes[begin_end..].starts_with(b"\n") {
        begin_end + 1
    } else {
        return RuleCandidate::None;
    };
    let mut end = body_start;
    while end < bytes.len() && end - body_start < MAX_BODY {
        if bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'+' | b'/' | b'=' | b'\n') {
            end += 1;
        } else if bytes[end] == b'\r' {
            if end - body_start + 2 > MAX_BODY || !bytes[end..].starts_with(b"\r\n") {
                return RuleCandidate::OverSpan;
            }
            end += 2;
        } else {
            break;
        }
    }

    if end == body_start
        || !bytes[end..].starts_with(END_PREFIX)
        || !bytes[end + END_PREFIX.len()..].starts_with(header_name)
        || !bytes[end + END_PREFIX.len() + header_name.len()..].starts_with(END_SUFFIX)
    {
        return RuleCandidate::OverSpan;
    }
    end += END_PREFIX.len() + header_name.len() + END_SUFFIX.len();
    if end < bytes.len() && bytes[end] != b'\n' && !bytes[end..].starts_with(b"\r\n") {
        return RuleCandidate::OverSpan;
    }
    RuleCandidate::Matched(end)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Candidate {
    end: usize,
    rule_order: usize,
}

fn arbitrate(candidates: impl IntoIterator<Item = Candidate>) -> Option<Candidate> {
    let mut selected: Option<Candidate> = None;
    for candidate in candidates {
        if selected.is_none_or(|current| {
            candidate.end > current.end
                || candidate.end == current.end && candidate.rule_order < current.rule_order
        }) {
            selected = Some(candidate);
        }
    }
    selected
}

fn alternatives_at(bytes: &[u8], start: usize) -> impl Iterator<Item = Alternative> + '_ {
    ALTERNATIVES
        .into_iter()
        .chain([
            alternative(b"hf_", 20, 509, is_alnum),
            alternative(b"AKIA", 16, 16, is_upper_alnum),
            alternative(b"ASIA", 16, 16, is_upper_alnum),
        ])
        .filter(move |alternative| bytes[start..].starts_with(alternative.prefix))
}

fn scan_alternative(
    bytes: &[u8],
    start: usize,
    alternative: Alternative,
    complete: bool,
) -> RuleCandidate {
    let body_start = start + alternative.prefix.len();
    let mut end = body_start;
    while end < bytes.len()
        && end - body_start < alternative.max_body
        && (alternative.alphabet)(bytes[end])
    {
        end += 1;
    }
    let body_len = end - body_start;
    if body_len == alternative.max_body
        && (end < bytes.len() && (alternative.alphabet)(bytes[end])
            || end == bytes.len() && !complete)
    {
        return RuleCandidate::OverSpan;
    }
    if end == bytes.len() && !complete {
        return RuleCandidate::None;
    }
    if body_len >= alternative.min_body {
        RuleCandidate::Matched(end)
    } else {
        RuleCandidate::None
    }
}

fn has_provider_token_start_boundary(bytes: &[u8], start: usize) -> bool {
    start == 0 || !is_alnum_underscore(bytes[start - 1])
}

fn scalar_boundary_at_or_before(content: &str, mut offset: usize) -> usize {
    while !content.is_char_boundary(offset) {
        offset -= 1;
    }
    offset
}

const fn is_alnum(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

const fn is_alnum_underscore(byte: u8) -> bool {
    is_alnum(byte) || byte == b'_'
}

const fn is_b64(byte: u8) -> bool {
    is_alnum_underscore(byte) || byte == b'-'
}

const fn is_alnum_hyphen(byte: u8) -> bool {
    is_alnum(byte) || byte == b'-'
}

const fn is_upper_alnum(byte: u8) -> bool {
    byte.is_ascii_uppercase() || byte.is_ascii_digit()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_boundary_moves_before_a_partial_scalar() {
        let content = format!("{}é", "x".repeat(510));
        assert_eq!(scalar_boundary_at_or_before(&content, 511), 510);
    }

    #[test]
    fn incomplete_candidate_waits_for_its_terminator() {
        let content = format!("sk-{}", "a".repeat(20));
        assert!(scan(&content, false).matches.is_empty());
        assert_eq!(scan(&content, true).matches[0].range, 0..content.len());
    }

    #[test]
    fn arbitration_selects_the_longest_candidate_then_rule_order() {
        let shorter_first = Candidate {
            end: 20,
            rule_order: 0,
        };
        let longer_second = Candidate {
            end: 30,
            rule_order: 1,
        };
        assert_eq!(
            arbitrate([shorter_first, longer_second]),
            Some(longer_second)
        );

        let later_rule = Candidate {
            end: 30,
            rule_order: 1,
        };
        let earlier_rule = Candidate {
            end: 30,
            rule_order: 0,
        };
        assert_eq!(arbitrate([later_rule, earlier_rule]), Some(earlier_rule));
    }
}
