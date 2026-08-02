//! Pure scanning for the `assistant-text-v1` assistant reply rules.

pub mod ledger;
pub mod projector;

use std::{
    ops::Range,
    path::{Path, PathBuf},
};

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
    /// A POSIX absolute path outside the approved workspace.
    PathPosixAbsolute,
    /// A Windows absolute path outside the approved workspace.
    PathWindowsAbsolute,
}

const RULE_ORDER: [Rule; 4] = [
    Rule::SecretProviderToken,
    Rule::SecretJwt,
    Rule::SecretPemPrivateKey,
    Rule::SecretAssignment,
];

const ASSIGNMENT_LABELS: [&[u8]; 12] = [
    b"key",
    b"api_key",
    b"apikey",
    b"api-token",
    b"token",
    b"secret",
    b"client_secret",
    b"passwd",
    b"password",
    b"auth",
    b"authorization",
    b"access_token",
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

/// A lexical path candidate found outside workspace policy validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathCandidate {
    Matched(Range<usize>),
    OverSpan,
    None,
}

/// The workspace-policy result for a lexical path candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathClassification {
    Released(Range<usize>),
    /// The first byte to withhold through the candidate's end.
    Withheld(usize),
    None,
}

/// Classifies a POSIX path through injected current filesystem resolution.
pub fn classify_posix_absolute_path<E>(
    content: &str,
    start: usize,
    approved_workspace: &Path,
    mut canonicalize: impl FnMut(&Path) -> Result<PathBuf, E>,
) -> PathClassification {
    match posix_absolute_path_candidate(content, start) {
        PathCandidate::Matched(range) => {
            let path = Path::new(&content[range.clone()]);
            let in_scope = canonicalize(approved_workspace).and_then(|workspace| {
                canonicalize(path).map(|candidate| candidate.starts_with(workspace))
            });
            match in_scope {
                Ok(true) => PathClassification::Released(range),
                Ok(false) | Err(_) => PathClassification::Withheld(start),
            }
        }
        PathCandidate::OverSpan => PathClassification::Withheld(start),
        PathCandidate::None => PathClassification::None,
    }
}

/// Classifies a Windows path through injected current filesystem resolution.
pub fn classify_windows_absolute_path<E>(
    content: &str,
    start: usize,
    approved_workspace: &Path,
    mut canonicalize: impl FnMut(&Path) -> Result<PathBuf, E>,
) -> PathClassification {
    match windows_absolute_path_candidate(content, start) {
        PathCandidate::Matched(range) => {
            let path = Path::new(&content[range.clone()]);
            let in_scope = canonicalize(approved_workspace).and_then(|workspace| {
                canonicalize(path).map(|candidate| candidate.starts_with(workspace))
            });
            match in_scope {
                Ok(true) => PathClassification::Released(range),
                Ok(false) | Err(_) => PathClassification::Withheld(start),
            }
        }
        PathCandidate::OverSpan => PathClassification::Withheld(start),
        PathCandidate::None => PathClassification::None,
    }
}

/// Recognizes a bounded POSIX absolute path at `start`.
pub fn posix_absolute_path_candidate(content: &str, start: usize) -> PathCandidate {
    const MAX_SPAN: usize = 4_096;

    let bytes = content.as_bytes();
    if bytes.get(start) != Some(&b'/')
        || !content.is_char_boundary(start)
        || start != 0 && !is_path_boundary(bytes[start - 1])
    {
        return PathCandidate::None;
    }

    let mut end = start + 1;
    if bytes.get(end).is_none_or(|byte| is_path_end(*byte)) {
        return PathCandidate::Matched(start..end);
    }

    loop {
        let component_start = end;
        while let Some(byte) = bytes.get(end) {
            if is_path_end(*byte) || matches!(byte, b'/' | b'\\') {
                break;
            }
            end += 1;
            if end - start > MAX_SPAN {
                return PathCandidate::OverSpan;
            }
        }
        if end == component_start {
            return PathCandidate::None;
        }
        match bytes.get(end) {
            None => return PathCandidate::Matched(start..end),
            Some(byte) if is_path_end(*byte) => return PathCandidate::Matched(start..end),
            Some(b'/') if end - start < MAX_SPAN => end += 1,
            Some(b'/') => return PathCandidate::OverSpan,
            Some(b'\\') | Some(_) => return PathCandidate::None,
        }
    }
}

/// Recognizes a bounded Windows absolute path at `start`.
pub fn windows_absolute_path_candidate(content: &str, start: usize) -> PathCandidate {
    const MAX_SPAN: usize = 4_096;

    let bytes = content.as_bytes();
    if !content.is_char_boundary(start)
        || start != 0
            && !bytes
                .get(start - 1)
                .is_some_and(|byte| is_path_boundary(*byte))
    {
        return PathCandidate::None;
    }

    let mut end = start;
    if bytes.get(end).is_some_and(u8::is_ascii_alphabetic)
        && bytes.get(end + 1) == Some(&b':')
        && bytes.get(end + 2) == Some(&b'\\')
    {
        end += 3;
    } else if bytes.get(end..end + 4) == Some(b"\\\\?\\") {
        end += 4;
        if bytes.get(end).is_some_and(u8::is_ascii_alphabetic)
            && bytes.get(end + 1) == Some(&b':')
            && bytes.get(end + 2) == Some(&b'\\')
        {
            end += 3;
        } else if bytes.get(end..end + 4) == Some(b"UNC\\") {
            end += 4;
            end = match windows_root_component(bytes, start, end, MAX_SPAN) {
                Ok(end) => end,
                Err(result) => return result,
            };
            end = match windows_root_component(bytes, start, end, MAX_SPAN) {
                Ok(end) => end,
                Err(result) => return result,
            };
        } else {
            return PathCandidate::None;
        }
    } else if bytes.get(end..end + 2) == Some(b"\\\\") {
        end += 2;
        end = match windows_root_component(bytes, start, end, MAX_SPAN) {
            Ok(end) => end,
            Err(result) => return result,
        };
        end = match windows_root_component(bytes, start, end, MAX_SPAN) {
            Ok(end) => end,
            Err(result) => return result,
        };
    } else {
        return PathCandidate::None;
    }

    if end - start > MAX_SPAN {
        return PathCandidate::OverSpan;
    }
    if bytes.get(end).is_none_or(|byte| is_path_end(*byte)) {
        return PathCandidate::Matched(start..end);
    }

    loop {
        let component_start = end;
        while let Some(byte) = bytes.get(end) {
            if is_path_end(*byte) || matches!(byte, b'/' | b'\\') {
                break;
            }
            end += 1;
            if end - start > MAX_SPAN {
                return PathCandidate::OverSpan;
            }
        }
        if end == component_start {
            return PathCandidate::None;
        }
        match bytes.get(end) {
            None => return PathCandidate::Matched(start..end),
            Some(byte) if is_path_end(*byte) => return PathCandidate::Matched(start..end),
            Some(b'\\') => {
                end += 1;
                if end - start > MAX_SPAN {
                    return PathCandidate::OverSpan;
                }
            }
            Some(b'/') | Some(_) => return PathCandidate::None,
        }
    }
}

fn windows_root_component(
    bytes: &[u8],
    start: usize,
    mut end: usize,
    max_span: usize,
) -> Result<usize, PathCandidate> {
    let component_start = end;
    while let Some(byte) = bytes.get(end) {
        if is_path_end(*byte) || matches!(byte, b'/' | b'\\') {
            break;
        }
        end += 1;
        if end - start > max_span {
            return Err(PathCandidate::OverSpan);
        }
    }
    if end == component_start || bytes.get(end) != Some(&b'\\') {
        return Err(PathCandidate::None);
    }
    end += 1;
    if end - start > max_span {
        return Err(PathCandidate::OverSpan);
    }
    Ok(end)
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
    scan_with_path_candidate(content, complete, |_, _| PathClassification::None, false)
}

/// Scans assistant reply content and applies workspace path policy.
///
/// `complete` states that no later bytes can extend the supplied content.
pub fn scan_with_workspace<E>(
    content: &str,
    complete: bool,
    approved_workspace: &Path,
    mut canonicalize: impl FnMut(&Path) -> Result<PathBuf, E>,
) -> Scan {
    scan_with_workspace_mode(
        content,
        complete,
        approved_workspace,
        &mut canonicalize,
        false,
    )
}

pub(super) fn scan_with_workspace_for_projector<E>(
    content: &str,
    complete: bool,
    approved_workspace: &Path,
    mut canonicalize: impl FnMut(&Path) -> Result<PathBuf, E>,
) -> Scan {
    scan_with_workspace_mode(
        content,
        complete,
        approved_workspace,
        &mut canonicalize,
        true,
    )
}

fn scan_with_workspace_mode<E>(
    content: &str,
    complete: bool,
    approved_workspace: &Path,
    mut canonicalize: impl FnMut(&Path) -> Result<PathBuf, E>,
    wait_for_incomplete_pem: bool,
) -> Scan {
    scan_with_path_candidate(
        content,
        complete,
        |content, start| {
            let posix =
                classify_posix_absolute_path(content, start, approved_workspace, &mut canonicalize);
            if posix == PathClassification::None {
                classify_windows_absolute_path(
                    content,
                    start,
                    approved_workspace,
                    &mut canonicalize,
                )
            } else {
                posix
            }
        },
        wait_for_incomplete_pem,
    )
}

fn scan_with_path_candidate(
    content: &str,
    complete: bool,
    mut classify_path: impl FnMut(&str, usize) -> PathClassification,
    wait_for_incomplete_pem: bool,
) -> Scan {
    let bytes = content.as_bytes();
    let mut matches = Vec::new();
    let mut withhold_from = None;
    let mut start = 0;

    while start < bytes.len() {
        let candidates =
            RULE_ORDER.map(|rule| rule.candidate(bytes, start, complete, wait_for_incomplete_pem));
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
        match classify_path(content, start) {
            PathClassification::Released(_) => {
                start += 1;
                continue;
            }
            PathClassification::Withheld(withheld_start) => {
                let (candidate, rule) = match posix_absolute_path_candidate(content, start) {
                    PathCandidate::None => (
                        windows_absolute_path_candidate(content, start),
                        Rule::PathWindowsAbsolute,
                    ),
                    candidate => (candidate, Rule::PathPosixAbsolute),
                };
                match candidate {
                    PathCandidate::Matched(range) => {
                        start = range.end;
                        matches.push(Match { range, rule });
                        continue;
                    }
                    PathCandidate::OverSpan => {
                        withhold_from = Some(withheld_start);
                        break;
                    }
                    PathCandidate::None => {}
                }
            }
            PathClassification::None => {}
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
    fn candidate(
        self,
        bytes: &[u8],
        start: usize,
        complete: bool,
        wait_for_incomplete_pem: bool,
    ) -> RuleCandidate {
        match self {
            Self::SecretProviderToken => provider_token_candidate(bytes, start, complete),
            Self::SecretJwt => jwt_candidate(bytes, start, complete),
            Self::SecretPemPrivateKey => {
                pem_private_key_candidate(bytes, start, complete, wait_for_incomplete_pem)
            }
            Self::SecretAssignment => assignment_candidate(bytes, start, complete),
            Self::PathPosixAbsolute | Self::PathWindowsAbsolute => RuleCandidate::None,
        }
    }

    const fn max_span(self) -> usize {
        match self {
            Self::SecretProviderToken => 512,
            Self::SecretJwt => 8_192,
            Self::SecretPemPrivateKey => 65_536,
            Self::SecretAssignment => 192,
            Self::PathPosixAbsolute => 4_096,
            Self::PathWindowsAbsolute => 4_096,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleCandidate {
    Matched(usize),
    OverSpan,
    None,
}

fn assignment_candidate(bytes: &[u8], start: usize, complete: bool) -> RuleCandidate {
    let Some(label_end) = assignment_label_end(bytes, start) else {
        return RuleCandidate::None;
    };
    let Some(delimiter_end) = assignment_delimiter_end(bytes, label_end) else {
        return RuleCandidate::None;
    };
    let value_start = assignment_value_prefix_end(bytes, delimiter_end);
    let Some(end) = assignment_value_end(bytes, value_start) else {
        return if bytes
            .get(value_start + 150)
            .is_some_and(|byte| is_assignment_value_byte(*byte))
        {
            RuleCandidate::OverSpan
        } else {
            RuleCandidate::None
        };
    };
    if complete || end < bytes.len() {
        RuleCandidate::Matched(end)
    } else {
        RuleCandidate::None
    }
}

fn assignment_label_end(bytes: &[u8], start: usize) -> Option<usize> {
    if start
        .checked_sub(1)
        .and_then(|index| bytes.get(index))
        .is_some_and(|byte| is_ascii_identifier_byte(*byte))
    {
        return None;
    }
    ASSIGNMENT_LABELS.into_iter().find_map(|label| {
        let end = start.checked_add(label.len())?;
        let candidate = bytes.get(start..end)?;
        if candidate.eq_ignore_ascii_case(label)
            && bytes
                .get(end)
                .is_none_or(|byte| !is_ascii_identifier_byte(*byte))
        {
            Some(end)
        } else {
            None
        }
    })
}

fn assignment_delimiter_end(bytes: &[u8], start: usize) -> Option<usize> {
    const DELIMITERS: [&[u8]; 9] = [b":=", b"=>", b"<=", b"?=", b"||", b"=", b">", b":", b","];

    let mut end = start;
    while end - start < 20
        && bytes
            .get(end)
            .is_some_and(|byte| is_assignment_filler(*byte))
    {
        end += 1;
    }
    DELIMITERS
        .into_iter()
        .find(|delimiter| {
            bytes
                .get(end..)
                .is_some_and(|remaining| remaining.starts_with(delimiter))
        })
        .map(|delimiter| end + delimiter.len())
}

fn assignment_value_prefix_end(bytes: &[u8], start: usize) -> usize {
    let mut end = start;
    while end - start < 5
        && bytes
            .get(end)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'=' | b'\'' | b'"' | b'`'))
    {
        end += 1;
    }
    end
}

fn assignment_value_end(bytes: &[u8], start: usize) -> Option<usize> {
    const MIN_VALUE: usize = 10;
    const MAX_VALUE: usize = 150;

    let mut end = start;
    while end - start < MAX_VALUE
        && bytes
            .get(end)
            .is_some_and(|byte| is_assignment_value_byte(*byte))
    {
        end += 1;
    }
    (end - start >= MIN_VALUE
        && bytes.get(end).is_none_or(|byte| {
            byte.is_ascii_whitespace() || matches!(byte, b'\'' | b'"' | b'`' | b';' | b'\\')
        }))
    .then_some(end)
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

fn pem_private_key_candidate(
    bytes: &[u8],
    start: usize,
    complete: bool,
    wait_for_incomplete: bool,
) -> RuleCandidate {
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
            if wait_for_incomplete && !complete && end + 1 == bytes.len() {
                return RuleCandidate::None;
            }
            if end - body_start + 2 > MAX_BODY || !bytes[end..].starts_with(b"\r\n") {
                return RuleCandidate::OverSpan;
            }
            end += 2;
        } else {
            break;
        }
    }

    let expected_end = [END_PREFIX, header_name, END_SUFFIX].concat();
    if wait_for_incomplete
        && !complete
        && bytes[end..].len() < expected_end.len()
        && expected_end.starts_with(&bytes[end..])
    {
        return RuleCandidate::None;
    }
    if end == body_start || !bytes[end..].starts_with(&expected_end) {
        return RuleCandidate::OverSpan;
    }
    end += expected_end.len();
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
    is_ascii_identifier_byte(byte)
}

const fn is_ascii_identifier_byte(byte: u8) -> bool {
    is_alnum_underscore(byte) || byte == b'-'
}

const fn is_assignment_filler(byte: u8) -> bool {
    is_ascii_identifier_byte(byte) || matches!(byte, b'.' | b' ' | b'\t')
}

const fn is_assignment_value_byte(byte: u8) -> bool {
    is_ascii_identifier_byte(byte) || matches!(byte, b'.' | b'/' | b'+' | b'=')
}

const fn is_path_boundary(byte: u8) -> bool {
    byte.is_ascii_whitespace() || matches!(byte, b'(' | b'[' | b'{' | b':' | b'=' | b',' | b';')
}

const fn is_path_end(byte: u8) -> bool {
    matches!(
        byte,
        b'\0' | b' ' | b'\t' | b'\r' | b'\n' | b'\'' | b'"' | b'`' | b'<' | b'>' | b'|'
    )
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
    fn assignment_recognizes_each_label_at_content_boundaries() {
        for label in ASSIGNMENT_LABELS {
            assert_eq!(assignment_label_end(label, 0), Some(label.len()));

            let label = std::str::from_utf8(label).unwrap();
            let after_boundary = format!("{label}!");
            assert_eq!(
                assignment_label_end(after_boundary.as_bytes(), 0),
                Some(label.len())
            );

            let before_boundary = format!("!{label}");
            assert_eq!(
                assignment_label_end(before_boundary.as_bytes(), 1),
                Some(before_boundary.len())
            );
        }
    }

    #[test]
    fn assignment_labels_ignore_mixed_ascii_case() {
        for label in ASSIGNMENT_LABELS {
            let mixed_case: Vec<u8> = label
                .iter()
                .enumerate()
                .map(|(index, byte)| {
                    if index % 2 == 0 {
                        byte.to_ascii_uppercase()
                    } else {
                        byte.to_ascii_lowercase()
                    }
                })
                .collect();
            assert_eq!(assignment_label_end(&mixed_case, 0), Some(mixed_case.len()));
        }
    }

    #[test]
    fn assignment_rejects_identifier_bytes_on_either_side() {
        for label in ASSIGNMENT_LABELS {
            let mut invalid_before = vec![b'x'];
            invalid_before.extend_from_slice(label);
            assert_eq!(assignment_label_end(&invalid_before, 1), None);

            let mut invalid_after = label.to_vec();
            invalid_after.push(b'x');
            assert_eq!(assignment_label_end(&invalid_after, 0), None);
        }

        for identifier in *b"aZ0_-" {
            let invalid_before = [identifier, b'k', b'e', b'y'];
            assert_eq!(assignment_label_end(&invalid_before, 1), None);

            let invalid_after = [b'k', b'e', b'y', identifier];
            assert_eq!(assignment_label_end(&invalid_after, 0), None);
        }
    }

    #[test]
    fn assignment_accepts_bounded_filler_and_each_delimiter() {
        for filler in *b"aZ0_. \t-" {
            for filler_len in 0..=20 {
                let content = [vec![filler; filler_len], b"=".to_vec()].concat();
                assert_eq!(assignment_delimiter_end(&content, 0), Some(content.len()));
            }
        }

        for delimiter in [
            b"=".as_slice(),
            b">",
            b":",
            b":=",
            b"=>",
            b"<=",
            b"?=",
            b",",
            b"||",
        ] {
            assert_eq!(
                assignment_delimiter_end(delimiter, 0),
                Some(delimiter.len())
            );
        }
    }

    #[test]
    fn assignment_prefers_two_byte_delimiters() {
        for delimiter in [b":=".as_slice(), b"=>"] {
            assert_eq!(assignment_delimiter_end(delimiter, 0), Some(2));
        }
    }

    #[test]
    fn assignment_rejects_invalid_filler_and_delimiters() {
        assert_eq!(assignment_delimiter_end(b"                     =", 0), None);
        assert_eq!(assignment_delimiter_end(b" !=", 0), None);
        assert_eq!(assignment_delimiter_end(b" ", 0), None);

        for incomplete in [b"?".as_slice(), b"<", b"|"] {
            assert_eq!(assignment_delimiter_end(incomplete, 0), None);
        }
    }

    #[test]
    fn assignment_candidate_releases_recognized_prefixes() {
        for content in [
            "key=",
            "API_KEY filler :=\t='`",
            "token                    || \t'\"`=",
        ] {
            assert_eq!(
                assignment_candidate(content.as_bytes(), 0, true),
                RuleCandidate::None
            );
            assert_eq!(
                assignment_candidate(content.as_bytes(), 0, false),
                RuleCandidate::None
            );
        }
    }

    #[test]
    fn assignment_value_prefix_advances_at_most_five_bytes() {
        assert_eq!(assignment_value_prefix_end(b"value", 0), 0);
        assert_eq!(assignment_value_prefix_end(b"\t='`value", 0), 4);
        assert_eq!(assignment_value_prefix_end(b" \t'\"`value", 0), 5);

        let six_prefix_bytes = b"= \t'\"`value";
        let end = assignment_value_prefix_end(six_prefix_bytes, 0);
        assert_eq!(end, 5);
        assert_eq!(six_prefix_bytes.get(end), Some(&b'`'));
    }

    #[test]
    fn assignment_value_accepts_each_allowed_byte() {
        for byte in *b"aZ0_./+=-" {
            let value = vec![byte; 10];
            assert_eq!(assignment_value_end(&value, 0), Some(value.len()));
        }
    }

    #[test]
    fn assignment_value_requires_ten_bytes() {
        assert_eq!(assignment_value_end(b"123456789", 0), None);
        assert_eq!(assignment_value_end(b"!1234567890", 0), None);
        assert_eq!(assignment_value_end(b"x1234567890", 1), Some(11));
    }

    #[test]
    fn assignment_value_accepts_each_terminator() {
        for terminator in *b" \t\n\x0c\r'\"`;\\" {
            let content = [b"1234567890".as_slice(), &[terminator]].concat();
            assert_eq!(assignment_value_end(&content, 0), Some(10));
        }
    }

    #[test]
    fn assignment_value_accepts_content_end() {
        assert_eq!(assignment_value_end(b"1234567890", 0), Some(10));
    }

    #[test]
    fn assignment_value_rejects_unrecognized_terminator() {
        assert_eq!(assignment_value_end(b"1234567890!more", 0), None);
    }

    #[test]
    fn assignment_value_enforces_maximum_before_terminator() {
        let mut maximum = vec![b'a'; 150];
        maximum.push(b';');
        assert_eq!(assignment_value_end(&maximum, 0), Some(150));

        let over_maximum = vec![b'a'; 151];
        assert_eq!(assignment_value_end(&over_maximum, 0), None);
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
