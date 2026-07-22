//! Pure source-text packing for Kokoro synthesis.
//!
//! This module stops at ADR 0015's initial ranges. Short-segment repair and
//! final per-segment phonemization belong to follow-up boundaries.

use std::ops::Range;

const PRIMARY_LIMIT: usize = 200;
const MAX_LIMIT: usize = 400;

/// A failure to produce initial synthesis ranges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackingError {
    /// The normalized source is empty or produces no phoneme tokens.
    NoContent,
    /// No non-empty source prefix can be represented within the 400-token cap.
    UnsupportedInput,
}

impl std::fmt::Display for PackingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoContent => f.write_str("Kokoro source has no content"),
            Self::UnsupportedInput => f.write_str("Kokoro source is unsupported"),
        }
    }
}

impl std::error::Error for PackingError {}

/// Packs normalized UTF-8 source into contiguous half-open byte ranges.
///
/// `count_tokens` is the injected accent-aware phonemize/filter boundary and
/// must return the exact Kokoro token count for the supplied source slice.
/// The function performs no I/O.
pub fn pack_initial_ranges(
    source: &str,
    mut count_tokens: impl FnMut(&str) -> usize,
) -> Result<Vec<Range<usize>>, PackingError> {
    if source.is_empty() {
        return Err(PackingError::NoContent);
    }
    if count_tokens(source) == 0 {
        return Err(PackingError::NoContent);
    }

    let protected = protected_runs(source);
    let candidates = natural_candidates(source, &protected);
    let whitespace = whitespace_runs(source);
    let mut ranges = Vec::new();
    let mut start = 0;
    let mut waived_protected = None;

    while start < source.len() {
        let end = ranked_end(source, start, PRIMARY_LIMIT, &candidates, &mut count_tokens)
            .or_else(|| ranked_end(source, start, MAX_LIMIT, &candidates, &mut count_tokens))
            .or_else(|| {
                oversized_protected_end(
                    source,
                    start,
                    &protected,
                    &whitespace,
                    &mut waived_protected,
                    &mut count_tokens,
                )
            })
            .or_else(|| {
                hard_split_end(
                    source,
                    start,
                    PRIMARY_LIMIT,
                    &protected,
                    &whitespace,
                    &mut count_tokens,
                )
            })
            .ok_or(PackingError::UnsupportedInput)?;

        if end <= start || count_tokens(&source[start..end]) > MAX_LIMIT {
            return Err(PackingError::UnsupportedInput);
        }
        ranges.push(start..end);
        start = end;
        if waived_protected
            .as_ref()
            .is_some_and(|run| start >= run.end)
        {
            waived_protected = None;
        }
    }

    Ok(ranges)
}

#[derive(Clone, Copy)]
struct Candidate {
    end: usize,
    rank: u8,
}

fn ranked_end(
    source: &str,
    start: usize,
    limit: usize,
    candidates: &[Candidate],
    count: &mut impl FnMut(&str) -> usize,
) -> Option<usize> {
    (1..=3).find_map(|rank| {
        candidates
            .iter()
            .filter(|candidate| candidate.rank == rank && candidate.end > start)
            .filter(|candidate| count(&source[start..candidate.end]) <= limit)
            .map(|candidate| candidate.end)
            .max()
    })
}

fn hard_split_end(
    source: &str,
    start: usize,
    limit: usize,
    protected: &[Range<usize>],
    whitespace: &[Range<usize>],
    count: &mut impl FnMut(&str) -> usize,
) -> Option<usize> {
    source[start..]
        .char_indices()
        .skip(1)
        .map(|(offset, _)| start + offset)
        .chain(std::iter::once(source.len()))
        .filter(|&end| allowed_fallback_end(end, protected, whitespace))
        .filter(|&end| count(&source[start..end]) <= limit)
        .max()
}

fn oversized_protected_end(
    source: &str,
    start: usize,
    protected: &[Range<usize>],
    whitespace: &[Range<usize>],
    waived: &mut Option<Range<usize>>,
    count: &mut impl FnMut(&str) -> usize,
) -> Option<usize> {
    if let Some(run) = waived.as_ref().filter(|run| run.contains(&start)) {
        return source[start..run.end]
            .char_indices()
            .skip(1)
            .map(|(offset, _)| start + offset)
            .chain(std::iter::once(run.end))
            .filter(|&end| count(&source[start..end]) <= MAX_LIMIT)
            .max();
    }

    let run_start = whitespace
        .iter()
        .find(|run| run.start == start)
        .map_or(start, |run| run.end);
    let run = protected.iter().find(|run| run.start == run_start)?;
    if count(&source[start..run.end]) <= MAX_LIMIT {
        return None;
    }
    *waived = Some(run.clone());

    source[run.start..run.end]
        .char_indices()
        .skip(1)
        .map(|(offset, _)| run.start + offset)
        .chain(std::iter::once(run.end))
        .filter(|&end| count(&source[start..end]) <= MAX_LIMIT)
        .max()
}

fn allowed_fallback_end(
    end: usize,
    protected: &[Range<usize>],
    whitespace: &[Range<usize>],
) -> bool {
    !protected.iter().any(|run| run.start < end && end < run.end)
        && !whitespace
            .iter()
            .any(|run| run.start < end && end <= run.end)
}

fn natural_candidates(source: &str, protected: &[Range<usize>]) -> Vec<Candidate> {
    let chars: Vec<(usize, char)> = source.char_indices().collect();
    let mut candidates = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let (offset, character) = chars[index];
        let mut end = offset + character.len_utf8();
        let rank = if matches!(character, '.' | '?' | '!') {
            Some(1)
        } else if matches!(character, ',' | ';' | ':') {
            Some(2)
        } else {
            None
        };
        if let Some(rank) = rank {
            let mut closer = index + 1;
            while closer < chars.len() && is_closer(chars[closer].1) {
                end = chars[closer].0 + chars[closer].1.len_utf8();
                closer += 1;
            }
            push_candidate(&mut candidates, end, rank, protected);
        }
        if character.is_whitespace() {
            let preceding = index.checked_sub(1).map(|i| chars[i].1);
            if !preceding.is_some_and(|c| is_ranked_punctuation(c) || is_closer(c)) {
                push_candidate(&mut candidates, offset, 3, protected);
            }
            while index + 1 < chars.len() && chars[index + 1].1.is_whitespace() {
                index += 1;
            }
        }
        index += 1;
    }
    push_candidate(&mut candidates, source.len(), 1, protected);
    candidates
}

fn push_candidate(
    candidates: &mut Vec<Candidate>,
    end: usize,
    rank: u8,
    protected: &[Range<usize>],
) {
    if !protected.iter().any(|run| run.start < end && end < run.end) {
        if let Some(candidate) = candidates.iter_mut().find(|candidate| candidate.end == end) {
            candidate.rank = candidate.rank.min(rank);
        } else {
            candidates.push(Candidate { end, rank });
        }
    }
}

fn is_ranked_punctuation(character: char) -> bool {
    matches!(character, '.' | '?' | '!' | ',' | ';' | ':')
}

fn is_closer(character: char) -> bool {
    matches!(
        character,
        '\'' | '"'
            | '\u{2019}'
            | '\u{201d}'
            | ')'
            | ']'
            | '}'
            | '\u{00bb}'
            | '\u{203a}'
            | '\u{3009}'
            | '\u{300b}'
            | '\u{300d}'
            | '\u{300f}'
            | '\u{3011}'
            | '\u{3015}'
            | '\u{ff09}'
            | '\u{ff3d}'
            | '\u{ff5d}'
    )
}

fn whitespace_runs(source: &str) -> Vec<Range<usize>> {
    let mut runs = Vec::new();
    let mut start = None;
    for (offset, character) in source.char_indices() {
        if character.is_whitespace() {
            start.get_or_insert(offset);
        } else if let Some(run_start) = start.take() {
            runs.push(run_start..offset);
        }
    }
    if let Some(run_start) = start {
        runs.push(run_start..source.len());
    }
    runs
}

fn protected_runs(source: &str) -> Vec<Range<usize>> {
    let mut runs = Vec::new();
    let mut offset = 0;
    while offset < source.len() {
        let rest = &source[offset..];
        let length = url_length(rest)
            .or_else(|| numeric_length(rest))
            .or_else(|| dotted_initialism_length(rest))
            .or_else(|| title_length(rest));
        if let Some(length) = length {
            runs.push(offset..offset + length);
            offset += length;
        } else {
            offset += rest.chars().next().expect("offset is in source").len_utf8();
        }
    }
    runs
}

fn url_length(source: &str) -> Option<usize> {
    ["http://", "https://", "www."]
        .iter()
        .any(|prefix| source.starts_with(prefix))
        .then(|| {
            source
                .char_indices()
                .find(|(_, character)| character.is_whitespace())
                .map_or(source.len(), |(offset, _)| offset)
        })
}

fn numeric_length(source: &str) -> Option<usize> {
    let mut chars = source.char_indices().peekable();
    if chars.peek().is_some_and(|(_, c)| matches!(c, '+' | '-')) {
        chars.next();
    }
    if !chars.next().is_some_and(|(_, c)| c.is_ascii_digit()) {
        return None;
    }
    let mut end = chars.peek().map_or(source.len(), |(offset, _)| *offset);
    while let Some((offset, character)) = chars.peek().copied() {
        if character.is_ascii_digit() || matches!(character, ',' | '.' | ':' | '/' | '-') {
            chars.next();
            end = chars.peek().map_or(source.len(), |(next, _)| *next);
        } else if character == '%' {
            chars.next();
            end = offset + 1;
            break;
        } else {
            break;
        }
    }
    Some(end)
}

fn dotted_initialism_length(source: &str) -> Option<usize> {
    let bytes = source.as_bytes();
    let mut end = 0;
    while end + 1 < bytes.len() && bytes[end].is_ascii_alphabetic() && bytes[end + 1] == b'.' {
        end += 2;
    }
    (end >= 4).then_some(end)
}

fn title_length(source: &str) -> Option<usize> {
    ["Mrs.", "Dr.", "Mr.", "Ms."]
        .iter()
        .find(|title| source.starts_with(**title))
        .map(|title| title.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lengths(source: &str) -> usize {
        source.chars().count()
    }

    fn assert_partition(source: &str, ranges: &[Range<usize>], count: impl Fn(&str) -> usize) {
        let mut next = 0;
        for range in ranges {
            assert_eq!(range.start, next);
            assert!(range.start < range.end);
            assert!(source.is_char_boundary(range.start));
            assert!(source.is_char_boundary(range.end));
            assert!(count(&source[range.clone()]) <= MAX_LIMIT);
            next = range.end;
        }
        assert_eq!(next, source.len());
    }

    #[test]
    fn punctuation_boundary_keeps_whitespace_on_the_right() {
        let source = format!("{}.  \n{}!", "a".repeat(100), "b".repeat(100));
        let ranges = pack_initial_ranges(&source, |slice| {
            if slice.len() == 101 || slice.len() == 104 {
                190
            } else {
                201
            }
        })
        .unwrap();
        assert_eq!(ranges, vec![0..101, 101..205]);
    }

    #[test]
    fn retries_at_400_before_hard_splitting_an_ordinary_word() {
        let source = "w".repeat(250);
        assert_eq!(pack_initial_ranges(&source, lengths).unwrap(), vec![0..250]);
    }

    #[test]
    fn hard_splits_long_ordinary_word_at_200() {
        let source = format!("{} {}", "w".repeat(450), "x".repeat(151));
        assert_eq!(
            pack_initial_ranges(&source, lengths).unwrap(),
            vec![0..200, 200..450, 450..602]
        );
    }

    #[test]
    fn oversized_protected_url_may_split_at_400() {
        let source = format!("https://{}", "u".repeat(442));
        assert_eq!(
            pack_initial_ranges(&source, lengths).unwrap(),
            vec![0..400, 400..450]
        );
    }

    #[test]
    fn oversized_protected_url_may_split_into_three_ranges() {
        let source = format!("https://{}", "u".repeat(892));
        let ranges = pack_initial_ranges(&source, lengths).unwrap();
        assert_eq!(ranges, vec![0..400, 400..800, 800..900]);
        assert_partition(&source, &ranges, lengths);
    }

    #[test]
    fn numeric_run_cannot_split() {
        let source = "2026-07-22 update";
        let count = |slice: &str| {
            if slice == "2026-07-22" {
                200
            } else if slice.starts_with("2026-07-22") {
                401
            } else {
                slice.chars().count()
            }
        };
        let ranges = pack_initial_ranges(source, count).unwrap();
        assert_eq!(ranges[0], 0..10);
        assert_partition(source, &ranges, count);
    }

    #[test]
    fn exact_token_boundaries_and_scalar_safety() {
        assert_eq!(
            pack_initial_ranges("phoneme-empty", |_| 0),
            Err(PackingError::NoContent)
        );
        for tokens in [1, 19, 20, 200, 400, 401] {
            let source = "é".repeat(tokens);
            let ranges = pack_initial_ranges(&source, lengths).unwrap();
            assert_partition(&source, &ranges, lengths);
            if tokens <= 400 {
                assert_eq!(ranges, vec![0..source.len()]);
            } else {
                assert_eq!(ranges.len(), 2);
            }
        }
        assert_eq!(
            pack_initial_ranges("", lengths),
            Err(PackingError::NoContent)
        );
    }

    #[test]
    fn rejects_when_one_scalar_exceeds_400_tokens() {
        assert_eq!(
            pack_initial_ranges("x", |_| 401),
            Err(PackingError::UnsupportedInput)
        );
    }

    #[test]
    fn protection_is_leftmost_longest_and_covers_all_run_types() {
        let runs = protected_runs("www.a 12.3 U.S.A. Dr. X");
        assert_eq!(runs, vec![0..5, 6..10, 11..17, 18..21]);
    }

    #[test]
    fn leading_whitespace_is_preserved_when_oversized_protection_is_waived() {
        let source = format!("  https://{}", "u".repeat(442));
        let ranges = pack_initial_ranges(&source, lengths).unwrap();
        assert_eq!(ranges, vec![0..400, 400..452]);
        assert_partition(&source, &ranges, lengths);
    }

    #[test]
    fn sentence_rank_includes_closers_and_beats_clause_and_word_candidates() {
        let source = "one, two.\u{201d}  three";
        let sentence_end = source.find("  ").unwrap();
        let ranges = pack_initial_ranges(
            source,
            |slice| {
                if slice.len() > sentence_end {
                    201
                } else {
                    1
                }
            },
        )
        .unwrap();
        assert_eq!(ranges[0], 0..sentence_end);
        assert_eq!(&source[ranges[1].clone()], "  three");
    }
}
