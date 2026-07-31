use muniment_core::assistant_text::{scan, Rule};

fn token(prefix: &str, body: char, length: usize) -> String {
    format!("{prefix}{}", body.to_string().repeat(length))
}

#[test]
fn matches_each_provider_alternative() {
    let cases = [
        ("ghp_", 'a', 36),
        ("gho_", 'a', 36),
        ("ghu_", 'a', 36),
        ("ghs_", 'a', 36),
        ("ghr_", 'a', 36),
        ("github_pat_", '_', 82),
        ("sk-", '_', 20),
        ("sk-ant-", '-', 20),
        ("xoxb-", '-', 10),
        ("xoxa-", '-', 10),
        ("xoxp-", '-', 10),
        ("xoxr-", '-', 10),
        ("xoxs-", '-', 10),
        ("sk_live_", 'a', 16),
        ("rk_live_", 'a', 16),
        ("hf_", 'a', 20),
        ("AKIA", 'A', 16),
        ("ASIA", '0', 16),
    ];
    for (prefix, body, length) in cases {
        let value = token(prefix, body, length);
        let result = scan(&value, true);
        assert_eq!(result.matches.len(), 1, "{prefix}");
        assert_eq!(result.matches[0].range, 0..value.len(), "{prefix}");
        assert_eq!(result.matches[0].rule, Rule::SecretProviderToken);
    }
}

#[test]
fn rejects_near_misses() {
    assert!(scan(&token("sk-", 'a', 19), true).matches.is_empty());
    assert!(scan(&format!("x{}", token("hf_", 'a', 20)), true)
        .matches
        .is_empty());
    assert!(scan("github_pat_aaaaaaaaaa!aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true).matches.is_empty());
}

#[test]
fn accepts_each_length_ceiling_with_a_boundary_byte() {
    let cases = [
        ("ghp_", 'a', 508),
        ("github_pat_", '_', 501),
        ("sk-", '_', 509),
        ("sk-ant-", '-', 505),
        ("xoxb-", '-', 504),
        ("sk_live_", 'a', 504),
        ("hf_", 'a', 509),
        ("AKIA", 'A', 16),
    ];
    for (prefix, body, length) in cases {
        let value = format!("{}!", token(prefix, body, length));
        assert_eq!(
            scan(&value, true).matches[0].range,
            0..value.len() - 1,
            "{prefix}"
        );
    }
}

#[test]
fn overlapping_openai_and_anthropic_alternatives_make_one_match() {
    let value = token("sk-ant-", 'a', 20);
    let result = scan(&value, true);
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].range, 0..value.len());
}

#[test]
fn reports_complete_and_incomplete_retention() {
    let content = format!("{}é", "x".repeat(600));
    let incomplete = scan(&content, false);
    assert!(content.is_char_boundary(incomplete.retention_offset));
    assert!(content.len() - incomplete.retention_offset <= 512);
    assert_eq!(scan(&content, true).retention_offset, content.len());
}

#[test]
fn withholds_an_over_span_candidate() {
    let content = format!("before {} after", token("sk-", 'a', 510));
    let result = scan(&content, true);
    assert_eq!(result.withhold_from, Some(7));
    assert!(result.matches.is_empty());
}

#[test]
fn returns_ordered_non_overlapping_ranges() {
    let first = token("hf_", 'a', 20);
    let second = token("AKIA", 'A', 16);
    let content = format!("{first} {second}");
    let result = scan(&content, true);
    assert_eq!(result.matches[0].range, 0..first.len());
    assert_eq!(result.matches[1].range, first.len() + 1..content.len());
}
