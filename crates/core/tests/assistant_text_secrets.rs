use muniment_core::assistant_text::{scan, Rule};

fn token(prefix: &str, body: char, length: usize) -> String {
    format!("{prefix}{}", body.to_string().repeat(length))
}

fn private_key(body: &str) -> String {
    named_private_key("PRIVATE KEY", body)
}

fn named_private_key(header_name: &str, body: &str) -> String {
    format!("-----BEGIN {header_name}-----\n{body}-----END {header_name}-----")
}

fn named_crlf_private_key(header_name: &str, body: &str) -> String {
    format!("-----BEGIN {header_name}-----\r\n{body}-----END {header_name}-----")
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
    let content = format!("{}é", "x".repeat(65_536));
    let incomplete = scan(&content, false);
    assert!(incomplete.retention_offset > 0);
    assert!(content.is_char_boundary(incomplete.retention_offset));
    assert!(content.len() - incomplete.retention_offset <= 65_536);
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

#[test]
fn matches_an_lf_private_key_block_without_its_trailing_lf() {
    let block = private_key("YWJjZA==\n");
    let content = format!("{block}\n");
    let result = scan(&content, true);
    assert_eq!(result.matches.len(), 1);
    assert_eq!(result.matches[0].range, 0..block.len());
    assert_eq!(result.matches[0].rule, Rule::SecretPemPrivateKey);
}

#[test]
fn matches_each_private_key_header_name() {
    let header_names = [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "DSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ];
    for header_name in header_names {
        let block = named_private_key(header_name, "AKIAAAAAAAAAAAAAAAAA\n");
        let result = scan(&block, true);
        assert_eq!(result.matches.len(), 1, "{header_name}");
        assert_eq!(result.matches[0].range, 0..block.len(), "{header_name}");
        assert_eq!(result.matches[0].rule, Rule::SecretPemPrivateKey);
    }
}

#[test]
fn matches_each_private_key_header_name_with_crlf() {
    let header_names = [
        "PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "RSA PRIVATE KEY",
        "DSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ];
    for header_name in header_names {
        let block = named_crlf_private_key(header_name, "YQ==\r\n");
        let content = format!("{block}\r\n");
        let result = scan(&content, true);
        assert_eq!(result.matches.len(), 1, "{header_name}");
        assert_eq!(result.matches[0].range, 0..block.len(), "{header_name}");
        assert_eq!(result.matches[0].rule, Rule::SecretPemPrivateKey);
    }
}

#[test]
fn private_key_end_name_must_match_begin_name() {
    let content = format!(
        "{}\nYQ==\n{}",
        concat!("-----BEGIN EC ", "PRIVATE KEY-----"),
        concat!("-----END RSA ", "PRIVATE KEY-----")
    );
    assert!(scan(&content, true).matches.is_empty());
}

#[test]
fn private_key_requires_a_line_start_boundary() {
    let block = private_key("YQ==\n");
    let after_lf = format!("before\n{block}");
    assert_eq!(scan(&block, true).matches[0].range, 0..block.len());
    assert_eq!(
        scan(&after_lf, true).matches[0].range,
        "before\n".len()..after_lf.len()
    );
    assert!(scan(&format!("x{block}"), true).matches.is_empty());
}

#[test]
fn private_key_rejects_carriage_returns_without_line_feeds() {
    let cases = [
        format!(
            "{}\rYQ==\n{}",
            concat!("-----BEGIN ", "PRIVATE KEY-----"),
            concat!("-----END ", "PRIVATE KEY-----")
        ),
        private_key("YQ==\r"),
        format!(
            "{}\nYQ==\n{}\rX",
            concat!("-----BEGIN ", "PRIVATE KEY-----"),
            concat!("-----END ", "PRIVATE KEY-----")
        ),
    ];
    for content in cases {
        assert!(scan(&content, true).matches.is_empty(), "{content:?}");
    }
}

#[test]
fn incomplete_private_key_returns_no_match_or_withhold() {
    let content = format!("{}\nYQ==\n", concat!("-----BEGIN ", "PRIVATE KEY-----"));
    for complete in [true, false] {
        let result = scan(&content, complete);
        assert!(result.matches.is_empty());
        assert_eq!(result.withhold_from, None);
    }
}

#[test]
fn private_key_rejects_invalid_end_body_and_empty_body() {
    let cases = [
        format!(
            "{}\nYQ==\n{}",
            concat!("-----BEGIN ", "PRIVATE KEY-----"),
            concat!("-----END RSA ", "PRIVATE KEY-----")
        ),
        private_key("YQ?=\n"),
        private_key(""),
    ];
    for content in cases {
        assert!(scan(&content, true).matches.is_empty(), "{content:?}");
    }
}

#[test]
fn private_key_enforces_body_length_bounds() {
    for length in [1, 65_460] {
        let block = private_key(&"A".repeat(length));
        assert_eq!(scan(&block, true).matches[0].range, 0..block.len());
    }

    let over_limit = private_key(&"A".repeat(65_461));
    let result = scan(&over_limit, true);
    assert!(result.matches.is_empty());
    assert_eq!(result.withhold_from, None);
}
