use muniment_core::assistant_text::Rule;
use muniment_core::memory_secret::{reject_memory_secret, MemorySecretRejection};

const PREFIX: &str = "# Note\n\n";

fn token(prefix: &str, body: char, length: usize) -> String {
    format!("{prefix}{}", body.to_string().repeat(length))
}

fn jwt(first: usize, second: usize, third: usize) -> String {
    format!(
        "{}.{}.{}",
        "A".repeat(first),
        "_".repeat(second),
        "-".repeat(third)
    )
}

fn private_key(body: &str) -> String {
    format!(
        "{}\n{body}{}",
        concat!("-----BEGIN ", "PRIVATE KEY-----"),
        concat!("-----END ", "PRIVATE KEY-----")
    )
}

fn record(secret: &str) -> String {
    format!("{PREFIX}{secret}\n")
}

#[test]
fn accepts_a_record_without_a_secret() {
    let content = "# Trip\n\nThe archive closes at four on Friday.\n";
    assert_eq!(reject_memory_secret(content), Ok(()));
}

#[test]
fn accepts_an_empty_record() {
    assert_eq!(reject_memory_secret(""), Ok(()));
}

#[test]
fn accepts_a_record_that_names_an_absolute_path() {
    let cases = [
        "# Home\n\nThe deed scan lives at /Users/ada/Documents/deed.pdf today.\n",
        "# Home\n\nThe deed scan lives at C:\\Users\\ada\\Documents\\deed.pdf today.\n",
        "/etc/muniment/config.toml\n",
    ];
    for content in cases {
        assert_eq!(reject_memory_secret(content), Ok(()), "{content:?}");
    }
}

#[test]
fn rejects_each_secret_rule_with_its_first_byte_range() {
    let cases = [
        (token("ghp_", 'a', 36), Rule::SecretProviderToken),
        (jwt(17, 17, 0), Rule::SecretJwt),
        (private_key("YQ==\n"), Rule::SecretPemPrivateKey),
        ("token=0123456789".to_owned(), Rule::SecretAssignment),
    ];
    for (secret, rule) in cases {
        let content = record(&secret);
        assert_eq!(
            reject_memory_secret(&content),
            Err(MemorySecretRejection::Matched {
                rule,
                range: PREFIX.len()..PREFIX.len() + secret.len(),
            }),
            "{rule:?}"
        );
    }
}

#[test]
fn rejects_the_first_secret_when_a_record_carries_two() {
    let first = token("ghp_", 'a', 36);
    let content = format!("{PREFIX}{first} then {}\n", jwt(17, 17, 0));
    let rejection = reject_memory_secret(&content).unwrap_err();
    assert_eq!(rejection.rule(), Some(Rule::SecretProviderToken));
    assert_eq!(rejection.range(), PREFIX.len()..PREFIX.len() + first.len());
}

#[test]
fn rejects_the_earlier_match_when_an_over_span_candidate_follows_it() {
    let first = token("ghp_", 'a', 36);
    let content = format!("{PREFIX}{first} {}\n", token("sk-", 'a', 510));
    assert_eq!(
        reject_memory_secret(&content),
        Err(MemorySecretRejection::Matched {
            rule: Rule::SecretProviderToken,
            range: PREFIX.len()..PREFIX.len() + first.len(),
        })
    );
}

#[test]
fn rejects_a_withheld_over_span_candidate() {
    let content = record(&token("sk-", 'a', 510));
    let rejection = reject_memory_secret(&content).unwrap_err();
    assert_eq!(
        rejection,
        MemorySecretRejection::Withheld {
            range: PREFIX.len()..content.len(),
        }
    );
    assert_eq!(rejection.rule(), None);
}

#[test]
fn a_rejection_message_repeats_no_matched_text() {
    let secret = token("ghp_", 'a', 36);
    let content = record(&secret);
    let message = reject_memory_secret(&content).unwrap_err().to_string();
    assert!(!message.contains(&secret), "{message}");
    assert!(!message.contains("ghp_"), "{message}");
    assert!(message.contains("8..48"), "{message}");
}
