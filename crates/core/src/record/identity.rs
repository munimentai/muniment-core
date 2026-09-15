//! The six identity kinds and their normalization. Every value is normalized
//! before it reaches the identity table, so one human never exists twice.

use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityKind {
    Email,
    Domain,
    Phone,
    Handle,
    External,
    NameKey,
}

impl IdentityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Email => "email",
            Self::Domain => "domain",
            Self::Phone => "phone",
            Self::Handle => "handle",
            Self::External => "external",
            Self::NameKey => "name_key",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "email" => Some(Self::Email),
            "domain" => Some(Self::Domain),
            "phone" => Some(Self::Phone),
            "handle" => Some(Self::Handle),
            "external" => Some(Self::External),
            "name_key" => Some(Self::NameKey),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    UnknownKind(String),
    Empty(IdentityKind),
    Malformed(IdentityKind, String),
    FreeMailDomain(String),
    PhoneNeedsCountry(String),
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownKind(kind) => write!(formatter, "identity kind {kind} is unknown"),
            Self::Empty(kind) => write!(formatter, "{} identity is empty", kind.as_str()),
            Self::Malformed(kind, value) => {
                write!(formatter, "{value} is not a {} identity", kind.as_str())
            }
            Self::FreeMailDomain(domain) => write!(
                formatter,
                "{domain} names a person's mail provider, not a company"
            ),
            Self::PhoneNeedsCountry(value) => {
                write!(formatter, "{value} needs a country code")
            }
        }
    }
}

impl std::error::Error for IdentityError {}

/// Providers that ignore dots in the local part.
const DOT_BLIND_PROVIDERS: &[&str] = &["gmail.com", "googlemail.com"];

/// Domains that identify a person and never a company.
const FREE_MAIL_DOMAINS: &[&str] = &[
    "gmail.com",
    "googlemail.com",
    "yahoo.com",
    "ymail.com",
    "hotmail.com",
    "outlook.com",
    "live.com",
    "msn.com",
    "icloud.com",
    "me.com",
    "mac.com",
    "aol.com",
    "proton.me",
    "protonmail.com",
    "pm.me",
    "gmx.com",
    "gmx.de",
    "mail.com",
    "zoho.com",
    "fastmail.com",
    "hey.com",
];

/// Two-label public suffixes, so a registrable domain keeps three labels.
const TWO_LABEL_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk", "com.au", "net.au",
    "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "net.nz", "co.jp", "or.jp", "ne.jp", "ac.jp",
    "co.kr", "or.kr", "com.br", "net.br", "org.br", "com.mx", "org.mx", "co.za", "org.za",
    "com.sg", "com.hk", "com.tw", "co.in", "net.in", "org.in", "com.cn", "net.cn", "org.cn",
    "com.ar", "com.tr", "co.il", "com.pl", "com.ua", "com.ru",
];

/// Suffixes a name key drops, so "Northwind Traders Inc." and "Northwind
/// Traders" block together.
const LEGAL_SUFFIXES: &[&str] = &[
    "inc",
    "incorporated",
    "llc",
    "llp",
    "lp",
    "ltd",
    "limited",
    "corp",
    "corporation",
    "co",
    "company",
    "gmbh",
    "ag",
    "plc",
    "sa",
    "sas",
    "srl",
    "bv",
    "nv",
    "pty",
    "pte",
    "oy",
    "ab",
    "as",
    "kk",
];

/// Normalizes one identity value for its kind.
pub fn normalize_identity(kind: IdentityKind, value: &str) -> Result<String, IdentityError> {
    let value = value.trim();
    if value.is_empty() {
        return Err(IdentityError::Empty(kind));
    }
    match kind {
        IdentityKind::Email => normalize_email(value),
        IdentityKind::Domain => normalize_domain(value),
        IdentityKind::Phone => normalize_phone(value),
        IdentityKind::Handle => normalize_handle(value),
        IdentityKind::External => normalize_external(value),
        IdentityKind::NameKey => {
            let key = name_key(value);
            if key.is_empty() {
                Err(IdentityError::Malformed(kind, value.to_owned()))
            } else {
                Ok(key)
            }
        }
    }
}

fn normalize_email(value: &str) -> Result<String, IdentityError> {
    let malformed = || IdentityError::Malformed(IdentityKind::Email, value.to_owned());
    let lower = value.to_ascii_lowercase();
    let (local, domain) = lower.split_once('@').ok_or_else(malformed)?;
    if local.is_empty()
        || domain.is_empty()
        || domain.contains('@')
        || !domain.contains('.')
        || lower.chars().any(char::is_whitespace)
    {
        return Err(malformed());
    }
    let mut local = local.split('+').next().unwrap_or_default().to_owned();
    if local.is_empty() {
        return Err(malformed());
    }
    if DOT_BLIND_PROVIDERS.contains(&domain) {
        local.retain(|character| character != '.');
    }
    Ok(format!("{local}@{domain}"))
}

/// Lowercases, strips a scheme, a path, a port and a leading `www.`, then
/// keeps the registrable labels. A public suffix list would be exact; this
/// table covers the common two-label suffixes.
fn normalize_domain(value: &str) -> Result<String, IdentityError> {
    let malformed = || IdentityError::Malformed(IdentityKind::Domain, value.to_owned());
    let mut host = value.to_ascii_lowercase();
    if let Some((_, rest)) = host.split_once("://") {
        host = rest.to_owned();
    }
    let host = host
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default()
        .split(':')
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_owned();
    let host = host.strip_prefix("www.").unwrap_or(&host).to_owned();
    if host.is_empty()
        || !host.contains('.')
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
        || host.split('.').any(|label| label.is_empty())
    {
        return Err(malformed());
    }
    let labels: Vec<&str> = host.split('.').collect();
    let keep = if labels.len() >= 3
        && TWO_LABEL_SUFFIXES.contains(&labels[labels.len() - 2..].join(".").as_str())
    {
        3
    } else {
        2
    };
    let registrable = labels[labels.len().saturating_sub(keep)..].join(".");
    if FREE_MAIL_DOMAINS.contains(&registrable.as_str()) {
        return Err(IdentityError::FreeMailDomain(registrable));
    }
    Ok(registrable)
}

/// E.164 with the United States as the default region: ten digits gain `+1`,
/// and anything else without a leading `+` needs its country code.
fn normalize_phone(value: &str) -> Result<String, IdentityError> {
    let has_plus = value.starts_with('+');
    let digits: String = value.chars().filter(char::is_ascii_digit).collect();
    let digits = if has_plus {
        digits
    } else if digits.len() == 10 {
        format!("1{digits}")
    } else if digits.len() == 11 && digits.starts_with('1') {
        digits
    } else {
        return Err(IdentityError::PhoneNeedsCountry(value.to_owned()));
    };
    if digits.len() < 8 || digits.len() > 15 || digits.starts_with('0') {
        return Err(IdentityError::Malformed(
            IdentityKind::Phone,
            value.to_owned(),
        ));
    }
    Ok(format!("+{digits}"))
}

/// `platform:id`, the stable id and never the display name.
fn normalize_handle(value: &str) -> Result<String, IdentityError> {
    let malformed = || IdentityError::Malformed(IdentityKind::Handle, value.to_owned());
    let (platform, id) = value.split_once(':').ok_or_else(malformed)?;
    let platform = platform.trim().to_ascii_lowercase();
    let id = id.trim();
    if platform.is_empty()
        || id.is_empty()
        || !platform
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        || id.chars().any(char::is_whitespace)
    {
        return Err(malformed());
    }
    Ok(format!("{platform}:{id}"))
}

/// `system:object:record_id`, the idempotency key for every import.
fn normalize_external(value: &str) -> Result<String, IdentityError> {
    let malformed = || IdentityError::Malformed(IdentityKind::External, value.to_owned());
    let mut parts = value.splitn(3, ':');
    let system = parts.next().unwrap_or_default().trim().to_ascii_lowercase();
    let object = parts.next().unwrap_or_default().trim();
    let record = parts.next().unwrap_or_default().trim();
    if system.is_empty()
        || object.is_empty()
        || record.is_empty()
        || system.chars().any(char::is_whitespace)
        || object.chars().any(char::is_whitespace)
    {
        return Err(malformed());
    }
    Ok(format!("{system}:{object}:{record}"))
}

/// Case-folded, punctuation stripped, legal suffixes removed. A blocking key
/// for resolution and never a unique identifier.
pub fn name_key(value: &str) -> String {
    let folded: String = value
        .to_lowercase()
        .chars()
        .map(|character| {
            if character.is_alphanumeric() {
                character
            } else {
                ' '
            }
        })
        .collect();
    let mut words: Vec<&str> = folded.split_whitespace().collect();
    while words.len() > 1 && LEGAL_SUFFIXES.contains(words.last().copied().as_ref().unwrap()) {
        words.pop();
    }
    words.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emails_fold_case_plus_tags_and_provider_dots() {
        assert_eq!(
            normalize_identity(
                IdentityKind::Email,
                " Elena.Vasquez+news@Northwind.Example "
            )
            .unwrap(),
            "elena.vasquez@northwind.example"
        );
        assert_eq!(
            normalize_identity(IdentityKind::Email, "e.le.na@gmail.com").unwrap(),
            "elena@gmail.com"
        );
        assert!(normalize_identity(IdentityKind::Email, "no-at-sign").is_err());
        assert!(normalize_identity(IdentityKind::Email, "+tag@x.example").is_err());
    }

    #[test]
    fn domains_keep_the_registrable_labels_and_refuse_free_mail() {
        assert_eq!(
            normalize_identity(
                IdentityKind::Domain,
                "https://www.Northwind.Example/path?q=1"
            )
            .unwrap(),
            "northwind.example"
        );
        assert_eq!(
            normalize_identity(IdentityKind::Domain, "mail.northwind.co.uk").unwrap(),
            "northwind.co.uk"
        );
        assert_eq!(
            normalize_identity(IdentityKind::Domain, "app.eu.northwind.io:8443").unwrap(),
            "northwind.io"
        );
        assert_eq!(
            normalize_identity(IdentityKind::Domain, "gmail.com"),
            Err(IdentityError::FreeMailDomain("gmail.com".into()))
        );
        assert!(normalize_identity(IdentityKind::Domain, "localhost").is_err());
    }

    #[test]
    fn phones_become_e164_with_the_default_region() {
        assert_eq!(
            normalize_identity(IdentityKind::Phone, "(415) 555-0142").unwrap(),
            "+14155550142"
        );
        assert_eq!(
            normalize_identity(IdentityKind::Phone, "+44 20 7946 0958").unwrap(),
            "+442079460958"
        );
        assert_eq!(
            normalize_identity(IdentityKind::Phone, "7946 0958"),
            Err(IdentityError::PhoneNeedsCountry("7946 0958".into()))
        );
        assert!(normalize_identity(IdentityKind::Phone, "+0 123 4567").is_err());
    }

    #[test]
    fn handles_and_external_ids_keep_their_namespaces() {
        assert_eq!(
            normalize_identity(IdentityKind::Handle, "Slack:U04K7Q2NM").unwrap(),
            "slack:U04K7Q2NM"
        );
        assert!(normalize_identity(IdentityKind::Handle, "U04K7Q2NM").is_err());
        assert_eq!(
            normalize_identity(IdentityKind::External, "Salesforce:Contact:0035g00000Xy").unwrap(),
            "salesforce:Contact:0035g00000Xy"
        );
        assert!(normalize_identity(IdentityKind::External, "salesforce:Contact").is_err());
    }

    #[test]
    fn name_keys_block_on_the_bare_name() {
        assert_eq!(name_key("Northwind Traders, Inc."), "northwind traders");
        assert_eq!(name_key("NORTHWIND TRADERS"), "northwind traders");
        assert_eq!(name_key("Acme Co Ltd"), "acme");
        assert_eq!(name_key("Inc"), "inc");
        assert_eq!(
            normalize_identity(IdentityKind::NameKey, "---"),
            Err(IdentityError::Malformed(
                IdentityKind::NameKey,
                "---".into()
            ))
        );
    }
}
