//! The reader contract. Every source implements Objects, Describe, Page and
//! Delta, and nothing else about it reaches the graph. A file reader runs in
//! Rust inside the runtime. The runtime holds each cursor and does every
//! write, so a reader never touches SQLite.

use crate::host::RuntimeHost;
use muniment_core::serde::{Deserialize, Serialize};
use muniment_core::serde_json::{self, Value};
use std::collections::BTreeMap;
use std::fmt;

/// One record of a source object: the column or field name to its text.
pub type Row = BTreeMap<String, String>;

/// One thing a source holds that a mapping can read: a file, a Stripe
/// customer list, a mailbox label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "muniment_core::serde")]
pub struct ObjectInfo {
    pub name: String,
    pub label: String,
}

/// One field of an object: its name, the type the samples suggest, and a few
/// distinct sample values, so a person maps it without opening the source.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "muniment_core::serde")]
pub struct FieldDescription {
    pub name: String,
    pub guess: String,
    pub samples: Vec<String>,
    pub filled: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "muniment_core::serde")]
pub struct Description {
    pub source: String,
    pub object: String,
    pub label: String,
    pub fields: Vec<FieldDescription>,
    pub rows: usize,
    pub bytes: u64,
    pub hash: String,
    /// Whether `rows` is the whole object. A source that counts nothing
    /// answers the rows it read so far.
    #[serde(default = "counted_default")]
    pub counted: bool,
}

/// Where a run stands in an object. The runtime stores it in the mapping.
/// `offset` counts rows landed, `hash` is the object's change mark, and
/// `token` is the source's own page token when it has one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "muniment_core::serde")]
pub struct Cursor {
    pub offset: usize,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

fn counted_default() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "muniment_core::serde")]
pub struct Page {
    pub rows: Vec<Row>,
    pub offset: usize,
    pub total: usize,
    pub hash: String,
    pub next: Option<Cursor>,
    #[serde(default = "counted_default")]
    pub counted: bool,
}

/// What changed in an object since a cursor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    crate = "muniment_core::serde",
    tag = "state",
    rename_all = "snake_case"
)]
pub enum Delta {
    Unchanged,
    Changed { hash: String },
    Gone,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReaderError {
    UnknownSource(String),
    UnknownObject(String),
    Unreadable(String),
    TooLarge {
        bytes: u64,
        cap: u64,
    },
    Malformed(String),
    /// A failure the source or its sidecar named, with its own code.
    Source {
        code: String,
        message: String,
    },
}

impl fmt::Display for ReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSource(source) => write!(formatter, "No reader reads {source}."),
            Self::UnknownObject(object) => write!(formatter, "{object} is not there to read."),
            Self::Unreadable(reason) => write!(formatter, "The file could not be read: {reason}."),
            Self::TooLarge { bytes, cap } => write!(
                formatter,
                "The file holds {bytes} bytes and the reader stops at {cap}."
            ),
            Self::Malformed(reason) => write!(formatter, "The file does not parse: {reason}."),
            Self::Source { message, .. } => formatter.write_str(message),
        }
    }
}

impl std::error::Error for ReaderError {}

impl ReaderError {
    /// The code the panel and the agent read beside the message.
    pub fn code(&self) -> &str {
        match self {
            Self::UnknownSource(_) => "unknown_source",
            Self::UnknownObject(_) => "unknown_object",
            Self::Unreadable(_) => "unreadable",
            Self::TooLarge { .. } => "too_large",
            Self::Malformed(_) => "malformed",
            Self::Source { code, .. } => code,
        }
    }
}

pub trait Reader {
    /// Every object the source holds.
    fn objects(&self) -> Result<Vec<ObjectInfo>, ReaderError>;
    /// One object's fields, samples and size.
    fn describe(&self, object: &str) -> Result<Description, ReaderError>;
    /// One page of rows from the cursor, or from the start.
    fn page(
        &self,
        object: &str,
        cursor: Option<&Cursor>,
        limit: usize,
    ) -> Result<Page, ReaderError>;
    /// Whether the object changed since the cursor was written.
    fn delta(&self, object: &str, cursor: &Cursor) -> Result<Delta, ReaderError>;
}

/// The one source name a file reader answers to.
pub const CSV_SOURCE: &str = "csv";
/// The network sources the Go sidecar reads, each behind its own secret.
pub const SIDECAR_SOURCES: [&str; 28] = [
    "stripe",
    "hubspot",
    "pipedrive",
    "salesforce",
    "zendesk",
    "intercom",
    "freshdesk",
    "zoho",
    "outreach",
    "salesloft",
    "notion",
    "airtable",
    "sheets",
    "square",
    "shopify",
    "paypal",
    "freshbooks",
    "quickbooks",
    "wave",
    "apollo",
    "gong",
    "zoominfo",
    "calendly",
    "mailchimp",
    "kit",
    "xero",
    "dynamics",
    "marketo",
];

/// Opens the reader for a source. `object` is the file path for a file
/// reader and the object name for a network source, whose secret comes from
/// the host's credential store.
pub fn open_reader(
    host: &RuntimeHost,
    source: &str,
    object: &str,
) -> Result<Box<dyn Reader>, ReaderError> {
    if source == CSV_SOURCE {
        return Ok(Box::new(crate::reader_csv::CsvReader::new(object)));
    }
    if !SIDECAR_SOURCES.contains(&source) {
        return Err(ReaderError::UnknownSource(source.to_owned()));
    }
    let secret =
        crate::reader_secret::read(host.credentials.as_ref(), source).ok_or_else(|| {
            ReaderError::Source {
                code: "not_connected".to_owned(),
                message: format!(
                    "Connect {} with its {} first.",
                    source_label(source),
                    secret_label(source)
                ),
            }
        })?;
    open_sidecar(host, source, secret)
}

/// Opens a sidecar reader on a secret the caller holds, before it is stored.
pub fn open_sidecar(
    host: &RuntimeHost,
    source: &str,
    secret: String,
) -> Result<Box<dyn Reader>, ReaderError> {
    let executable = crate::reader_sidecar::sidecar_executable(host.reader_executable.as_deref())
        .ok_or_else(|| ReaderError::Source {
        code: "reader_missing".to_owned(),
        message: format!(
            "The {} reader is not installed beside the runtime.",
            source_label(source)
        ),
    })?;
    Ok(Box::new(crate::reader_sidecar::SidecarReader::new(
        source, executable, secret,
    )))
}

/// The name a source shows: `Stripe` for `stripe`, `HubSpot` for `hubspot`.
pub fn source_label(source: &str) -> String {
    match source {
        "hubspot" => return "HubSpot".to_owned(),
        "zoho" => return "Zoho CRM".to_owned(),
        "sheets" => return "Google Sheets".to_owned(),
        "paypal" => return "PayPal".to_owned(),
        "quickbooks" => return "QuickBooks".to_owned(),
        "freshbooks" => return "FreshBooks".to_owned(),
        "zoominfo" => return "ZoomInfo".to_owned(),
        "dynamics" => return "Dynamics 365".to_owned(),
        _ => {}
    }
    let mut chars = source.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// What a source calls its credential, as the panel's connect sentence
/// names it. A source with several credentials names the set.
pub fn secret_label(source: &str) -> &'static str {
    match source {
        "hubspot" => "private app access token",
        "pipedrive" | "zendesk" => "API token",
        "salesforce" => "connected app",
        "intercom" | "square" => "access token",
        "freshdesk" | "salesloft" | "apollo" | "mailchimp" | "kit" => "API key",
        "gong" => "access key",
        "zoominfo" => "username and password",
        "zoho" => "self client",
        "outreach" | "paypal" | "freshbooks" | "quickbooks" | "xero" => "app credentials",
        "dynamics" => "app registration",
        "marketo" => "custom service credentials",
        "notion" => "internal integration token",
        "airtable" | "calendly" => "personal access token",
        "sheets" => "service account key",
        "shopify" => "Admin API access token",
        "wave" => "full access token",
        _ => "secret key",
    }
}

/// The type a column's non-empty samples suggest, as the kind schema names
/// types: `string`, `number`, `integer`, `boolean`, `date`, `date-time`, and
/// three hints for identity columns, `email`, `domain` and `phone`.
pub fn guess_type<'a>(values: impl Iterator<Item = &'a str>) -> String {
    let mut seen = 0_usize;
    let mut integer = true;
    let mut number = true;
    let mut boolean = true;
    let mut date = true;
    let mut date_time = true;
    let mut email = true;
    let mut domain = true;
    let mut phone = true;
    for value in values {
        let value = value.trim();
        if value.is_empty() {
            continue;
        }
        seen += 1;
        let numeric = crate::reader_mapping::parse_number(value);
        integer &= numeric.is_some_and(|number| number.fract() == 0.0);
        number &= numeric.is_some();
        boolean &= crate::reader_mapping::parse_boolean(value).is_some();
        date &= crate::reader_mapping::parse_date(value).is_some() && !value.contains(':');
        date_time &= crate::reader_mapping::parse_date_time(value).is_some() && value.contains(':');
        email &= looks_like_email(value);
        domain &= looks_like_domain(value);
        phone &= looks_like_phone(value);
    }
    if seen == 0 {
        return "string".to_owned();
    }
    let guess = if boolean {
        "boolean"
    } else if integer {
        "integer"
    } else if number {
        "number"
    } else if date {
        "date"
    } else if date_time {
        "date-time"
    } else if email {
        "email"
    } else if phone {
        "phone"
    } else if domain {
        "domain"
    } else {
        "string"
    };
    guess.to_owned()
}

fn looks_like_email(value: &str) -> bool {
    let Some((local, host)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && host.contains('.')
        && !host.contains('@')
        && !value.chars().any(char::is_whitespace)
}

fn looks_like_domain(value: &str) -> bool {
    let host = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    host.contains('.')
        && !host.contains('@')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'.')
}

fn looks_like_phone(value: &str) -> bool {
    let digits = value.chars().filter(char::is_ascii_digit).count();
    (8..=15).contains(&digits)
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | ' ' | '(' | ')' | '.'))
}

/// Serializes one value the way the mapping stores a cursor.
pub fn cursor_value(cursor: &Cursor, rows: usize, ran_at: &str, complete: bool) -> Value {
    let mut value = serde_json::json!({
        "offset": cursor.offset,
        "hash": cursor.hash,
        "rows": rows,
        "ran_at": ran_at,
        "complete": complete,
    });
    if let Some(token) = &cursor.token {
        value["token"] = Value::String(token.clone());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guesses_a_column_type_from_its_samples() {
        let guess = |values: &[&str]| guess_type(values.iter().copied());
        assert_eq!(guess(&["1", "2", "", "30"]), "integer");
        assert_eq!(guess(&["1.5", "$2,000.00", "-3"]), "number");
        assert_eq!(guess(&["yes", "no", "true"]), "boolean");
        assert_eq!(guess(&["2026-01-02", "03/04/2026"]), "date");
        assert_eq!(
            guess(&["2026-01-02T10:00:00Z", "2026-01-02 10:00:00"]),
            "date-time"
        );
        assert_eq!(guess(&["a@b.co", "c@d.org"]), "email");
        assert_eq!(guess(&["+1 555 010 0000", "(555) 010-0001"]), "phone");
        assert_eq!(
            guess(&["northwind.example", "https://contoso.example/x"]),
            "domain"
        );
        assert_eq!(guess(&["Northwind", "Contoso"]), "string");
        assert_eq!(guess(&["", " "]), "string");
        assert_eq!(guess(&["1", "one"]), "string");
    }

    #[test]
    fn opens_the_csv_reader_and_names_an_unknown_or_unconnected_source() {
        let host = RuntimeHost::default();
        assert!(open_reader(&host, "csv", "/tmp/x.csv").is_ok());
        let error = match open_reader(&host, "abacus", "customers") {
            Ok(_) => panic!("an unknown source opened"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "unknown_source");
        assert_eq!(error.to_string(), "No reader reads abacus.");
        std::env::set_var("MUNIMENT_READER_SECRET_STRIPE", "");
        let error = match open_reader(&host, "stripe", "customers") {
            Ok(_) => panic!("an unconnected source opened"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "not_connected");
        assert_eq!(
            error.to_string(),
            "Connect Stripe with its secret key first."
        );
        std::env::remove_var("MUNIMENT_READER_SECRET_STRIPE");
        assert_eq!(source_label("stripe"), "Stripe");
        assert_eq!(source_label("hubspot"), "HubSpot");
        assert_eq!(secret_label("hubspot"), "private app access token");
        assert_eq!(secret_label("stripe"), "secret key");
        assert_eq!(secret_label("pipedrive"), "API token");
        assert_eq!(source_label("pipedrive"), "Pipedrive");
        assert_eq!(secret_label("salesforce"), "connected app");
        assert!(SIDECAR_SOURCES.contains(&"freshdesk"));
        assert!(SIDECAR_SOURCES.contains(&"quickbooks"));
        assert_eq!(source_label("zoho"), "Zoho CRM");
        assert_eq!(source_label("sheets"), "Google Sheets");
        assert_eq!(secret_label("shopify"), "Admin API access token");
        assert_eq!(secret_label("square"), "access token");
    }
}
