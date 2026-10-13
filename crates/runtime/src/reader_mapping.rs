//! A mapping is a `mapping` record: which source object lands on which kind,
//! which column fills which property, which column is the identity that
//! keys every row, and which columns link the row to a record another object
//! landed. This module reads one row through a mapping into the data, the
//! identities and the links a propose takes. It touches no source and no
//! graph.

use crate::reader::{Cursor, Row};
use muniment_core::record::{EntityRow, IdentityInput, KindRow};
use muniment_core::serde_json::{self, Map, Value};
use std::collections::BTreeMap;

/// The mapping's identity column: `email:Email`, `domain:Website`,
/// `name_key:Company`, or `external:stripe:customer:Customer ID`, where the
/// system and object before the column become the external id's prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentitySpec {
    pub kind: String,
    pub prefix: Option<String>,
    pub column: String,
}

impl IdentitySpec {
    pub fn parse(text: &str) -> Result<Self, String> {
        let (kind, rest) = text
            .split_once(':')
            .ok_or_else(|| format!("identity {text} is not <kind>:<column>"))?;
        let kind = kind.trim().to_owned();
        let rest = rest.trim();
        if rest.is_empty() {
            return Err(format!("identity {text} names no column"));
        }
        if kind == "external" {
            let mut parts = rest.splitn(3, ':');
            let system = parts.next().unwrap_or_default().trim();
            let object = parts.next().unwrap_or_default().trim();
            let column = parts.next().unwrap_or_default().trim();
            if system.is_empty() || object.is_empty() || column.is_empty() {
                return Err(format!(
                    "identity {text} is not external:<system>:<object>:<column>"
                ));
            }
            return Ok(Self {
                kind,
                prefix: Some(format!("{system}:{object}")),
                column: column.to_owned(),
            });
        }
        if !matches!(
            kind.as_str(),
            "email" | "domain" | "phone" | "handle" | "name_key"
        ) {
            return Err(format!("identity kind {kind} is unknown"));
        }
        Ok(Self {
            kind,
            prefix: None,
            column: rest.to_owned(),
        })
    }

    pub fn text(&self) -> String {
        match &self.prefix {
            Some(prefix) => format!("{}:{prefix}:{}", self.kind, self.column),
            None => format!("{}:{}", self.kind, self.column),
        }
    }
}

/// The identity kinds a mapped column fills when the kind has no property of
/// that name: the column lands as an identity beside the key, so a person
/// keyed on a source id keeps the email the row carries.
pub const IDENTITY_PROPERTIES: [&str; 4] = ["email", "phone", "domain", "handle"];

/// One edge a row draws: the relation, and the identity spec whose column
/// holds the other end, `billed_to` through
/// `external:stripe:customers:customer` for a subscription's customer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EdgeSpec {
    pub relation: String,
    pub identity: IdentitySpec,
}

impl EdgeSpec {
    fn parse(value: &Value) -> Result<Self, String> {
        let relation = value
            .get("relation")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| "an edge names no relation".to_owned())?;
        let identity = value
            .get("identity")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| format!("the {relation} edge names no identity"))?;
        Ok(Self {
            relation: relation.to_owned(),
            identity: IdentitySpec::parse(identity)?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mapping {
    pub id: String,
    pub source: String,
    pub object: String,
    pub kind: String,
    /// Source column to kind property, in column order.
    pub fields: BTreeMap<String, String>,
    pub identity: Option<IdentitySpec>,
    pub edges: Vec<EdgeSpec>,
    pub approved: bool,
    pub cursor: Option<Cursor>,
}

impl Mapping {
    /// Reads a mapping record. A record that names no field is a mapping
    /// with nothing to do, and that is an error the run reports.
    pub fn from_entity(entity: &EntityRow) -> Result<Self, String> {
        if entity.kind != "mapping" {
            return Err(format!(
                "entity {} is a {}, not a mapping",
                entity.id, entity.kind
            ));
        }
        let data = entity.data.as_object().cloned().unwrap_or_default();
        let string = |key: &str| {
            data.get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|text| !text.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("the mapping has no {key}"))
        };
        let fields: BTreeMap<String, String> = data
            .get("fields")
            .and_then(Value::as_object)
            .map(|object| {
                object
                    .iter()
                    .filter_map(|(column, property)| {
                        property
                            .as_str()
                            .map(str::trim)
                            .filter(|property| !property.is_empty())
                            .map(|property| (column.clone(), property.to_owned()))
                    })
                    .collect()
            })
            .unwrap_or_default();
        if fields.is_empty() {
            return Err("the mapping fills no property".to_owned());
        }
        let identity = data
            .get("identity")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|text| !text.is_empty())
            .map(IdentitySpec::parse)
            .transpose()?;
        let edges = data
            .get("edges")
            .and_then(Value::as_array)
            .map(|edges| {
                edges
                    .iter()
                    .map(EdgeSpec::parse)
                    .collect::<Result<Vec<_>, _>>()
            })
            .transpose()?
            .unwrap_or_default();
        let cursor = data.get("cursors").and_then(|cursors| {
            let offset = cursors.get("offset")?.as_u64()? as usize;
            let hash = cursors.get("hash")?.as_str()?.to_owned();
            let token = cursors
                .get("token")
                .and_then(Value::as_str)
                .map(str::to_owned);
            Some(Cursor {
                offset,
                hash,
                token,
            })
        });
        Ok(Self {
            id: entity.id.clone(),
            source: string("source")?,
            object: string("object")?,
            kind: string("kind")?,
            fields,
            identity,
            edges,
            approved: data
                .get("approved")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            cursor,
        })
    }
}

/// One row read through the mapping: the data a propose takes, the identity
/// that keys it, the identities that ride beside the key, the links the row
/// draws, and a short title for the queue.
#[derive(Clone, Debug, PartialEq)]
pub struct RowPlan {
    pub data: Map<String, Value>,
    pub identity: Option<IdentityInput>,
    pub identities: Vec<IdentityInput>,
    pub links: Vec<RowLink>,
    pub title: String,
}

/// One link a row draws to a record another object landed, named by the
/// identity the other record carries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowLink {
    pub relation: String,
    pub target: IdentityInput,
}

/// Why one row cannot land, with the title the queue shows for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RowRefusal {
    pub title: String,
    pub reason: String,
}

/// The title the record would give a row: its kind's title template over the
/// mapped cells, else the row's email, else the cell that keys the row, else
/// the first mapped cell that holds words rather than a number or a switch.
fn row_title(kind: &KindRow, data: &Map<String, Value>, row: &Row, mapping: &Mapping) -> String {
    let rendered =
        muniment_core::record::render_template(&kind.title_template, &Value::Object(data.clone()));
    if !rendered.trim().is_empty() {
        return rendered.chars().take(80).collect();
    }
    let key = mapping
        .identity
        .as_ref()
        .and_then(|spec| row.get(&spec.column))
        .map(|cell| cell.trim())
        .filter(|cell| !cell.is_empty());
    email_cell(row)
        .or_else(|| key.map(str::to_owned))
        .or_else(|| {
            mapping
                .fields
                .keys()
                .filter_map(|column| row.get(column))
                .map(|cell| cell.trim())
                .find(|cell| {
                    !cell.is_empty()
                        && parse_number(cell).is_none()
                        && parse_boolean(cell).is_none()
                })
                .map(str::to_owned)
        })
        .unwrap_or_default()
        .chars()
        .take(80)
        .collect()
}

/// Reads one row into a plan, or the one reason it cannot land.
pub fn row_plan(mapping: &Mapping, kind: &KindRow, row: &Row) -> Result<RowPlan, RowRefusal> {
    let mut data = Map::new();
    let mut identities = Vec::new();
    let refuse = |data: &Map<String, Value>, reason: String| RowRefusal {
        title: row_title(kind, data, row, mapping),
        reason,
    };
    for (column, property) in &mapping.fields {
        let cell = row.get(column).map(|cell| cell.trim()).unwrap_or_default();
        if cell.is_empty() {
            continue;
        }
        let Some(schema) = property_schema(kind, property) else {
            // A kind without the property still keeps an email, a phone, a
            // domain or a handle: the column lands as an identity beside the key.
            if IDENTITY_PROPERTIES.contains(&property.as_str()) {
                let keyed = mapping
                    .identity
                    .as_ref()
                    .is_some_and(|spec| &spec.kind == property && &spec.column == column);
                if !keyed {
                    identities.push(IdentityInput {
                        kind: property.clone(),
                        value: cell.to_owned(),
                    });
                }
                continue;
            }
            return Err(refuse(
                &data,
                format!("{property} is not a property of {}", kind.name),
            ));
        };
        let value = match coerce(cell, &schema) {
            Ok(value) => value,
            Err(reason) => return Err(refuse(&data, format!("{column}: {reason}"))),
        };
        data.insert(property.clone(), value);
    }
    // A row with no name still lands under its email: the title property the
    // kind requires takes the email cell, so an email-only customer is a
    // record and not a refusal.
    if let Some(email) = email_cell(row) {
        for property in title_properties(kind) {
            if data.contains_key(&property) || !is_required(kind, &property) {
                continue;
            }
            let is_text = property_schema(kind, &property)
                .is_some_and(|schema| schema.get("type").and_then(Value::as_str) == Some("string"));
            if is_text {
                data.insert(property, Value::String(email.clone()));
            }
        }
    }
    if data.is_empty() {
        return Err(refuse(&data, "every mapped cell is empty".to_owned()));
    }
    let title = row_title(kind, &data, row, mapping);
    // An edge whose cell is empty draws nothing, and the row still lands.
    let links = mapping
        .edges
        .iter()
        .filter_map(|edge| {
            let cell = row.get(&edge.identity.column)?.trim();
            if cell.is_empty() {
                return None;
            }
            let value = match &edge.identity.prefix {
                Some(prefix) => format!("{prefix}:{cell}"),
                None => cell.to_owned(),
            };
            Some(RowLink {
                relation: edge.relation.clone(),
                target: IdentityInput {
                    kind: edge.identity.kind.clone(),
                    value,
                },
            })
        })
        .collect();
    let identity = match &mapping.identity {
        Some(spec) => {
            let cell = row
                .get(&spec.column)
                .map(|cell| cell.trim())
                .unwrap_or_default();
            if cell.is_empty() {
                return Err(refuse(
                    &data,
                    format!(
                        "the {} cell is empty, so the row has no identity",
                        spec.column
                    ),
                ));
            }
            let value = match &spec.prefix {
                Some(prefix) => format!("{prefix}:{cell}"),
                None => cell.to_owned(),
            };
            Some(IdentityInput {
                kind: spec.kind.clone(),
                value,
            })
        }
        None => Some(IdentityInput {
            kind: "name_key".to_owned(),
            value: title.clone(),
        }),
    };
    Ok(RowPlan {
        data,
        identity,
        identities,
        links,
        title,
    })
}

/// The row's email: the `email` column, else the first column that ends in
/// `email`, when the cell holds an address.
fn email_cell(row: &Row) -> Option<String> {
    row.get("email")
        .or_else(|| {
            row.iter()
                .find(|(column, _)| column.to_ascii_lowercase().ends_with("email"))
                .map(|(_, cell)| cell)
        })
        .map(|cell| cell.trim())
        .filter(|cell| cell.contains('@'))
        .map(str::to_owned)
}

/// The properties the kind's title template renders, in order.
fn title_properties(kind: &KindRow) -> Vec<String> {
    let mut properties = Vec::new();
    let mut rest = kind.title_template.as_str();
    while let Some(start) = rest.find('{') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('}') else { break };
        properties.push(after[..end].to_owned());
        rest = &after[end + 1..];
    }
    properties
}

fn is_required(kind: &KindRow, property: &str) -> bool {
    kind.schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|list| list.iter().any(|item| item.as_str() == Some(property)))
}

/// Whether a stored entity's data differs from the plan on any mapped key.
pub fn data_differs(current: &Value, data: &Map<String, Value>) -> bool {
    data.iter()
        .any(|(key, value)| current.get(key) != Some(value))
}

fn property_schema(kind: &KindRow, property: &str) -> Option<Value> {
    kind.schema
        .get("properties")
        .and_then(|properties| properties.get(property))
        .cloned()
        .or_else(|| {
            kind.extension
                .as_ref()
                .and_then(|extension| extension.get("properties"))
                .and_then(|properties| properties.get(property))
                .cloned()
        })
}

/// Reads one cell into the property's JSON value.
pub fn coerce(cell: &str, schema: &Value) -> Result<Value, String> {
    let expected = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string");
    match expected {
        "string" => {
            if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
                let wanted = fold(cell);
                return allowed
                    .iter()
                    .filter_map(Value::as_str)
                    .find(|candidate| fold(candidate) == wanted)
                    .map(|candidate| Value::String(candidate.to_owned()))
                    .ok_or_else(|| {
                        format!(
                            "{cell} is not one of {}",
                            allowed
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        )
                    });
            }
            match schema.get("format").and_then(Value::as_str) {
                Some("date") => parse_date(cell)
                    .map(Value::String)
                    .ok_or_else(|| format!("{cell} is not a date")),
                Some("date-time") => parse_date_time(cell)
                    .map(Value::String)
                    .ok_or_else(|| format!("{cell} is not a date and time")),
                _ => Ok(Value::String(cell.to_owned())),
            }
        }
        "number" => parse_number(cell)
            .map(Value::from)
            .ok_or_else(|| format!("{cell} is not a number")),
        "integer" => parse_number(cell)
            .filter(|number| number.fract() == 0.0 && number.abs() < 9.0e15)
            .map(|number| Value::from(number as i64))
            .ok_or_else(|| format!("{cell} is not a whole number")),
        "boolean" => parse_boolean(cell)
            .map(Value::Bool)
            .ok_or_else(|| format!("{cell} is not yes or no")),
        "array" => {
            let separator = if cell.contains(';') { ';' } else { ',' };
            Ok(Value::Array(
                cell.split(separator)
                    .map(str::trim)
                    .filter(|item| !item.is_empty())
                    .map(|item| Value::String(item.to_owned()))
                    .collect(),
            ))
        }
        "object" => serde_json::from_str::<Value>(cell)
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| format!("{cell} is not a JSON object")),
        _ => Ok(Value::String(cell.to_owned())),
    }
}

/// Lowercase with spaces, hyphens and underscores dropped, so `In Progress`,
/// `in-progress` and `in_progress` name one allowed value.
fn fold(text: &str) -> String {
    text.trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| !matches!(c, ' ' | '-' | '_'))
        .collect()
}

/// A number as a spreadsheet or a statement writes it: a currency mark, a
/// thousands separator, a percent sign, or parentheses for a negative.
pub fn parse_number(cell: &str) -> Option<f64> {
    let trimmed = cell.trim();
    let negative = trimmed.starts_with('(') && trimmed.ends_with(')');
    let cleaned: String = trimmed
        .chars()
        .filter(|c| {
            !matches!(
                c,
                '$' | '€' | '£' | '¥' | ',' | '%' | '(' | ')' | ' ' | '\u{a0}'
            )
        })
        .collect();
    if cleaned.is_empty() || cleaned.chars().any(char::is_alphabetic) {
        return None;
    }
    let number: f64 = cleaned.parse().ok()?;
    if !number.is_finite() {
        return None;
    }
    Some(if negative { -number } else { number })
}

pub fn parse_boolean(cell: &str) -> Option<bool> {
    match cell.trim().to_ascii_lowercase().as_str() {
        "yes" | "y" | "true" | "t" | "1" | "on" | "active" | "enabled" => Some(true),
        "no" | "n" | "false" | "f" | "0" | "off" | "inactive" | "disabled" => Some(false),
        _ => None,
    }
}

/// A date as `YYYY-MM-DD`, from that shape, `YYYY/MM/DD`, `MM/DD/YYYY`,
/// `DD.MM.YYYY`, or the date part of a date and time.
pub fn parse_date(cell: &str) -> Option<String> {
    let trimmed = cell.trim();
    for pattern in [
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%d.%m.%Y",
        "%Y%m%d",
        "%b %d, %Y",
        "%d %b %Y",
        "%B %d, %Y",
    ] {
        if let Ok(date) = muniment_core::chrono::NaiveDate::parse_from_str(trimmed, pattern) {
            return Some(date.format("%Y-%m-%d").to_string());
        }
    }
    let head: String = trimmed.chars().take(10).collect();
    if trimmed.len() > 10
        && matches!(trimmed.as_bytes()[10], b'T' | b' ')
        && muniment_core::chrono::NaiveDate::parse_from_str(&head, "%Y-%m-%d").is_ok()
    {
        return Some(head);
    }
    None
}

/// A date and time as RFC 3339 in UTC, from RFC 3339, `YYYY-MM-DD HH:MM[:SS]`
/// read as UTC, a bare date at midnight, or Unix seconds or milliseconds.
pub fn parse_date_time(cell: &str) -> Option<String> {
    let trimmed = cell.trim();
    if let Ok(instant) = muniment_core::chrono::DateTime::parse_from_rfc3339(trimmed) {
        return Some(
            instant
                .with_timezone(&muniment_core::chrono::Utc)
                .to_rfc3339_opts(muniment_core::chrono::SecondsFormat::Secs, true),
        );
    }
    for pattern in [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%dT%H:%M",
        "%m/%d/%Y %H:%M:%S",
        "%m/%d/%Y %H:%M",
    ] {
        if let Ok(naive) = muniment_core::chrono::NaiveDateTime::parse_from_str(trimmed, pattern) {
            return Some(
                naive
                    .and_utc()
                    .to_rfc3339_opts(muniment_core::chrono::SecondsFormat::Secs, true),
            );
        }
    }
    if let Some(date) = trimmed
        .parse::<muniment_core::chrono::NaiveDate>()
        .ok()
        .or_else(|| muniment_core::chrono::NaiveDate::parse_from_str(trimmed, "%m/%d/%Y").ok())
    {
        return Some(
            date.and_hms_opt(0, 0, 0)?
                .and_utc()
                .to_rfc3339_opts(muniment_core::chrono::SecondsFormat::Secs, true),
        );
    }
    if trimmed.chars().all(|c| c.is_ascii_digit()) {
        let seconds: i64 = match trimmed.len() {
            9..=10 => trimmed.parse().ok()?,
            13 => trimmed.parse::<i64>().ok()? / 1000,
            _ => return None,
        };
        return muniment_core::chrono::DateTime::<muniment_core::chrono::Utc>::from_timestamp(
            seconds, 0,
        )
        .map(|instant| instant.to_rfc3339_opts(muniment_core::chrono::SecondsFormat::Secs, true));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use muniment_core::serde_json::json;

    fn org_kind() -> KindRow {
        KindRow {
            count: 0,
            name: "org".into(),
            version: 1,
            schema: json!({
                "type": "object",
                "properties": {
                    "name": {"type": "string"},
                    "domain": {"type": "string"},
                    "employee_band": {"type": "string", "enum": ["1-10", "11-50", "51-200"]},
                    "founded": {"type": "string", "format": "date"},
                    "arr": {"type": "number"},
                    "seats": {"type": "integer"},
                    "active": {"type": "boolean"},
                    "tags": {"type": "array", "items": {"type": "string"}}
                },
                "required": ["name"]
            }),
            title_template: "{name}".into(),
            text_template: "{name}.".into(),
            states: None,
            extension: Some(
                json!({"type": "object", "properties": {"x_region": {"type": "string"}}}),
            ),
        }
    }

    fn mapping_entity(data: Value) -> EntityRow {
        EntityRow {
            id: "map-1".into(),
            kind: "mapping".into(),
            title: "csv customers.csv to org".into(),
            body_text: None,
            state: None,
            data,
            created_at: "2026-09-16T00:00:00.000Z".into(),
            updated_at: "2026-09-16T00:00:00.000Z".into(),
            deleted_at: None,
        }
    }

    #[test]
    fn parses_an_identity_spec_in_every_shape() {
        assert_eq!(
            IdentitySpec::parse("domain:Website").unwrap(),
            IdentitySpec {
                kind: "domain".into(),
                prefix: None,
                column: "Website".into()
            }
        );
        let external = IdentitySpec::parse("external:stripe:customer:Customer ID").unwrap();
        assert_eq!(external.prefix.as_deref(), Some("stripe:customer"));
        assert_eq!(external.column, "Customer ID");
        assert_eq!(external.text(), "external:stripe:customer:Customer ID");
        assert!(IdentitySpec::parse("external:stripe:Customer ID").is_err());
        assert!(IdentitySpec::parse("Website").is_err());
        assert!(IdentitySpec::parse("guid:Website").is_err());
        assert!(IdentitySpec::parse("email:").is_err());
    }

    #[test]
    fn reads_a_mapping_record_and_refuses_an_empty_one() {
        let mapping = Mapping::from_entity(&mapping_entity(json!({
            "source": "csv", "object": "/tmp/customers.csv", "kind": "org",
            "fields": {"Company": "name", "Website": "domain", "Skip": ""},
            "identity": "domain:Website", "approved": true,
            "cursors": {"offset": 40, "hash": "abc", "rows": 40}
        })))
        .unwrap();
        assert_eq!(mapping.fields.len(), 2);
        assert_eq!(mapping.identity.as_ref().unwrap().column, "Website");
        assert!(mapping.approved);
        assert_eq!(mapping.cursor.as_ref().unwrap().offset, 40);
        let empty = Mapping::from_entity(&mapping_entity(json!({
            "source": "csv", "object": "/tmp/x.csv", "kind": "org", "fields": {}
        })));
        assert_eq!(empty.unwrap_err(), "the mapping fills no property");
        let mut other = mapping_entity(json!({}));
        other.kind = "org".into();
        assert!(Mapping::from_entity(&other)
            .unwrap_err()
            .contains("not a mapping"));
    }

    #[test]
    fn plans_a_row_with_typed_values_and_the_identity() {
        let mapping = Mapping::from_entity(&mapping_entity(json!({
            "source": "csv", "object": "/tmp/customers.csv", "kind": "org",
            "fields": {"Company": "name", "Website": "domain", "Band": "employee_band", "Founded": "founded",
                       "ARR": "arr", "Seats": "seats", "Active": "active", "Tags": "tags", "Region": "x_region"},
            "identity": "domain:Website"
        })))
        .unwrap();
        let row: Row = [
            ("Company", "Northwind"),
            ("Website", "https://www.northwind.example/"),
            ("Band", "11 - 50"),
            ("Founded", "03/15/2019"),
            ("ARR", "$1,200.50"),
            ("Seats", "12"),
            ("Active", "Yes"),
            ("Tags", "a; b;"),
            ("Region", "EMEA"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let plan = row_plan(&mapping, &org_kind(), &row).unwrap();
        assert_eq!(plan.title, "Northwind");
        assert_eq!(plan.data["employee_band"], "11-50");
        assert_eq!(plan.data["founded"], "2019-03-15");
        assert_eq!(plan.data["arr"], 1200.5);
        assert_eq!(plan.data["seats"], 12);
        assert_eq!(plan.data["active"], true);
        assert_eq!(plan.data["tags"], json!(["a", "b"]));
        assert_eq!(plan.data["x_region"], "EMEA");
        assert_eq!(
            plan.identity,
            Some(IdentityInput {
                kind: "domain".into(),
                value: "https://www.northwind.example/".into()
            })
        );
        assert!(data_differs(&json!({"name": "Northwind"}), &plan.data));
        assert!(!data_differs(&Value::Object(plan.data.clone()), &plan.data));

        let mut bad = row.clone();
        bad.insert("Seats".into(), "twelve".into());
        let refusal = row_plan(&mapping, &org_kind(), &bad).unwrap_err();
        assert_eq!(refusal.reason, "Seats: twelve is not a whole number");
        assert_eq!(refusal.title, "Northwind");
        bad = row.clone();
        bad.insert("Band".into(), "huge".into());
        assert!(row_plan(&mapping, &org_kind(), &bad)
            .unwrap_err()
            .reason
            .starts_with("Band: huge is not one of"));
        bad = row.clone();
        bad.insert("Website".into(), " ".into());
        let refusal = row_plan(&mapping, &org_kind(), &bad).unwrap_err();
        assert!(refusal.reason.contains("no identity"));
        assert_eq!(refusal.title, "Northwind");

        let keyed_on_title = Mapping::from_entity(&mapping_entity(json!({
            "source": "csv", "object": "/tmp/customers.csv", "kind": "org", "fields": {"Company": "name"}
        })))
        .unwrap();
        let plan = row_plan(&keyed_on_title, &org_kind(), &row).unwrap();
        assert_eq!(plan.identity.unwrap().kind, "name_key");
        let mut blank = Row::new();
        blank.insert("Company".into(), "".into());
        assert_eq!(
            row_plan(&keyed_on_title, &org_kind(), &blank)
                .unwrap_err()
                .reason,
            "every mapped cell is empty"
        );
    }

    #[test]
    fn reads_numbers_booleans_dates_and_times_as_files_write_them() {
        assert_eq!(parse_number("$1,200.50"), Some(1200.5));
        assert_eq!(parse_number("(300)"), Some(-300.0));
        assert_eq!(parse_number("12%"), Some(12.0));
        assert_eq!(parse_number("1e3"), None);
        assert_eq!(parse_number("abc"), None);
        assert_eq!(parse_boolean("TRUE"), Some(true));
        assert_eq!(parse_boolean("off"), Some(false));
        assert_eq!(parse_boolean("maybe"), None);
        assert_eq!(parse_date("2026-09-16").as_deref(), Some("2026-09-16"));
        assert_eq!(parse_date("9/6/2026").as_deref(), Some("2026-09-06"));
        assert_eq!(parse_date("16.09.2026").as_deref(), Some("2026-09-16"));
        assert_eq!(
            parse_date("2026-09-16T10:00:00Z").as_deref(),
            Some("2026-09-16")
        );
        assert_eq!(parse_date("Sep 16, 2026").as_deref(), Some("2026-09-16"));
        assert_eq!(parse_date("yesterday"), None);
        assert_eq!(
            parse_date_time("2026-09-16T10:00:00+02:00").as_deref(),
            Some("2026-09-16T08:00:00Z")
        );
        assert_eq!(
            parse_date_time("2026-09-16 10:00").as_deref(),
            Some("2026-09-16T10:00:00Z")
        );
        assert_eq!(
            parse_date_time("2026-09-16").as_deref(),
            Some("2026-09-16T00:00:00Z")
        );
        assert_eq!(
            parse_date_time("1700000000").as_deref(),
            Some("2023-11-14T22:13:20Z")
        );
        assert_eq!(
            parse_date_time("1700000000000").as_deref(),
            Some("2023-11-14T22:13:20Z")
        );
        assert_eq!(parse_date_time("noon"), None);
        assert_eq!(
            coerce("{\"a\":1}", &json!({"type": "object"})).unwrap(),
            json!({"a": 1})
        );
        assert!(coerce("[1]", &json!({"type": "object"})).is_err());
    }

    #[test]
    fn keeps_an_identity_column_the_kind_has_no_property_for() {
        let person = KindRow {
            name: "person".into(),
            schema: json!({
                "type": "object",
                "properties": {"full_name": {"type": "string"}, "job_title": {"type": "string"}},
                "required": ["full_name"]
            }),
            title_template: "{full_name}".into(),
            ..org_kind()
        };
        let mapping = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "customers", "kind": "person",
            "fields": {"name": "full_name", "email": "email", "phone": "phone", "id": "x_missing"},
            "identity": "external:stripe:customers:id"
        })))
        .unwrap();
        let row: Row = [
            ("id", "cus_1"),
            ("name", "Ann"),
            ("email", "ann@example.com"),
            ("phone", ""),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let refusal = row_plan(&mapping, &person, &row).unwrap_err();
        assert_eq!(refusal.reason, "x_missing is not a property of person");
        assert_eq!(refusal.title, "ann@example.com");

        let mapping = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "customers", "kind": "person",
            "fields": {"name": "full_name", "email": "email", "phone": "phone"},
            "identity": "external:stripe:customers:id"
        })))
        .unwrap();
        let plan = row_plan(&mapping, &person, &row).unwrap();
        assert_eq!(plan.data["full_name"], "Ann");
        assert!(!plan.data.contains_key("email"));
        assert_eq!(
            plan.identities,
            vec![IdentityInput {
                kind: "email".into(),
                value: "ann@example.com".into()
            }]
        );
        assert_eq!(plan.identity.unwrap().value, "stripe:customers:cus_1");

        // The key column itself is not repeated beside the key.
        let keyed_on_email = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "customers", "kind": "person",
            "fields": {"name": "full_name", "email": "email"},
            "identity": "email:email"
        })))
        .unwrap();
        let plan = row_plan(&keyed_on_email, &person, &row).unwrap();
        assert!(plan.identities.is_empty());
        assert_eq!(plan.identity.unwrap().kind, "email");
    }

    #[test]
    fn draws_an_edge_from_a_column_that_names_another_record() {
        let subscription = KindRow {
            name: "subscription".into(),
            schema: json!({
                "type": "object",
                "properties": {"plan": {"type": "string"}, "amount": {"type": "number"}},
                "required": ["plan"]
            }),
            title_template: "{plan}".into(),
            ..org_kind()
        };
        let mapping = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "subscriptions", "kind": "subscription",
            "fields": {"plan": "plan", "amount": "amount"},
            "identity": "external:stripe:subscriptions:id",
            "edges": [{"relation": "billed_to", "identity": "external:stripe:customers:customer"}]
        })))
        .unwrap();
        assert_eq!(mapping.edges.len(), 1);
        assert_eq!(mapping.edges[0].identity.column, "customer");
        let row: Row = [
            ("id", "sub_1"),
            ("customer", "cus_1"),
            ("plan", "Team"),
            ("amount", "49"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let plan = row_plan(&mapping, &subscription, &row).unwrap();
        assert_eq!(
            plan.links,
            vec![RowLink {
                relation: "billed_to".into(),
                target: IdentityInput {
                    kind: "external".into(),
                    value: "stripe:customers:cus_1".into()
                }
            }]
        );
        let mut orphan = row.clone();
        orphan.insert("customer".into(), "".into());
        assert!(row_plan(&mapping, &subscription, &orphan)
            .unwrap()
            .links
            .is_empty());

        let unnamed = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "subscriptions", "kind": "subscription",
            "fields": {"plan": "plan"}, "edges": [{"identity": "external:stripe:customers:customer"}]
        })));
        assert_eq!(unnamed.unwrap_err(), "an edge names no relation");
        let bare = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "subscriptions", "kind": "subscription",
            "fields": {"plan": "plan"}, "edges": [{"relation": "billed_to", "identity": "customer"}]
        })));
        assert!(bare.unwrap_err().contains("not <kind>:<column>"));
    }

    #[test]
    fn titles_a_refused_row_by_its_email_or_its_key_before_a_stray_cell() {
        let mapping = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "customers", "kind": "org",
            "fields": {"balance": "arr", "name": "name", "seats": "seats"},
            "identity": "external:stripe:customers:id"
        })))
        .unwrap();
        let row: Row = [
            ("id", "cus_9"),
            ("name", ""),
            ("email", "ops@fabrikam.example"),
            ("balance", "0.00"),
            ("seats", "many"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let refusal = row_plan(&mapping, &org_kind(), &row).unwrap_err();
        assert_eq!(refusal.reason, "seats: many is not a whole number");
        assert_eq!(refusal.title, "ops@fabrikam.example");

        let mut no_email = row.clone();
        no_email.insert("email".into(), "".into());
        assert_eq!(
            row_plan(&mapping, &org_kind(), &no_email)
                .unwrap_err()
                .title,
            "cus_9"
        );

        let keyed_on_title = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "customers", "kind": "org",
            "fields": {"balance": "arr", "seats": "seats", "note": "x_region"}
        })))
        .unwrap();
        no_email.insert("note".into(), "Fabrikam's account".into());
        assert_eq!(
            row_plan(&keyed_on_title, &org_kind(), &no_email)
                .unwrap_err()
                .title,
            "Fabrikam's account"
        );
    }

    #[test]
    fn titles_a_nameless_row_by_its_email() {
        let kind = KindRow {
            schema: json!({
                "type": "object",
                "properties": {"name": {"type": "string"}, "domain": {"type": "string"}},
                "required": ["name"]
            }),
            ..org_kind()
        };
        let mapping = Mapping::from_entity(&mapping_entity(json!({
            "source": "stripe", "object": "customers", "kind": "org",
            "fields": {"name": "name", "email_domain": "domain"},
            "identity": "domain:email_domain"
        })))
        .unwrap();
        let row: Row = [
            ("id", "cus_1"),
            ("name", ""),
            ("email", "ann@example.com"),
            ("email_domain", "example.com"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        let plan = row_plan(&mapping, &kind, &row).unwrap();
        assert_eq!(plan.data["name"], "ann@example.com");
        assert_eq!(plan.title, "ann@example.com");

        let mut no_email = row.clone();
        no_email.insert("email".into(), "".into());
        no_email.insert("email_domain".into(), "".into());
        assert_eq!(
            row_plan(&mapping, &kind, &no_email).unwrap_err().reason,
            "every mapped cell is empty"
        );
    }
}
