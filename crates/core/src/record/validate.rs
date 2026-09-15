//! Kind validation on write. The core schema and the company's extension are
//! both JSON Schema objects, and every property in the data must belong to
//! one of them.

use super::EXTENSION_PREFIX;
use serde_json::{Map, Value};
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ValidationError {
    UnknownProperty(String),
    MissingRequired { field: String, prompt: String },
    WrongType { field: String, expected: String },
    NotAllowed { field: String, allowed: Vec<String> },
    BadFormat { field: String, format: String },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownProperty(field) => {
                write!(formatter, "{field} is not a property of this kind")
            }
            Self::MissingRequired { prompt, .. } => formatter.write_str(prompt),
            Self::WrongType { field, expected } => {
                write!(formatter, "{field} must be a {expected}")
            }
            Self::NotAllowed { field, allowed } => {
                write!(formatter, "{field} must be one of {}", allowed.join(", "))
            }
            Self::BadFormat { field, format } => {
                write!(formatter, "{field} must be a {format}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validates one complete data object against the kind and its extension.
pub fn validate(
    kind: &str,
    core: &Value,
    extension: Option<&Value>,
    data: &Map<String, Value>,
) -> Result<(), ValidationError> {
    let core_properties = properties(core);
    let extension_properties = extension.map(properties);
    for (field, value) in data {
        let schema = core_properties
            .and_then(|map| map.get(field))
            .or_else(|| {
                extension_properties
                    .flatten()
                    .and_then(|map| map.get(field))
                    .filter(|_| field.starts_with(EXTENSION_PREFIX))
            })
            .ok_or_else(|| ValidationError::UnknownProperty(field.clone()))?;
        if !value.is_null() {
            check_property(field, schema, value)?;
        }
    }
    for schema in std::iter::once(core).chain(extension) {
        for field in required(schema) {
            if data.get(field).is_none_or(Value::is_null) {
                return Err(ValidationError::MissingRequired {
                    field: field.to_owned(),
                    prompt: format!("{field} is required for kind {kind}. What is it?"),
                });
            }
        }
    }
    Ok(())
}

fn properties(schema: &Value) -> Option<&Map<String, Value>> {
    schema.get("properties").and_then(Value::as_object)
}

fn required(schema: &Value) -> impl Iterator<Item = &str> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
}

fn check_property(field: &str, schema: &Value, value: &Value) -> Result<(), ValidationError> {
    let expected = schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("string");
    let wrong = || ValidationError::WrongType {
        field: field.to_owned(),
        expected: expected.to_owned(),
    };
    match expected {
        "string" => {
            let text = value.as_str().ok_or_else(wrong)?;
            if let Some(allowed) = schema.get("enum").and_then(Value::as_array) {
                if !allowed.iter().any(|candidate| candidate == value) {
                    return Err(ValidationError::NotAllowed {
                        field: field.to_owned(),
                        allowed: allowed
                            .iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect(),
                    });
                }
            }
            match schema.get("format").and_then(Value::as_str) {
                Some("date") if chrono::NaiveDate::parse_from_str(text, "%Y-%m-%d").is_err() => {
                    Err(ValidationError::BadFormat {
                        field: field.to_owned(),
                        format: "date, YYYY-MM-DD".to_owned(),
                    })
                }
                Some("date-time") if chrono::DateTime::parse_from_rfc3339(text).is_err() => {
                    Err(ValidationError::BadFormat {
                        field: field.to_owned(),
                        format: "date-time, RFC 3339".to_owned(),
                    })
                }
                _ => Ok(()),
            }
        }
        "number" => value.as_f64().map(|_| ()).ok_or_else(wrong),
        "integer" => value.as_i64().map(|_| ()).ok_or_else(wrong),
        "boolean" => value.as_bool().map(|_| ()).ok_or_else(wrong),
        "object" => value.as_object().map(|_| ()).ok_or_else(wrong),
        "array" => {
            let items = value.as_array().ok_or_else(wrong)?;
            if let Some(item_schema) = schema.get("items") {
                for item in items {
                    check_property(field, item_schema, item)?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn deal() -> Value {
        json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "stage": {"type": "string", "enum": ["discovery", "won"]},
                "amount": {"type": "number"},
                "expected_close": {"type": "string", "format": "date"},
                "tags": {"type": "array", "items": {"type": "string"}}
            },
            "required": ["name", "stage"]
        })
    }

    fn object(value: Value) -> Map<String, Value> {
        value.as_object().unwrap().clone()
    }

    #[test]
    fn accepts_a_complete_object() {
        let data = object(
            json!({"name": "N", "stage": "won", "amount": 1.5, "expected_close": "2026-09-16", "tags": ["a"]}),
        );
        validate("deal", &deal(), None, &data).unwrap();
    }

    #[test]
    fn names_the_missing_required_field_with_a_prompt() {
        let data = object(json!({"name": "N"}));
        assert_eq!(
            validate("deal", &deal(), None, &data),
            Err(ValidationError::MissingRequired {
                field: "stage".into(),
                prompt: "stage is required for kind deal. What is it?".into(),
            })
        );
    }

    #[test]
    fn rejects_unknown_properties_types_enums_and_formats() {
        let base = json!({"name": "N", "stage": "won"});
        let mut data = object(base.clone());
        data.insert("color".into(), json!("red"));
        assert_eq!(
            validate("deal", &deal(), None, &data),
            Err(ValidationError::UnknownProperty("color".into()))
        );

        let mut data = object(base.clone());
        data.insert("amount".into(), json!("ten"));
        assert!(matches!(
            validate("deal", &deal(), None, &data),
            Err(ValidationError::WrongType { .. })
        ));

        let mut data = object(base.clone());
        data.insert("stage".into(), json!("open"));
        assert!(matches!(
            validate("deal", &deal(), None, &data),
            Err(ValidationError::NotAllowed { .. })
        ));

        let mut data = object(base.clone());
        data.insert("expected_close".into(), json!("16/09/2026"));
        assert!(matches!(
            validate("deal", &deal(), None, &data),
            Err(ValidationError::BadFormat { .. })
        ));

        let mut data = object(base);
        data.insert("tags".into(), json!([1]));
        assert!(matches!(
            validate("deal", &deal(), None, &data),
            Err(ValidationError::WrongType { .. })
        ));
    }

    #[test]
    fn extension_properties_need_the_prefix_and_a_declaration() {
        let extension = json!({"type": "object", "properties": {"x_renewal_risk": {"type": "string", "enum": ["low", "high"]}}});
        let mut data = object(json!({"name": "N", "stage": "won"}));
        data.insert("x_renewal_risk".into(), json!("low"));
        validate("deal", &deal(), Some(&extension), &data).unwrap();

        data.insert("x_other".into(), json!("low"));
        assert_eq!(
            validate("deal", &deal(), Some(&extension), &data),
            Err(ValidationError::UnknownProperty("x_other".into()))
        );

        let smuggled = json!({"type": "object", "properties": {"stage": {"type": "string"}}});
        let data = object(json!({"name": "N", "stage": "anything"}));
        assert!(matches!(
            validate("deal", &deal(), Some(&smuggled), &data),
            Err(ValidationError::NotAllowed { .. })
        ));
    }
}
