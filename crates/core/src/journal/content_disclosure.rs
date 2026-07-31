use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentDisclosure {
    Released,
    Withheld(WithholdingReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WithholdingReason {
    Workspace,
    Connector,
    Artifact,
    Permission,
    ContentPolicy,
}

pub fn read_content_disclosure(payload: &Value) -> ContentDisclosure {
    let Some(fields) = payload.as_object() else {
        return invalid_disclosure();
    };
    match fields.get("content_disclosure").and_then(Value::as_str) {
        Some("released") if !fields.contains_key("content_disclosure_reason") => {
            ContentDisclosure::Released
        }
        Some("withheld") => fields
            .get("content_disclosure_reason")
            .and_then(Value::as_str)
            .and_then(read_reason)
            .map(ContentDisclosure::Withheld)
            .unwrap_or_else(invalid_disclosure),
        _ => invalid_disclosure(),
    }
}

fn read_reason(reason: &str) -> Option<WithholdingReason> {
    match reason {
        "workspace" => Some(WithholdingReason::Workspace),
        "connector" => Some(WithholdingReason::Connector),
        "artifact" => Some(WithholdingReason::Artifact),
        "permission" => Some(WithholdingReason::Permission),
        "content_policy" => Some(WithholdingReason::ContentPolicy),
        _ => None,
    }
}

fn invalid_disclosure() -> ContentDisclosure {
    ContentDisclosure::Withheld(WithholdingReason::ContentPolicy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn reads_released_disclosure() {
        assert_eq!(
            read_content_disclosure(&json!({"content_disclosure": "released"})),
            ContentDisclosure::Released
        );
    }

    #[test]
    fn missing_disclosure_is_withheld() {
        assert!(matches!(
            read_content_disclosure(&json!({"text": "legacy"})),
            ContentDisclosure::Withheld(_)
        ));
    }

    #[test]
    fn unknown_disclosure_is_withheld() {
        assert!(matches!(
            read_content_disclosure(&json!({"content_disclosure": "public"})),
            ContentDisclosure::Withheld(_)
        ));
    }

    #[test]
    fn released_disclosure_with_reason_is_withheld() {
        assert!(matches!(
            read_content_disclosure(&json!({
                "content_disclosure": "released",
                "content_disclosure_reason": "workspace"
            })),
            ContentDisclosure::Withheld(_)
        ));
    }

    #[test]
    fn withheld_disclosure_without_reason_is_withheld() {
        assert!(matches!(
            read_content_disclosure(&json!({"content_disclosure": "withheld"})),
            ContentDisclosure::Withheld(_)
        ));
    }

    #[test]
    fn reads_each_withholding_reason() {
        let cases = [
            ("workspace", WithholdingReason::Workspace),
            ("connector", WithholdingReason::Connector),
            ("artifact", WithholdingReason::Artifact),
            ("permission", WithholdingReason::Permission),
            ("content_policy", WithholdingReason::ContentPolicy),
        ];
        for (reason, expected) in cases {
            assert_eq!(
                read_content_disclosure(&json!({
                    "content_disclosure": "withheld",
                    "content_disclosure_reason": reason
                })),
                ContentDisclosure::Withheld(expected)
            );
        }
    }

    #[test]
    fn unknown_withholding_reason_is_withheld() {
        assert!(matches!(
            read_content_disclosure(&json!({
                "content_disclosure": "withheld",
                "content_disclosure_reason": "other"
            })),
            ContentDisclosure::Withheld(_)
        ));
    }
}
