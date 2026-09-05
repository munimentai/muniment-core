//! Route taxonomy and model metadata contract for the bundled classifier.

/// The metadata key for the classifier's ordered class list.
///
/// Its value is a JSON array of strings in [`ROUTE_CLASSES`] order.
pub const CLASS_LIST_METADATA_KEY: &str = "muniment.router.classes";

/// A route produced by the bundled classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    Cloud,
    Local,
    Proxy,
}

impl RouteClass {
    /// Returns the stable model class name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cloud => "route.cloud",
            Self::Local => "route.local",
            Self::Proxy => "route.proxy",
        }
    }

    /// Parses a stable model class name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "route.cloud" => Some(Self::Cloud),
            "route.local" => Some(Self::Local),
            "route.proxy" => Some(Self::Proxy),
            _ => None,
        }
    }
}

/// The classifier classes in model-output order.
pub const ROUTE_CLASSES: [RouteClass; 3] =
    [RouteClass::Cloud, RouteClass::Local, RouteClass::Proxy];

/// A failure to validate the classifier class-list metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassListError {
    MalformedJson,
    NotArray,
    WrongCount,
    Reordered,
    UnknownName,
}

impl std::fmt::Display for ClassListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedJson => write!(f, "classifier class list is malformed JSON"),
            Self::NotArray => write!(f, "classifier class list is not an array"),
            Self::WrongCount => write!(f, "classifier class list has the wrong count"),
            Self::Reordered => write!(f, "classifier class list is reordered"),
            Self::UnknownName => write!(f, "classifier class list contains an unknown name"),
        }
    }
}

impl std::error::Error for ClassListError {}

/// Validates the JSON-encoded classifier class list.
pub fn parse_class_list(value: &str) -> Result<(), ClassListError> {
    let value: serde_json::Value =
        serde_json::from_str(value).map_err(|_| ClassListError::MalformedJson)?;
    let classes = value.as_array().ok_or(ClassListError::NotArray)?;
    if classes.len() != ROUTE_CLASSES.len() {
        return Err(ClassListError::WrongCount);
    }

    for (value, expected) in classes.iter().zip(ROUTE_CLASSES) {
        let name = value.as_str().ok_or(ClassListError::UnknownName)?;
        let actual = RouteClass::parse(name).ok_or(ClassListError::UnknownName)?;
        if actual != expected {
            return Err(ClassListError::Reordered);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_the_ordered_class_list() {
        assert_eq!(
            parse_class_list(r#"["route.cloud","route.local","route.proxy"]"#),
            Ok(())
        );
    }

    #[test]
    fn rejects_malformed_json() {
        assert_eq!(parse_class_list("["), Err(ClassListError::MalformedJson));
    }

    #[test]
    fn rejects_a_non_array_value() {
        assert_eq!(parse_class_list("{}"), Err(ClassListError::NotArray));
    }

    #[test]
    fn rejects_the_wrong_class_count() {
        assert_eq!(
            parse_class_list(r#"["route.cloud","route.local"]"#),
            Err(ClassListError::WrongCount)
        );
    }

    #[test]
    fn rejects_a_reordered_class_list() {
        assert_eq!(
            parse_class_list(r#"["route.local","route.cloud","route.proxy"]"#),
            Err(ClassListError::Reordered)
        );
    }

    #[test]
    fn rejects_an_unknown_class_name() {
        assert_eq!(
            parse_class_list(r#"["route.cloud","route.unknown","route.proxy"]"#),
            Err(ClassListError::UnknownName)
        );
    }
}
