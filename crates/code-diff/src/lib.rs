pub mod fixtures;

use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CodeDiff {
    pub schema_version: u32,
    pub id: String,
    pub files: Vec<DiffFile>,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffFile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_path: Option<String>,
    pub status: DiffStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_mode: Option<String>,
    pub binary: bool,
    pub hunks: Vec<DiffHunk>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiffStatus {
    Added,
    Deleted,
    Modified,
    Renamed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffHunk {
    pub old_start: u64,
    pub old_count: u64,
    pub new_start: u64,
    pub new_count: u64,
    pub header: String,
    pub lines: Vec<DiffLine>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffLine {
    pub kind: DiffLineKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_line_number: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_line_number: Option<u64>,
    pub text: String,
    pub segments: Vec<DiffLineSegment>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiffLineKind {
    Context,
    Addition,
    Deletion,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiffLineSegment {
    pub kind: DiffLineSegmentKind,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiffLineSegmentKind {
    Plain,
    Addition,
    Deletion,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    UnsupportedSchemaVersion,
    AddedFilePathMismatch,
    DeletedFilePathMismatch,
    ModifiedFilePathMismatch,
    RenamedFilePathMismatch,
    RenamedFilePathsMatch,
    ModeWithoutPath,
    BinaryFileHasHunks,
    LineNumberOnMissingSide,
    HunkLineCountMismatch,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::UnsupportedSchemaVersion => "schemaVersion must equal 1",
            Self::AddedFilePathMismatch => "an added file must carry only a new path",
            Self::DeletedFilePathMismatch => "a deleted file must carry only an old path",
            Self::ModifiedFilePathMismatch => "a modified file must carry both paths",
            Self::RenamedFilePathMismatch => "a renamed file must carry both paths",
            Self::RenamedFilePathsMatch => "a renamed file must carry two different paths",
            Self::ModeWithoutPath => "a mode must not exist without its path",
            Self::BinaryFileHasHunks => "a binary file must not contain hunks",
            Self::LineNumberOnMissingSide => "a line must not number a missing side",
            Self::HunkLineCountMismatch => "a hunk count must match its lines",
        })
    }
}

impl Error for ValidationError {}

impl CodeDiff {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.schema_version != 1 {
            return Err(ValidationError::UnsupportedSchemaVersion);
        }
        for file in &self.files {
            match file.status {
                DiffStatus::Added if file.old_path.is_some() || file.new_path.is_none() => {
                    return Err(ValidationError::AddedFilePathMismatch);
                }
                DiffStatus::Deleted if file.old_path.is_none() || file.new_path.is_some() => {
                    return Err(ValidationError::DeletedFilePathMismatch);
                }
                DiffStatus::Modified if file.old_path.is_none() || file.new_path.is_none() => {
                    return Err(ValidationError::ModifiedFilePathMismatch);
                }
                DiffStatus::Renamed if file.old_path.is_none() || file.new_path.is_none() => {
                    return Err(ValidationError::RenamedFilePathMismatch);
                }
                DiffStatus::Renamed if file.old_path == file.new_path => {
                    return Err(ValidationError::RenamedFilePathsMatch);
                }
                _ => {}
            }
            if (file.old_path.is_none() && file.old_mode.is_some())
                || (file.new_path.is_none() && file.new_mode.is_some())
            {
                return Err(ValidationError::ModeWithoutPath);
            }
            if file.binary && !file.hunks.is_empty() {
                return Err(ValidationError::BinaryFileHasHunks);
            }
            for hunk in &file.hunks {
                let mut old_count = 0;
                let mut new_count = 0;
                for line in &hunk.lines {
                    match line.kind {
                        DiffLineKind::Context => {
                            old_count += 1;
                            new_count += 1;
                        }
                        DiffLineKind::Addition => {
                            if line.old_line_number.is_some() {
                                return Err(ValidationError::LineNumberOnMissingSide);
                            }
                            new_count += 1;
                        }
                        DiffLineKind::Deletion => {
                            if line.new_line_number.is_some() {
                                return Err(ValidationError::LineNumberOnMissingSide);
                            }
                            old_count += 1;
                        }
                    }
                }
                if old_count != hunk.old_count || new_count != hunk.new_count {
                    return Err(ValidationError::HunkLineCountMismatch);
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum DecodeError {
    Json(serde_json::Error),
    Validation(ValidationError),
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => error.fmt(formatter),
            Self::Validation(error) => error.fmt(formatter),
        }
    }
}

impl Error for DecodeError {}

#[derive(Debug)]
pub enum CanonicalBytesError {
    Validation(ValidationError),
    Json(serde_json::Error),
}

impl fmt::Display for CanonicalBytesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(error) => error.fmt(formatter),
            Self::Json(error) => error.fmt(formatter),
        }
    }
}

impl Error for CanonicalBytesError {}

/// Returns RFC 8785 canonical JSON bytes for a valid code diff.
pub fn canonical_bytes(value: &CodeDiff) -> Result<Vec<u8>, CanonicalBytesError> {
    value.validate().map_err(CanonicalBytesError::Validation)?;
    let mut value = serde_json::to_value(value).map_err(CanonicalBytesError::Json)?;
    sort_object_keys(&mut value);
    serde_json::to_vec(&value).map_err(CanonicalBytesError::Json)
}

fn sort_object_keys(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(values) => {
            for value in values {
                sort_object_keys(value);
            }
        }
        serde_json::Value::Object(object) => {
            let mut entries: Vec<_> = std::mem::take(object).into_iter().collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            for (key, mut value) in entries {
                sort_object_keys(&mut value);
                object.insert(key, value);
            }
        }
        _ => {}
    }
}

pub fn decode(bytes: &[u8]) -> Result<CodeDiff, DecodeError> {
    let value: CodeDiff = serde_json::from_slice(bytes).map_err(DecodeError::Json)?;
    value.validate().map_err(DecodeError::Validation)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::sort_object_keys;
    use serde_json::{Map, Value};

    #[test]
    fn canonicalization_ignores_object_key_insertion_order() {
        let mut first = Map::new();
        first.insert("z".into(), Value::Bool(true));
        first.insert(
            "a".into(),
            Value::Object(Map::from_iter([
                ("y".into(), Value::from(2)),
                ("b".into(), Value::from(1)),
            ])),
        );
        let mut second = Map::new();
        second.insert(
            "a".into(),
            Value::Object(Map::from_iter([
                ("b".into(), Value::from(1)),
                ("y".into(), Value::from(2)),
            ])),
        );
        second.insert("z".into(), Value::Bool(true));
        let (mut first, mut second) = (Value::Object(first), Value::Object(second));

        sort_object_keys(&mut first);
        sort_object_keys(&mut second);

        let first = serde_json::to_vec(&first).unwrap();
        assert_eq!(first, serde_json::to_vec(&second).unwrap());
        assert_eq!(first, br#"{"a":{"b":1,"y":2},"z":true}"#);
    }
}
