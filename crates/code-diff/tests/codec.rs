use muniment_code_diff::{
    decode, CodeDiff, DecodeError, DiffFile, DiffHunk, DiffLine, DiffLineKind, DiffStatus,
    ValidationError,
};

fn valid() -> CodeDiff {
    CodeDiff {
        schema_version: 1,
        id: "test-diff".into(),
        files: vec![DiffFile {
            old_path: Some("old.txt".into()),
            new_path: Some("new.txt".into()),
            status: DiffStatus::Modified,
            old_mode: Some("100644".into()),
            new_mode: Some("100644".into()),
            binary: false,
            hunks: vec![DiffHunk {
                old_start: 1,
                old_count: 1,
                new_start: 1,
                new_count: 1,
                header: "@@ -1 +1 @@".into(),
                lines: vec![DiffLine {
                    kind: DiffLineKind::Context,
                    old_line_number: Some(1),
                    new_line_number: Some(1),
                    text: "same".into(),
                    segments: vec![],
                }],
            }],
        }],
        truncated: false,
    }
}

#[test]
fn empty_and_truncated_diffs_are_valid() {
    let empty = CodeDiff {
        files: vec![],
        ..valid()
    };
    empty.validate().unwrap();
    CodeDiff {
        truncated: true,
        ..empty
    }
    .validate()
    .unwrap();
}

#[test]
fn rejects_each_contradictory_value_with_its_named_error() {
    let mut value = valid();
    value.schema_version = 2;
    assert_eq!(
        value.validate(),
        Err(ValidationError::UnsupportedSchemaVersion)
    );

    let mut value = valid();
    value.files[0].binary = true;
    assert_eq!(value.validate(), Err(ValidationError::BinaryFileHasHunks));

    let mut value = valid();
    value.files[0].hunks[0].lines[0].kind = DiffLineKind::Addition;
    assert_eq!(
        value.validate(),
        Err(ValidationError::LineNumberOnMissingSide)
    );

    let mut value = valid();
    value.files[0].hunks[0].old_count = 0;
    assert_eq!(
        value.validate(),
        Err(ValidationError::HunkLineCountMismatch)
    );
}

#[test]
fn decode_checks_the_schema_and_model() {
    let bytes = serde_json::to_vec(&valid()).unwrap();
    assert_eq!(decode(&bytes).unwrap(), valid());

    let mut value = valid();
    value.schema_version = 0;
    assert!(matches!(
        decode(&serde_json::to_vec(&value).unwrap()),
        Err(DecodeError::Validation(
            ValidationError::UnsupportedSchemaVersion
        ))
    ));
    assert!(matches!(decode(b"not json"), Err(DecodeError::Json(_))));
}

#[test]
fn missing_sides_are_absent_on_the_wire() {
    let mut value = valid();
    value.files[0].hunks[0].lines[0].kind = DiffLineKind::Addition;
    value.files[0].hunks[0].lines[0].old_line_number = None;
    value.files[0].hunks[0].old_count = 0;
    let wire = serde_json::to_value(value).unwrap();

    assert!(wire["files"][0]["hunks"][0]["lines"][0]
        .as_object()
        .unwrap()
        .get("oldLineNumber")
        .is_none());
}
