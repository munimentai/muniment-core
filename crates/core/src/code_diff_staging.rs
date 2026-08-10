//! Pure staging for proposed file operations.

use std::{
    collections::{BTreeMap, HashSet},
    error::Error,
    fmt,
};

use crate::write_plan::{MAX_OPERATIONS, MAX_OPERATION_OUTPUT_BYTES, MAX_PLAN_OUTPUT_BYTES};

/// One proposed change to an in-memory workspace tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProposedOperation {
    Write { path: String, output: Vec<u8> },
    Rename { source: String, target: String },
    Delete { path: String },
}

/// Applies proposed operations in order to a copy of the current tree.
pub fn stage_proposed_operations(
    current: &BTreeMap<String, Vec<u8>>,
    operations: &[ProposedOperation],
) -> Result<BTreeMap<String, Vec<u8>>, StageProposedOperationsError> {
    validate_operations(operations)?;

    let mut staged = current.clone();
    for operation in operations {
        match operation {
            ProposedOperation::Write { path, output } => {
                staged.insert(path.clone(), output.clone());
            }
            ProposedOperation::Rename { source, target } => {
                let Some(output) = staged.remove(source) else {
                    return Err(StageProposedOperationsError::RenameSourceMissing(
                        source.clone(),
                    ));
                };
                if staged.contains_key(target) {
                    return Err(StageProposedOperationsError::RenameTargetExists(
                        target.clone(),
                    ));
                }
                staged.insert(target.clone(), output);
            }
            ProposedOperation::Delete { path } => {
                if staged.remove(path).is_none() {
                    return Err(StageProposedOperationsError::DeleteTargetMissing(
                        path.clone(),
                    ));
                }
            }
        }
    }
    Ok(staged)
}

fn validate_operations(
    operations: &[ProposedOperation],
) -> Result<(), StageProposedOperationsError> {
    if operations.len() > MAX_OPERATIONS {
        return Err(StageProposedOperationsError::TooManyOperations {
            count: operations.len(),
        });
    }

    let mut paths = HashSet::new();
    let mut total = 0usize;
    for operation in operations {
        for path in operation.paths().into_iter().flatten() {
            validate_path(path)?;
            if !paths.insert(path) {
                return Err(StageProposedOperationsError::ConflictingPath(
                    path.to_owned(),
                ));
            }
        }

        if let ProposedOperation::Write { path, output } = operation {
            total = checked_output_total(total, path, output.len())?;
        }
    }
    Ok(())
}

fn checked_output_total(
    total: usize,
    path: &str,
    output_len: usize,
) -> Result<usize, StageProposedOperationsError> {
    if output_len > MAX_OPERATION_OUTPUT_BYTES {
        return Err(StageProposedOperationsError::OperationOutputTooLarge(
            path.to_owned(),
        ));
    }
    let total = total
        .checked_add(output_len)
        .ok_or_else(|| StageProposedOperationsError::TotalOutputTooLarge(path.to_owned()))?;
    if total > MAX_PLAN_OUTPUT_BYTES {
        return Err(StageProposedOperationsError::TotalOutputTooLarge(
            path.to_owned(),
        ));
    }
    Ok(total)
}

impl ProposedOperation {
    fn paths(&self) -> [Option<&str>; 2] {
        match self {
            Self::Write { path, .. } | Self::Delete { path } => [Some(path), None],
            Self::Rename { source, target } => [Some(source), Some(target)],
        }
    }
}

fn validate_path(path: &str) -> Result<(), StageProposedOperationsError> {
    if path.is_empty() {
        return Err(StageProposedOperationsError::EmptyPath(path.to_owned()));
    }
    let bytes = path.as_bytes();
    if path.starts_with('/')
        || (bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'/')
    {
        return Err(StageProposedOperationsError::AbsolutePath(path.to_owned()));
    }
    if path.contains('\\') {
        return Err(StageProposedOperationsError::BackslashInPath(
            path.to_owned(),
        ));
    }
    if path.contains('\0') {
        return Err(StageProposedOperationsError::NulInPath(path.to_owned()));
    }
    if let Some(component) = path.split('/').find(|part| part.is_empty()) {
        debug_assert!(component.is_empty());
        return Err(StageProposedOperationsError::EmptyPathComponent(
            path.to_owned(),
        ));
    }
    if path.split('/').any(|part| part == ".") {
        return Err(StageProposedOperationsError::CurrentPathComponent(
            path.to_owned(),
        ));
    }
    if path.split('/').any(|part| part == "..") {
        return Err(StageProposedOperationsError::ParentPathComponent(
            path.to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StageProposedOperationsError {
    TooManyOperations { count: usize },
    OperationOutputTooLarge(String),
    TotalOutputTooLarge(String),
    EmptyPath(String),
    AbsolutePath(String),
    EmptyPathComponent(String),
    CurrentPathComponent(String),
    ParentPathComponent(String),
    BackslashInPath(String),
    NulInPath(String),
    ConflictingPath(String),
    RenameSourceMissing(String),
    RenameTargetExists(String),
    DeleteTargetMissing(String),
}

impl fmt::Display for StageProposedOperationsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyOperations { count } => write!(
                formatter,
                "the proposal has {count} operations, but the limit is {MAX_OPERATIONS}"
            ),
            Self::OperationOutputTooLarge(path) => write!(
                formatter,
                "the output for path {path:?} exceeds {MAX_OPERATION_OUTPUT_BYTES} bytes"
            ),
            Self::TotalOutputTooLarge(path) => write!(
                formatter,
                "the total output exceeds {MAX_PLAN_OUTPUT_BYTES} bytes at path {path:?}"
            ),
            Self::EmptyPath(path) => write!(formatter, "path {path:?} is empty"),
            Self::AbsolutePath(path) => write!(formatter, "path {path:?} is absolute"),
            Self::EmptyPathComponent(path) => {
                write!(formatter, "path {path:?} contains an empty component")
            }
            Self::CurrentPathComponent(path) => {
                write!(formatter, "path {path:?} contains a . component")
            }
            Self::ParentPathComponent(path) => {
                write!(formatter, "path {path:?} contains a .. component")
            }
            Self::BackslashInPath(path) => write!(formatter, "path {path:?} contains a backslash"),
            Self::NulInPath(path) => write!(formatter, "path {path:?} contains a NUL byte"),
            Self::ConflictingPath(path) => {
                write!(
                    formatter,
                    "path {path:?} appears in more than one operation"
                )
            }
            Self::RenameSourceMissing(path) => {
                write!(formatter, "rename source path {path:?} does not exist")
            }
            Self::RenameTargetExists(path) => {
                write!(formatter, "rename target path {path:?} already exists")
            }
            Self::DeleteTargetMissing(path) => {
                write!(formatter, "delete target path {path:?} does not exist")
            }
        }
    }
}

impl Error for StageProposedOperationsError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::code_diff::compute_code_diff;

    fn tree(files: &[(&str, &[u8])]) -> BTreeMap<String, Vec<u8>> {
        files
            .iter()
            .map(|(path, bytes)| ((*path).to_owned(), bytes.to_vec()))
            .collect()
    }

    #[test]
    fn stages_operations_in_order_and_produces_a_code_diff() {
        let current = tree(&[("edit.txt", b"old"), ("old.txt", b"move"), ("gone", b"x")]);
        let staged = stage_proposed_operations(
            &current,
            &[
                ProposedOperation::Write {
                    path: "edit.txt".into(),
                    output: b"new".to_vec(),
                },
                ProposedOperation::Rename {
                    source: "old.txt".into(),
                    target: "new.txt".into(),
                },
                ProposedOperation::Delete {
                    path: "gone".into(),
                },
            ],
        )
        .unwrap();

        assert_eq!(staged, tree(&[("edit.txt", b"new"), ("new.txt", b"move")]));
        let diff = compute_code_diff(&current, &staged).unwrap();
        assert_eq!(diff.files.len(), 3);
    }

    #[test]
    fn rejects_invalid_paths_with_named_variants_and_text() {
        let cases = [
            ("", StageProposedOperationsError::EmptyPath("".into())),
            (
                "/a",
                StageProposedOperationsError::AbsolutePath("/a".into()),
            ),
            (
                "C:/outside",
                StageProposedOperationsError::AbsolutePath("C:/outside".into()),
            ),
            (
                "a//b",
                StageProposedOperationsError::EmptyPathComponent("a//b".into()),
            ),
            (
                "a/./b",
                StageProposedOperationsError::CurrentPathComponent("a/./b".into()),
            ),
            (
                "a/../b",
                StageProposedOperationsError::ParentPathComponent("a/../b".into()),
            ),
            (
                "a\\b",
                StageProposedOperationsError::BackslashInPath("a\\b".into()),
            ),
            (
                "a\0b",
                StageProposedOperationsError::NulInPath("a\0b".into()),
            ),
        ];
        for (path, expected) in cases {
            let error = stage_proposed_operations(
                &BTreeMap::new(),
                &[ProposedOperation::Delete { path: path.into() }],
            )
            .unwrap_err();
            assert_eq!(error, expected);
            assert!(error.to_string().contains(&format!("{path:?}")));
        }
    }

    #[test]
    fn rejects_operation_and_total_bounds() {
        let too_many = vec![ProposedOperation::Delete { path: "a".into() }; MAX_OPERATIONS + 1];
        assert!(matches!(
            stage_proposed_operations(&BTreeMap::new(), &too_many),
            Err(StageProposedOperationsError::TooManyOperations { .. })
        ));

        let oversized = [ProposedOperation::Write {
            path: "large".into(),
            output: vec![0; MAX_OPERATION_OUTPUT_BYTES + 1],
        }];
        assert_eq!(
            stage_proposed_operations(&BTreeMap::new(), &oversized),
            Err(StageProposedOperationsError::OperationOutputTooLarge(
                "large".into()
            ))
        );

        let excessive: Vec<_> = (0..9)
            .map(|index| ProposedOperation::Write {
                path: format!("{index}.bin"),
                output: vec![0; MAX_OPERATION_OUTPUT_BYTES],
            })
            .collect();
        assert_eq!(
            stage_proposed_operations(&BTreeMap::new(), &excessive),
            Err(StageProposedOperationsError::TotalOutputTooLarge(
                "8.bin".into()
            ))
        );

        assert_eq!(
            checked_output_total(0, "large", MAX_OPERATION_OUTPUT_BYTES + 1),
            Err(StageProposedOperationsError::OperationOutputTooLarge(
                "large".into()
            ))
        );
        assert_eq!(
            checked_output_total(MAX_PLAN_OUTPUT_BYTES, "total", 1),
            Err(StageProposedOperationsError::TotalOutputTooLarge(
                "total".into()
            ))
        );
        assert_eq!(
            checked_output_total(usize::MAX, "overflow", 1),
            Err(StageProposedOperationsError::TotalOutputTooLarge(
                "overflow".into()
            ))
        );
    }

    #[test]
    fn rejects_conflicts_and_missing_tree_entries() {
        let conflict = [
            ProposedOperation::Write {
                path: "same".into(),
                output: Vec::new(),
            },
            ProposedOperation::Delete {
                path: "same".into(),
            },
        ];
        assert_eq!(
            stage_proposed_operations(&BTreeMap::new(), &conflict),
            Err(StageProposedOperationsError::ConflictingPath("same".into()))
        );
        assert_eq!(
            stage_proposed_operations(
                &BTreeMap::new(),
                &[ProposedOperation::Rename {
                    source: "missing".into(),
                    target: "new".into(),
                }]
            ),
            Err(StageProposedOperationsError::RenameSourceMissing(
                "missing".into()
            ))
        );
        assert_eq!(
            stage_proposed_operations(
                &tree(&[("old", b"x"), ("taken", b"y")]),
                &[ProposedOperation::Rename {
                    source: "old".into(),
                    target: "taken".into(),
                }]
            ),
            Err(StageProposedOperationsError::RenameTargetExists(
                "taken".into()
            ))
        );
        assert_eq!(
            stage_proposed_operations(
                &BTreeMap::new(),
                &[ProposedOperation::Delete {
                    path: "missing".into(),
                }]
            ),
            Err(StageProposedOperationsError::DeleteTargetMissing(
                "missing".into()
            ))
        );
    }
}
