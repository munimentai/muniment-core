//! Filesystem application for verified workspace write plans.

use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::Dir;
use std::{collections::BTreeMap, fmt, io, io::Write, path::Path};

use crate::{
    code_diff_observe::VerifiedWritePlan,
    write_plan::{WriteOperation, WritePlan},
};

/// Applies a write plan through the parent directories returned by verification.
pub fn apply_workspace_write_plan(
    plan: &WritePlan,
    verified: VerifiedWritePlan,
) -> Result<(), ApplyWritePlanError> {
    let parents = verified.into_parents();
    require_all_parents(plan, &parents)?;

    for operation in plan.operations() {
        match operation {
            WriteOperation::Write {
                target,
                output,
                mode,
            } => apply_write(
                parent(&parents, target.path()),
                target.path(),
                output,
                *mode,
            )?,
            WriteOperation::Delete { target } => parent(&parents, target.path())
                .remove_file(final_name(target.path()))
                .map_err(|source| path_error(target.path(), source))?,
            WriteOperation::Rename { source, target } => parent(&parents, source.path())
                .rename(
                    final_name(source.path()),
                    parent(&parents, target.path()),
                    final_name(target.path()),
                )
                .map_err(|error| path_error(target.path(), error))?,
        }
    }
    Ok(())
}

fn require_all_parents(
    plan: &WritePlan,
    parents: &BTreeMap<String, Dir>,
) -> Result<(), ApplyWritePlanError> {
    for operation in plan.operations() {
        let paths: [Option<&str>; 2] = match operation {
            WriteOperation::Write { target, .. } | WriteOperation::Delete { target } => {
                [Some(target.path()), None]
            }
            WriteOperation::Rename { source, target } => [Some(source.path()), Some(target.path())],
        };
        for path in paths.into_iter().flatten() {
            if !parents.contains_key(path) {
                return Err(ApplyWritePlanError::MissingParent { path: path.into() });
            }
        }
    }
    Ok(())
}

fn apply_write(
    parent: &Dir,
    path: &str,
    output: &[u8],
    mode: u32,
) -> Result<(), ApplyWritePlanError> {
    let target_name = final_name(path);
    let temporary_name = format!(
        ".{}.{}.tmp",
        target_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    );
    let result = (|| {
        let mut options = cap_std::fs::OpenOptions::new();
        options
            .create_new(true)
            .write(true)
            .follow(FollowSymlinks::No);
        let mut file = parent
            .open_with(&temporary_name, &options)
            .map_err(|source| path_error(path, source))?
            .into_std();
        file.write_all(output)
            .map_err(|source| path_error(path, source))?;
        set_file_mode(&file, mode).map_err(|source| path_error(path, source))?;
        file.sync_all().map_err(|source| path_error(path, source))?;
        parent
            .rename(&temporary_name, parent, target_name)
            .map_err(|source| path_error(path, source))
    })();
    if result.is_err() {
        let _ = parent.remove_file(&temporary_name);
    }
    result
}

#[cfg(unix)]
fn set_file_mode(file: &std::fs::File, mode: u32) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(mode))
}

#[cfg(windows)]
fn set_file_mode(_file: &std::fs::File, _mode: u32) -> io::Result<()> {
    Ok(())
}

fn parent<'a>(parents: &'a BTreeMap<String, Dir>, path: &str) -> &'a Dir {
    parents
        .get(path)
        .expect("all parent handles were checked before application")
}

fn final_name(path: &str) -> &std::ffi::OsStr {
    Path::new(path)
        .file_name()
        .expect("verified workspace paths have a final component")
}

fn path_error(path: &str, source: io::Error) -> ApplyWritePlanError {
    ApplyWritePlanError::Path {
        path: path.into(),
        source,
    }
}

#[derive(Debug)]
pub enum ApplyWritePlanError {
    MissingParent { path: String },
    Path { path: String, source: io::Error },
}

impl fmt::Display for ApplyWritePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingParent { path } => {
                write!(formatter, "path {path:?} has no verified parent handle")
            }
            Self::Path { path, .. } => write!(formatter, "path {path:?} could not be applied"),
        }
    }
}

impl std::error::Error for ApplyWritePlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingParent { .. } => None,
            Self::Path { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        code_diff_observe::{observe_workspace_write_plan, verify_workspace_write_plan},
        code_diff_staging::ProposedOperation,
    };
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    struct Workspace(std::path::PathBuf);

    impl Workspace {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("muniment-apply-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn plan(&self, operations: &[ProposedOperation]) -> WritePlan {
            observe_workspace_write_plan(&self.0, operations).unwrap().0
        }
    }

    impl Drop for Workspace {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn writes_exact_bytes_and_mode() {
        let workspace = Workspace::new();
        let plan = workspace.plan(&[ProposedOperation::Write {
            path: "file.txt".into(),
            output: b"exact\0bytes".to_vec(),
        }]);
        let verified = verify_workspace_write_plan(&workspace.0, &plan).unwrap();

        apply_workspace_write_plan(&plan, verified).unwrap();

        assert_eq!(
            fs::read(workspace.0.join("file.txt")).unwrap(),
            b"exact\0bytes"
        );
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(workspace.0.join("file.txt"))
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o644
        );
    }

    #[test]
    fn deletes_a_file() {
        let workspace = Workspace::new();
        fs::write(workspace.0.join("file.txt"), b"remove").unwrap();
        let plan = workspace.plan(&[ProposedOperation::Delete {
            path: "file.txt".into(),
        }]);
        let verified = verify_workspace_write_plan(&workspace.0, &plan).unwrap();

        apply_workspace_write_plan(&plan, verified).unwrap();

        assert!(!workspace.0.join("file.txt").exists());
    }

    #[test]
    fn renames_across_parent_directories() {
        let workspace = Workspace::new();
        fs::create_dir_all(workspace.0.join("from")).unwrap();
        fs::create_dir_all(workspace.0.join("to")).unwrap();
        fs::write(workspace.0.join("from/file.txt"), b"move").unwrap();
        let plan = workspace.plan(&[ProposedOperation::Rename {
            source: "from/file.txt".into(),
            target: "to/file.txt".into(),
        }]);
        let verified = verify_workspace_write_plan(&workspace.0, &plan).unwrap();

        apply_workspace_write_plan(&plan, verified).unwrap();

        assert!(!workspace.0.join("from/file.txt").exists());
        assert_eq!(fs::read(workspace.0.join("to/file.txt")).unwrap(), b"move");
    }

    #[test]
    fn rejects_every_missing_handle_before_changes() {
        let workspace = Workspace::new();
        fs::write(workspace.0.join("keep.txt"), b"keep").unwrap();
        let apply_plan = workspace.plan(&[
            ProposedOperation::Delete {
                path: "keep.txt".into(),
            },
            ProposedOperation::Write {
                path: "missing.txt".into(),
                output: b"new".to_vec(),
            },
        ]);
        let other_plan = workspace.plan(&[ProposedOperation::Delete {
            path: "keep.txt".into(),
        }]);
        let verified = verify_workspace_write_plan(&workspace.0, &other_plan).unwrap();

        let error = apply_workspace_write_plan(&apply_plan, verified).unwrap_err();

        assert!(matches!(
            error,
            ApplyWritePlanError::MissingParent { ref path } if path == "missing.txt"
        ));
        assert_eq!(fs::read(workspace.0.join("keep.txt")).unwrap(), b"keep");
    }

    #[test]
    fn filesystem_failure_names_the_path() {
        let workspace = Workspace::new();
        fs::write(workspace.0.join("file.txt"), b"remove").unwrap();
        let plan = workspace.plan(&[ProposedOperation::Delete {
            path: "file.txt".into(),
        }]);
        let verified = verify_workspace_write_plan(&workspace.0, &plan).unwrap();
        fs::remove_file(workspace.0.join("file.txt")).unwrap();

        let error = apply_workspace_write_plan(&plan, verified).unwrap_err();

        assert!(matches!(
            error,
            ApplyWritePlanError::Path { ref path, .. } if path == "file.txt"
        ));
    }
}
