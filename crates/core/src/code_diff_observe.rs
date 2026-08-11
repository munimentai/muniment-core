//! Safe workspace observation for proposed file operations.

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::Dir};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt, io, io::Read, path::Path};

use crate::{
    code_diff_staging::{
        validate_operations, validate_path, ProposedOperation, StageProposedOperationsError,
    },
    write_plan::{
        ObservedPath, ObservedState, StableFileIdentity, WriteOperation, WritePlan, WritePlanError,
    },
};

pub const MAX_CURRENT_FILE_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_CURRENT_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_FILE_MODE: u32 = 0o644;

/// Observes affected paths and returns the exact plan with the current tree.
pub fn observe_workspace_write_plan(
    workspace_root: &Path,
    proposed: &[ProposedOperation],
) -> Result<(WritePlan, BTreeMap<String, Vec<u8>>), ObserveWritePlanError> {
    validate_operations(proposed).map_err(ObserveWritePlanError::InvalidProposal)?;
    let root = Dir::open_ambient_dir(workspace_root, ambient_authority())
        .map_err(|source| ObserveWritePlanError::Workspace { source })?;
    let mut current = BTreeMap::new();
    let mut total = 0u64;
    let mut operations = Vec::with_capacity(proposed.len());

    for operation in proposed {
        operations.push(match operation {
            ProposedOperation::Write { path, output } => {
                let target = observe_path(&root, path, &mut current, &mut total)?;
                let mode = match target.state() {
                    ObservedState::File { mode, .. } => *mode,
                    ObservedState::Absent => DEFAULT_FILE_MODE,
                };
                WriteOperation::Write {
                    target,
                    output: output.clone(),
                    mode,
                }
            }
            ProposedOperation::Rename { source, target } => WriteOperation::Rename {
                source: observe_path(&root, source, &mut current, &mut total)?,
                target: observe_path(&root, target, &mut current, &mut total)?,
            },
            ProposedOperation::Delete { path } => WriteOperation::Delete {
                target: observe_path(&root, path, &mut current, &mut total)?,
            },
        });
    }

    let plan = WritePlan::new(operations).map_err(ObserveWritePlanError::WritePlan)?;
    Ok((plan, current))
}

/// Parent directories that still match every observation in a write plan.
#[derive(Debug)]
pub struct VerifiedWritePlan {
    parents: BTreeMap<String, Dir>,
}

impl VerifiedWritePlan {
    /// Returns the opened parent directory for an affected workspace path.
    pub fn parent(&self, path: &str) -> Option<&Dir> {
        self.parents.get(path)
    }

    /// Returns all opened parent directories, keyed by affected workspace path.
    pub fn into_parents(self) -> BTreeMap<String, Dir> {
        self.parents
    }
}

/// Re-observes a write plan and returns the exact parent handles used by the check.
pub fn verify_workspace_write_plan(
    workspace_root: &Path,
    plan: &WritePlan,
) -> Result<VerifiedWritePlan, VerifyWritePlanError> {
    let root = Dir::open_ambient_dir(workspace_root, ambient_authority()).map_err(|source| {
        VerifyWritePlanError::Observation(ObserveWritePlanError::Workspace { source })
    })?;
    let mut current = BTreeMap::new();
    let mut total = 0u64;
    let mut parents = BTreeMap::new();

    for operation in plan.operations() {
        let paths: [Option<&ObservedPath>; 2] = match operation {
            WriteOperation::Write { target, .. } | WriteOperation::Delete { target } => {
                [Some(target), None]
            }
            WriteOperation::Rename { source, target } => [Some(source), Some(target)],
        };
        for expected in paths.into_iter().flatten() {
            let (observed, parent) =
                observe_path_with_parent(&root, expected.path(), &mut current, &mut total)
                    .map_err(VerifyWritePlanError::Observation)?;
            compare_observed_path(expected, &observed)?;
            parents.insert(expected.path().to_owned(), parent);
        }
    }

    Ok(VerifiedWritePlan { parents })
}

fn compare_observed_path(
    expected: &ObservedPath,
    observed: &ObservedPath,
) -> Result<(), VerifyWritePlanError> {
    let changed = match (expected.state(), observed.state()) {
        (ObservedState::Absent, ObservedState::Absent) => None,
        (ObservedState::Absent, ObservedState::File { .. })
        | (ObservedState::File { .. }, ObservedState::Absent) => Some(StaleDimension::Existence),
        (
            ObservedState::File {
                byte_length: expected_length,
                sha256: expected_sha256,
                mode: expected_mode,
                identity: expected_identity,
            },
            ObservedState::File {
                byte_length,
                sha256,
                mode,
                identity,
            },
        ) => {
            if expected_length != byte_length {
                Some(StaleDimension::ByteLength)
            } else if expected_sha256 != sha256 {
                Some(StaleDimension::Sha256)
            } else if expected_mode != mode {
                Some(StaleDimension::Mode)
            } else if expected_identity != identity {
                Some(StaleDimension::Identity)
            } else {
                None
            }
        }
    };
    let changed = changed.or_else(|| {
        (expected.parent_identity() != observed.parent_identity())
            .then_some(StaleDimension::ParentIdentity)
    });
    match changed {
        Some(dimension) => Err(VerifyWritePlanError::Stale {
            path: expected.path().to_owned(),
            dimension,
        }),
        None => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StaleDimension {
    Existence,
    ByteLength,
    Sha256,
    Mode,
    Identity,
    ParentIdentity,
}

impl fmt::Display for StaleDimension {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Existence => "existence",
            Self::ByteLength => "byte length",
            Self::Sha256 => "SHA-256",
            Self::Mode => "mode",
            Self::Identity => "stable file identity",
            Self::ParentIdentity => "parent identity",
        })
    }
}

#[derive(Debug)]
pub enum VerifyWritePlanError {
    Observation(ObserveWritePlanError),
    Stale {
        path: String,
        dimension: StaleDimension,
    },
}

impl fmt::Display for VerifyWritePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observation(error) => write!(formatter, "write plan check failed: {error}"),
            Self::Stale { path, dimension } => {
                write!(formatter, "path {path:?} changed its {dimension}")
            }
        }
    }
}

impl std::error::Error for VerifyWritePlanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Observation(error) => Some(error),
            Self::Stale { .. } => None,
        }
    }
}

fn observe_path(
    root: &Dir,
    path: &str,
    current: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
) -> Result<ObservedPath, ObserveWritePlanError> {
    observe_path_with_parent(root, path, current, total).map(|(observed, _)| observed)
}

fn observe_path_with_parent(
    root: &Dir,
    path: &str,
    current: &mut BTreeMap<String, Vec<u8>>,
    total: &mut u64,
) -> Result<(ObservedPath, Dir), ObserveWritePlanError> {
    validate_path(path).map_err(ObserveWritePlanError::InvalidProposal)?;
    let relative = Path::new(path);
    let parent_path = relative.parent().unwrap_or_else(|| Path::new(""));
    let mut parent = root.try_clone().map_err(|source| path_io(path, source))?;
    for component in parent_path.components() {
        parent = match parent.open_dir_nofollow(component.as_os_str()) {
            Ok(directory) => directory,
            Err(source) => {
                return Err(classify_open_error(
                    &parent,
                    component.as_os_str(),
                    path,
                    source,
                ))
            }
        };
    }
    let parent_identity = directory_identity(&parent).map_err(|source| path_io(path, source))?;
    let name = relative
        .file_name()
        .expect("validated path has a file name");
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let mut file = match parent.open_with(name, &options) {
        Ok(file) => file.into_std(),
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok((
                ObservedPath::new(path, ObservedState::Absent, parent_identity),
                parent,
            ));
        }
        Err(source) => return Err(classify_open_error(&parent, name, path, source)),
    };
    let metadata = file.metadata().map_err(|source| path_io(path, source))?;
    if !metadata.is_file() {
        return Err(ObserveWritePlanError::NotAFile { path: path.into() });
    }
    let length = metadata.len();
    if length > MAX_CURRENT_FILE_BYTES {
        return Err(ObserveWritePlanError::FileTooLarge { path: path.into() });
    }
    let next_total = total
        .checked_add(length)
        .ok_or_else(|| ObserveWritePlanError::TotalTooLarge { path: path.into() })?;
    if next_total > MAX_CURRENT_TOTAL_BYTES {
        return Err(ObserveWritePlanError::TotalTooLarge { path: path.into() });
    }
    let capacity = usize::try_from(length)
        .map_err(|_| ObserveWritePlanError::FileTooLarge { path: path.into() })?;
    let mut bytes = Vec::with_capacity(capacity);
    file.by_ref()
        .take(MAX_CURRENT_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| path_io(path, source))?;
    if u64::try_from(bytes.len()).ok() != Some(length) {
        return Err(ObserveWritePlanError::ChangedDuringRead { path: path.into() });
    }
    *total = next_total;
    let state = ObservedState::File {
        byte_length: length,
        sha256: Sha256::digest(&bytes).into(),
        mode: file_mode(&metadata),
        identity: file_identity(&file, &metadata).map_err(|source| path_io(path, source))?,
    };
    current.insert(path.into(), bytes);
    Ok((ObservedPath::new(path, state, parent_identity), parent))
}

#[cfg(unix)]
fn file_identity(
    _file: &std::fs::File,
    metadata: &std::fs::Metadata,
) -> io::Result<StableFileIdentity> {
    use std::os::unix::fs::MetadataExt;
    Ok(StableFileIdentity::new(
        metadata.dev(),
        u128::from(metadata.ino()),
    ))
}

#[cfg(windows)]
fn file_identity(
    file: &std::fs::File,
    _metadata: &std::fs::Metadata,
) -> io::Result<StableFileIdentity> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    let file_index =
        (u128::from(information.nFileIndexHigh) << 32) | u128::from(information.nFileIndexLow);
    Ok(StableFileIdentity::new(
        information.dwVolumeSerialNumber.into(),
        file_index,
    ))
}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::MetadataExt;
    metadata.mode() & 0o7777
}

#[cfg(windows)]
fn file_mode(_metadata: &std::fs::Metadata) -> u32 {
    DEFAULT_FILE_MODE
}

#[cfg(unix)]
fn directory_identity(directory: &Dir) -> io::Result<StableFileIdentity> {
    use cap_fs_ext::MetadataExt;
    let metadata = directory.dir_metadata()?;
    Ok(StableFileIdentity::new(
        metadata.dev(),
        u128::from(metadata.ino()),
    ))
}

#[cfg(windows)]
fn directory_identity(directory: &Dir) -> io::Result<StableFileIdentity> {
    let file = directory.try_clone()?.into_std_file();
    let metadata = file.metadata()?;
    file_identity(&file, &metadata)
}

fn path_io(path: &str, source: io::Error) -> ObserveWritePlanError {
    ObserveWritePlanError::Path {
        path: path.into(),
        source,
    }
}

fn classify_open_error(
    parent: &Dir,
    name: &std::ffi::OsStr,
    path: &str,
    source: io::Error,
) -> ObserveWritePlanError {
    if parent
        .symlink_metadata(name)
        .is_ok_and(|metadata| metadata.file_type().is_symlink())
    {
        ObserveWritePlanError::Symlink { path: path.into() }
    } else {
        path_io(path, source)
    }
}

#[derive(Debug)]
pub enum ObserveWritePlanError {
    InvalidProposal(StageProposedOperationsError),
    Workspace { source: io::Error },
    Path { path: String, source: io::Error },
    Symlink { path: String },
    NotAFile { path: String },
    FileTooLarge { path: String },
    TotalTooLarge { path: String },
    ChangedDuringRead { path: String },
    WritePlan(WritePlanError),
}

impl fmt::Display for ObserveWritePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidProposal(error) => write!(formatter, "invalid proposal: {error}"),
            Self::Workspace { .. } => formatter.write_str("the workspace root could not be opened"),
            Self::Path { path, .. } => write!(formatter, "path {path:?} could not be observed"),
            Self::Symlink { path } => write!(formatter, "path {path:?} contains a symlink"),
            Self::NotAFile { path } => write!(formatter, "path {path:?} is not a file"),
            Self::FileTooLarge { path } => {
                write!(formatter, "path {path:?} exceeds the read limit")
            }
            Self::TotalTooLarge { path } => write!(
                formatter,
                "the read total exceeds its limit at path {path:?}"
            ),
            Self::ChangedDuringRead { path } => {
                write!(formatter, "path {path:?} changed while it was read")
            }
            Self::WritePlan(error) => write!(formatter, "invalid write plan: {error}"),
        }
    }
}

impl std::error::Error for ObserveWritePlanError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        cas::LocalCas,
        code_diff_journal::{compose_code_diff_proposal, load_code_diff_proposal},
        journal::RunJournal,
        write_plan::WriteOperation,
    };
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};
    use uuid::Uuid;

    struct TestWorkspace {
        root: std::path::PathBuf,
    }

    impl TestWorkspace {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("muniment-observe-{}", Uuid::now_v7()));
            fs::create_dir(&root).unwrap();
            Self { root }
        }
    }

    impl Drop for TestWorkspace {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root).unwrap();
        }
    }

    fn identity_for_path(path: &Path, metadata: &fs::Metadata) -> StableFileIdentity {
        file_identity(&fs::File::open(path).unwrap(), metadata).unwrap()
    }

    fn delete_plan(workspace: &TestWorkspace, path: &str) -> WritePlan {
        observe_workspace_write_plan(
            &workspace.root,
            &[ProposedOperation::Delete { path: path.into() }],
        )
        .unwrap()
        .0
    }

    fn stale_dimension(error: VerifyWritePlanError) -> StaleDimension {
        match error {
            VerifyWritePlanError::Stale { path, dimension } => {
                assert_eq!(path, "nested/file.txt");
                dimension
            }
            error => panic!("expected stale path error, got {error}"),
        }
    }

    #[test]
    fn observes_operations_and_replays_the_stored_proposal() {
        let workspace = TestWorkspace::new();
        fs::write(workspace.root.join("rewrite.txt"), b"before\n").unwrap();
        fs::write(workspace.root.join("rename.txt"), b"move\n").unwrap();
        fs::write(workspace.root.join("delete.txt"), b"remove\n").unwrap();
        #[cfg(unix)]
        fs::set_permissions(
            workspace.root.join("rewrite.txt"),
            fs::Permissions::from_mode(0o750),
        )
        .unwrap();
        let proposed = vec![
            ProposedOperation::Write {
                path: "rewrite.txt".into(),
                output: b"after\n".to_vec(),
            },
            ProposedOperation::Write {
                path: "new.txt".into(),
                output: b"new\n".to_vec(),
            },
            ProposedOperation::Rename {
                source: "rename.txt".into(),
                target: "moved.txt".into(),
            },
            ProposedOperation::Delete {
                path: "delete.txt".into(),
            },
        ];

        let (plan, current) = observe_workspace_write_plan(&workspace.root, &proposed).unwrap();
        assert_eq!(current.len(), 3);
        let root = Dir::open_ambient_dir(&workspace.root, ambient_authority()).unwrap();
        let parent_identity = directory_identity(&root).unwrap();
        let rewrite_metadata = fs::metadata(workspace.root.join("rewrite.txt")).unwrap();
        match &plan.operations()[0] {
            WriteOperation::Write { target, mode, .. } => {
                assert_eq!(*mode, file_mode(&rewrite_metadata));
                assert_eq!(target.parent_identity(), &parent_identity);
                assert_eq!(
                    target.state(),
                    &ObservedState::File {
                        byte_length: 7,
                        sha256: Sha256::digest(b"before\n").into(),
                        mode: file_mode(&rewrite_metadata),
                        identity: identity_for_path(
                            &workspace.root.join("rewrite.txt"),
                            &rewrite_metadata,
                        ),
                    }
                );
            }
            _ => panic!("expected write"),
        }
        match &plan.operations()[1] {
            WriteOperation::Write { target, mode, .. } => {
                assert_eq!(*mode, DEFAULT_FILE_MODE);
                assert_eq!(target.state(), &ObservedState::Absent);
                assert_eq!(target.parent_identity(), &parent_identity);
            }
            _ => panic!("expected write"),
        }
        match &plan.operations()[2] {
            WriteOperation::Rename { source, target } => {
                let metadata = fs::metadata(workspace.root.join("rename.txt")).unwrap();
                assert_eq!(source.parent_identity(), &parent_identity);
                assert_eq!(
                    source.state(),
                    &ObservedState::File {
                        byte_length: 5,
                        sha256: Sha256::digest(b"move\n").into(),
                        mode: file_mode(&metadata),
                        identity: identity_for_path(&workspace.root.join("rename.txt"), &metadata,),
                    }
                );
                assert_eq!(target.state(), &ObservedState::Absent);
                assert_eq!(target.parent_identity(), &parent_identity);
            }
            _ => panic!("expected rename"),
        }
        match &plan.operations()[3] {
            WriteOperation::Delete { target } => {
                let metadata = fs::metadata(workspace.root.join("delete.txt")).unwrap();
                assert_eq!(target.parent_identity(), &parent_identity);
                assert_eq!(
                    target.state(),
                    &ObservedState::File {
                        byte_length: 7,
                        sha256: Sha256::digest(b"remove\n").into(),
                        mode: file_mode(&metadata),
                        identity: identity_for_path(&workspace.root.join("delete.txt"), &metadata,),
                    }
                );
            }
            _ => panic!("expected delete"),
        }

        let store = TestWorkspace::new();
        let mut journal = RunJournal::open(store.root.join("runs.sqlite3")).unwrap();
        let cas = LocalCas::open(&store.root.join("cas")).unwrap();
        let run_id = Uuid::now_v7().to_string();
        let effect_id = Uuid::now_v7().to_string();
        let diff =
            compose_code_diff_proposal(&plan, &current, &mut journal, &cas, &run_id, &effect_id)
                .unwrap();
        assert_eq!(
            load_code_diff_proposal(&mut journal, &cas, &run_id, &effect_id).unwrap(),
            Some((plan, diff))
        );
    }

    #[test]
    fn verifies_every_path_and_returns_the_observed_parent_handles() {
        let workspace = TestWorkspace::new();
        fs::create_dir(workspace.root.join("nested")).unwrap();
        fs::write(workspace.root.join("nested/source.txt"), b"source").unwrap();
        let proposed = [
            ProposedOperation::Write {
                path: "nested/new.txt".into(),
                output: b"new".to_vec(),
            },
            ProposedOperation::Rename {
                source: "nested/source.txt".into(),
                target: "nested/target.txt".into(),
            },
        ];
        let plan = observe_workspace_write_plan(&workspace.root, &proposed)
            .unwrap()
            .0;

        let verified = verify_workspace_write_plan(&workspace.root, &plan).unwrap();
        assert_eq!(verified.into_parents().len(), 3);
        let verified = verify_workspace_write_plan(&workspace.root, &plan).unwrap();
        let parent = verified.parent("nested/new.txt").unwrap();
        assert!(parent.dir_metadata().unwrap().is_dir());
        assert!(verified.parent("nested/source.txt").is_some());
        assert!(verified.parent("nested/target.txt").is_some());
    }

    #[test]
    fn rejects_changed_existence_byte_length_and_sha256() {
        let workspace = TestWorkspace::new();
        fs::create_dir(workspace.root.join("nested")).unwrap();
        let path = workspace.root.join("nested/file.txt");

        fs::write(&path, b"old").unwrap();
        let plan = delete_plan(&workspace, "nested/file.txt");
        fs::remove_file(&path).unwrap();
        assert_eq!(
            stale_dimension(verify_workspace_write_plan(&workspace.root, &plan).unwrap_err()),
            StaleDimension::Existence
        );

        let plan = observe_workspace_write_plan(
            &workspace.root,
            &[ProposedOperation::Write {
                path: "nested/file.txt".into(),
                output: Vec::new(),
            }],
        )
        .unwrap()
        .0;
        fs::write(&path, b"now present").unwrap();
        assert_eq!(
            stale_dimension(verify_workspace_write_plan(&workspace.root, &plan).unwrap_err()),
            StaleDimension::Existence
        );

        let plan = delete_plan(&workspace, "nested/file.txt");
        fs::write(&path, b"longer contents").unwrap();
        assert_eq!(
            stale_dimension(verify_workspace_write_plan(&workspace.root, &plan).unwrap_err()),
            StaleDimension::ByteLength
        );

        fs::write(&path, b"same").unwrap();
        let plan = delete_plan(&workspace, "nested/file.txt");
        fs::write(&path, b"size").unwrap();
        assert_eq!(
            stale_dimension(verify_workspace_write_plan(&workspace.root, &plan).unwrap_err()),
            StaleDimension::Sha256
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_changed_mode_file_identity_and_parent_identity() {
        let workspace = TestWorkspace::new();
        fs::create_dir(workspace.root.join("nested")).unwrap();
        let path = workspace.root.join("nested/file.txt");
        fs::write(&path, b"same").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let plan = delete_plan(&workspace, "nested/file.txt");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            stale_dimension(verify_workspace_write_plan(&workspace.root, &plan).unwrap_err()),
            StaleDimension::Mode
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let plan = delete_plan(&workspace, "nested/file.txt");
        fs::rename(&path, workspace.root.join("nested/old-file.txt")).unwrap();
        fs::write(&path, b"same").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            stale_dimension(verify_workspace_write_plan(&workspace.root, &plan).unwrap_err()),
            StaleDimension::Identity
        );

        let plan = delete_plan(&workspace, "nested/file.txt");
        fs::rename(
            workspace.root.join("nested"),
            workspace.root.join("old-parent"),
        )
        .unwrap();
        fs::create_dir(workspace.root.join("nested")).unwrap();
        fs::hard_link(
            workspace.root.join("old-parent/file.txt"),
            workspace.root.join("nested/file.txt"),
        )
        .unwrap();
        assert_eq!(
            stale_dimension(verify_workspace_write_plan(&workspace.root, &plan).unwrap_err()),
            StaleDimension::ParentIdentity
        );
    }

    #[cfg(unix)]
    #[test]
    fn stale_check_rejects_new_links() {
        let workspace = TestWorkspace::new();
        fs::create_dir(workspace.root.join("nested")).unwrap();
        fs::write(workspace.root.join("nested/file.txt"), b"same").unwrap();
        let plan = delete_plan(&workspace, "nested/file.txt");
        fs::remove_file(workspace.root.join("nested/file.txt")).unwrap();
        symlink("../outside.txt", workspace.root.join("nested/file.txt")).unwrap();

        assert!(matches!(
            verify_workspace_write_plan(&workspace.root, &plan),
            Err(VerifyWritePlanError::Observation(
                ObserveWritePlanError::Symlink { path }
            )) if path == "nested/file.txt"
        ));
    }

    #[test]
    fn rejects_unsafe_paths_with_the_offending_path() {
        let workspace = TestWorkspace::new();
        for path in [
            "/outside",
            "a//b",
            "a/./b",
            "a/../b",
            "C:",
            "C:relative",
            r"\\?\C:\device",
            r"\\.\device",
        ] {
            let error = observe_workspace_write_plan(
                &workspace.root,
                &[ProposedOperation::Write {
                    path: path.into(),
                    output: Vec::new(),
                }],
            )
            .unwrap_err();
            match error {
                ObserveWritePlanError::InvalidProposal(
                    StageProposedOperationsError::AbsolutePath(offending)
                    | StageProposedOperationsError::EmptyPathComponent(offending)
                    | StageProposedOperationsError::CurrentPathComponent(offending)
                    | StageProposedOperationsError::ParentPathComponent(offending)
                    | StageProposedOperationsError::BackslashInPath(offending),
                ) => assert_eq!(offending, path),
                error => panic!("unexpected error for {path:?}: {error}"),
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_symlink_target() {
        let workspace = TestWorkspace::new();
        fs::write(workspace.root.join("real.txt"), b"real").unwrap();
        symlink("real.txt", workspace.root.join("link.txt")).unwrap();
        let error = observe_workspace_write_plan(
            &workspace.root,
            &[ProposedOperation::Delete {
                path: "link.txt".into(),
            }],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ObserveWritePlanError::Symlink { path } if path == "link.txt"
        ));

        fs::create_dir(workspace.root.join("real-dir")).unwrap();
        symlink("real-dir", workspace.root.join("link-dir")).unwrap();
        let error = observe_workspace_write_plan(
            &workspace.root,
            &[ProposedOperation::Write {
                path: "link-dir/new.txt".into(),
                output: Vec::new(),
            }],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ObserveWritePlanError::Symlink { path } if path == "link-dir/new.txt"
        ));
    }

    #[test]
    fn rejects_a_file_over_the_read_limit() {
        let workspace = TestWorkspace::new();
        let file = fs::File::create(workspace.root.join("large.bin")).unwrap();
        file.set_len(MAX_CURRENT_FILE_BYTES + 1).unwrap();
        let error = observe_workspace_write_plan(
            &workspace.root,
            &[ProposedOperation::Delete {
                path: "large.bin".into(),
            }],
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ObserveWritePlanError::FileTooLarge { path } if path == "large.bin"
        ));
    }

    #[test]
    fn rejects_current_files_over_the_total_read_limit() {
        let workspace = TestWorkspace::new();
        let proposed: Vec<_> = (0..9)
            .map(|index| {
                let path = format!("{index}.bin");
                let file = fs::File::create(workspace.root.join(&path)).unwrap();
                file.set_len(MAX_CURRENT_FILE_BYTES).unwrap();
                ProposedOperation::Delete { path }
            })
            .collect();
        let error = observe_workspace_write_plan(&workspace.root, &proposed).unwrap_err();
        assert!(matches!(
            error,
            ObserveWritePlanError::TotalTooLarge { path } if path == "8.bin"
        ));
    }
}
