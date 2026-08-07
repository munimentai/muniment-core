//! Bounded discovery of Markdown documents under the Muniment Home.

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::{ambient_authority, fs::Dir};
use std::collections::BinaryHeap;
use std::fs;
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

const HOME_DIRECTORIES: [&str; 4] = ["agents", "memory", "projects", "sessions"];

/// Maximum number of documents returned by one scan.
pub const MAX_DOCUMENT_COUNT: usize = 10_000;
/// Maximum byte length of one document (4 MiB).
pub const MAX_DOCUMENT_BYTES: u64 = 4 * 1024 * 1024;
/// Maximum directory depth below a scaffold directory.
pub const MAX_DIRECTORY_DEPTH: usize = 32;

/// Metadata for one indexable Markdown document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HomeDocument {
    pub path: PathBuf,
    pub byte_length: u64,
    pub modified_at: SystemTime,
}

/// Why one filesystem entry did not produce a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScanSkipReason {
    FileCountLimit,
    FileTooLarge,
    DirectoryDepthLimit,
    InvalidUtf8,
}

/// One entry omitted from the scan result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanSkip {
    pub path: PathBuf,
    pub reason: ScanSkipReason,
}

/// The deterministic documents and any entries omitted by a bound or content check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HomeDocumentScan {
    pub documents: Vec<HomeDocument>,
    pub skipped: Vec<ScanSkip>,
    /// Total Markdown files omitted by the file-count cap.
    pub file_count_dropped: usize,
}

impl HomeDocumentScan {
    /// Returns true when a file-count, file-size, or directory-depth cap omitted an entry.
    pub fn cap_dropped_entries(&self) -> bool {
        self.file_count_dropped > 0
            || self.skipped.iter().any(|skip| {
                matches!(
                    skip.reason,
                    ScanSkipReason::FileCountLimit
                        | ScanSkipReason::FileTooLarge
                        | ScanSkipReason::DirectoryDepthLimit
                )
            })
    }
}

/// A stable scan failure kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryScanErrorKind {
    InvalidHome,
    Io,
}

impl std::fmt::Display for MemoryScanErrorKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidHome => "The Muniment Home path is invalid.",
            Self::Io => "The Muniment Home could not be scanned.",
        })
    }
}

impl std::error::Error for MemoryScanErrorKind {}

/// Scans only the four scaffold directories without following symbolic links.
pub fn scan_home_documents(home: &Path) -> Result<HomeDocumentScan, MemoryScanErrorKind> {
    let home = open_home(home)?;
    let mut candidates = BinaryHeap::new();
    let mut skipped = Vec::new();
    let mut file_count_dropped = 0;

    for name in HOME_DIRECTORIES {
        let metadata = match home.symlink_metadata(name) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(MemoryScanErrorKind::Io),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let directory = match home.open_dir_nofollow(name) {
            Ok(directory) => directory,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(MemoryScanErrorKind::Io),
        };
        collect_markdown(
            &directory,
            Path::new(name),
            0,
            &mut candidates,
            &mut skipped,
            &mut file_count_dropped,
        )?;
    }

    let candidates = candidates.into_sorted_vec();

    let mut documents = Vec::new();
    for path in candidates {
        let file = match open_file(&home, &path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(MemoryScanErrorKind::Io),
        };
        let metadata = file.metadata().map_err(|_| MemoryScanErrorKind::Io)?;
        if !metadata.is_file() {
            continue;
        }
        if metadata.len() > MAX_DOCUMENT_BYTES {
            skipped.push(ScanSkip {
                path: path.clone(),
                reason: ScanSkipReason::FileTooLarge,
            });
            continue;
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_DOCUMENT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| MemoryScanErrorKind::Io)?;
        if bytes.len() as u64 > MAX_DOCUMENT_BYTES {
            skipped.push(ScanSkip {
                path: path.clone(),
                reason: ScanSkipReason::FileTooLarge,
            });
            continue;
        }
        if std::str::from_utf8(&bytes).is_err() {
            skipped.push(ScanSkip {
                path: path.clone(),
                reason: ScanSkipReason::InvalidUtf8,
            });
            continue;
        }
        documents.push(HomeDocument {
            path,
            byte_length: bytes.len() as u64,
            modified_at: metadata.modified().map_err(|_| MemoryScanErrorKind::Io)?,
        });
    }
    skipped.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(HomeDocumentScan {
        documents,
        skipped,
        file_count_dropped,
    })
}

fn open_home(home: &Path) -> Result<Dir, MemoryScanErrorKind> {
    let parent = home.parent().ok_or(MemoryScanErrorKind::InvalidHome)?;
    let name = home.file_name().ok_or(MemoryScanErrorKind::InvalidHome)?;
    let parent =
        Dir::open_ambient_dir(parent, ambient_authority()).map_err(|_| MemoryScanErrorKind::Io)?;
    parent.open_dir_nofollow(name).map_err(|error| {
        if error.kind() == io::ErrorKind::InvalidInput {
            MemoryScanErrorKind::InvalidHome
        } else {
            MemoryScanErrorKind::Io
        }
    })
}

fn collect_markdown(
    directory: &Dir,
    relative: &Path,
    depth: usize,
    files: &mut BinaryHeap<PathBuf>,
    skipped: &mut Vec<ScanSkip>,
    file_count_dropped: &mut usize,
) -> Result<(), MemoryScanErrorKind> {
    let entries = directory.entries().map_err(|_| MemoryScanErrorKind::Io)?;
    for entry in entries {
        let entry = entry.map_err(|_| MemoryScanErrorKind::Io)?;
        let kind = entry.file_type().map_err(|_| MemoryScanErrorKind::Io)?;
        let path = relative.join(entry.file_name());
        if kind.is_symlink() {
            continue;
        }
        if kind.is_dir() {
            if depth == MAX_DIRECTORY_DEPTH {
                skipped.push(ScanSkip {
                    path,
                    reason: ScanSkipReason::DirectoryDepthLimit,
                });
                continue;
            }
            let child = match directory.open_dir_nofollow(entry.file_name()) {
                Ok(child) => child,
                Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                Err(_) => return Err(MemoryScanErrorKind::Io),
            };
            collect_markdown(&child, &path, depth + 1, files, skipped, file_count_dropped)?;
        } else if kind.is_file() && path.extension().is_some_and(|extension| extension == "md") {
            if files.len() < MAX_DOCUMENT_COUNT {
                files.push(path);
            } else {
                *file_count_dropped = file_count_dropped.saturating_add(1);
                if files.peek().is_some_and(|largest| path < *largest) {
                    files.pop();
                    files.push(path);
                }
            }
        }
    }
    Ok(())
}

fn open_file(home: &Dir, relative: &Path) -> io::Result<fs::File> {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    let name = relative
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid document path"))?;
    let mut directory = home.try_clone()?;
    for component in parent.components() {
        let Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid document path",
            ));
        };
        directory = directory.open_dir_nofollow(component)?;
    }
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    directory
        .open_with(name, &options)
        .map(|file| file.into_std())
}
