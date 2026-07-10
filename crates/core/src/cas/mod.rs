//! Content-addressed local object storage.
//!
//! Objects are named by the lowercase hexadecimal SHA-256 digest of their
//! bytes and stored as `objects/<first two hex characters>/<remaining hex>`.
//! Writes first go to a unique temporary file in the store root, then are
//! atomically published into place; an existing object makes `put` a no-op.

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

static NEXT_TEMP_FILE: AtomicU64 = AtomicU64::new(0);
const COPY_BUFFER_SIZE: usize = 64 * 1024;
const STALE_TEMP_AGE: Duration = Duration::from_secs(24 * 60 * 60);
const TEMP_FILE_PREFIX: &str = ".cas-tmp-";

/// A validated lowercase hexadecimal SHA-256 digest.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ContentHash(String);

impl ContentHash {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ContentHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ContentHash {
    type Err = CasError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(CasError::InvalidHash(value.to_owned()))
        }
    }
}

/// Failures reading or validating the local object store.
#[derive(Debug)]
pub enum CasError {
    Io(std::io::Error),
    InvalidHash(String),
    NotFound(ContentHash),
    Corrupt {
        expected: ContentHash,
        actual: ContentHash,
    },
}

impl fmt::Display for CasError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CasError::Io(error) => write!(f, "object store I/O error: {error}"),
            CasError::InvalidHash(hash) => write!(f, "invalid SHA-256 content hash: {hash}"),
            CasError::NotFound(hash) => write!(f, "object not found: {hash}"),
            CasError::Corrupt { expected, actual } => {
                write!(f, "object {expected} is corrupt (actual hash {actual})")
            }
        }
    }
}

impl std::error::Error for CasError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            CasError::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<std::io::Error> for CasError {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

/// A content-addressed store rooted at a caller-selected directory.
#[derive(Debug)]
pub struct LocalCas {
    root: PathBuf,
}

impl LocalCas {
    pub fn open(root: &Path) -> Result<Self, CasError> {
        fs::create_dir_all(root.join("objects"))?;
        let store = Self {
            root: root.to_owned(),
        };
        store.sweep_stale_temp_files()?;
        Ok(store)
    }

    pub fn put(&self, bytes: &[u8]) -> Result<ContentHash, CasError> {
        self.put_reader(&mut &*bytes)
    }

    /// Streams an object into the store while incrementally computing its hash.
    pub fn put_reader(&self, reader: &mut impl Read) -> Result<ContentHash, CasError> {
        let (temporary, mut file) = self.create_temp_file()?;
        let result = (|| -> Result<ContentHash, CasError> {
            let mut hasher = Sha256::new();
            let mut buffer = [0_u8; COPY_BUFFER_SIZE];
            loop {
                let count = reader.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                file.write_all(&buffer[..count])?;
            }
            file.sync_all()?;
            drop(file);

            let hash = ContentHash(format!("{:x}", hasher.finalize()));
            let destination = self.object_path(&hash);
            fs::create_dir_all(destination.parent().expect("object path has a parent"))?;

            // A hard link publishes the complete file atomically without replacing a
            // winner if another writer installed the same object concurrently.
            match fs::hard_link(&temporary, &destination) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            fs::remove_file(&temporary)?;
            Ok(hash)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub fn get(&self, hash: &ContentHash) -> Result<Option<Vec<u8>>, CasError> {
        match fs::read(self.object_path(hash)) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    /// Opens an object for constant-memory streaming reads.
    pub fn open_object(&self, hash: &ContentHash) -> Result<Option<fs::File>, CasError> {
        match fs::File::open(self.object_path(hash)) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn has(&self, hash: &ContentHash) -> Result<bool, CasError> {
        match fs::metadata(self.object_path(hash)) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error.into()),
        }
    }

    pub fn verify(&self, hash: &ContentHash) -> Result<(), CasError> {
        let mut file = self
            .open_object(hash)?
            .ok_or_else(|| CasError::NotFound(hash.clone()))?;
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; COPY_BUFFER_SIZE];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        let actual = ContentHash(format!("{:x}", hasher.finalize()));
        if actual == *hash {
            Ok(())
        } else {
            Err(CasError::Corrupt {
                expected: hash.clone(),
                actual,
            })
        }
    }

    fn object_path(&self, hash: &ContentHash) -> PathBuf {
        let value = hash.as_str();
        self.root
            .join("objects")
            .join(&value[..2])
            .join(&value[2..])
    }

    fn create_temp_file(&self) -> Result<(PathBuf, fs::File), CasError> {
        loop {
            let sequence = NEXT_TEMP_FILE.fetch_add(1, Ordering::Relaxed);
            let path = self.root.join(format!(
                "{TEMP_FILE_PREFIX}{}-{sequence}",
                std::process::id()
            ));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    fn sweep_stale_temp_files(&self) -> Result<(), CasError> {
        let now = SystemTime::now();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with(TEMP_FILE_PREFIX)
                || !entry.file_type()?.is_file()
            {
                continue;
            }
            let modified = entry.metadata()?.modified()?;
            if now.duration_since(modified).unwrap_or_default() < STALE_TEMP_AGE {
                continue;
            }
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
