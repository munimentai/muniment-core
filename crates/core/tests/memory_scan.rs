use muniment_core::memory_scan::{
    scan_home_documents, ScanSkipReason, MAX_DIRECTORY_DEPTH, MAX_DOCUMENT_BYTES,
    MAX_DOCUMENT_COUNT,
};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

struct TempHome(PathBuf);

impl TempHome {
    fn new(name: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "muniment-memory-scan-{name}-{}-{nonce}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        for directory in ["memory", "agents", "projects", "sessions"] {
            std::fs::create_dir(path.join(directory)).unwrap();
        }
        Self(path)
    }

    fn write(&self, relative: impl AsRef<Path>, bytes: &[u8]) {
        let path = self.0.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn returns_only_scaffold_markdown_in_sorted_order() {
    let home = TempHome::new("sorted");
    home.write("sessions/z.md", b"last");
    home.write("agents/a.md", b"first");
    home.write("memory/nested/b.md", b"middle");
    home.write("memory/no.txt", b"ignored");
    home.write("outside.md", b"ignored");

    let scan = scan_home_documents(&home.0).unwrap();

    assert_eq!(
        scan.documents
            .iter()
            .map(|document| document.path.to_str().unwrap())
            .collect::<Vec<_>>(),
        ["agents/a.md", "memory/nested/b.md", "sessions/z.md"]
    );
    assert_eq!(scan.documents[0].byte_length, 5);
    assert!(scan.documents[0].modified_at >= UNIX_EPOCH);
    assert!(scan.skipped.is_empty());
    assert!(!scan.cap_dropped_entries());
}

#[test]
fn reports_the_file_count_cap() {
    let home = TempHome::new("count");
    let excess_count = 1_001;
    for number in (0..MAX_DOCUMENT_COUNT + excess_count).rev() {
        home.write(format!("memory/{number:05}.md"), b"x");
    }

    let scan = scan_home_documents(&home.0).unwrap();

    assert_eq!(scan.documents.len(), MAX_DOCUMENT_COUNT);
    assert_eq!(
        scan.documents.last().unwrap().path,
        Path::new("memory/09999.md")
    );
    assert!(scan.skipped.is_empty());
    assert_eq!(scan.file_count_dropped, excess_count);
    assert!(scan.cap_dropped_entries());
}

#[test]
fn reports_the_file_byte_cap_and_invalid_utf8() {
    let home = TempHome::new("content");
    home.write(
        "memory/large.md",
        &vec![b'x'; MAX_DOCUMENT_BYTES as usize + 1],
    );
    home.write("memory/invalid.md", &[0xff]);
    home.write("memory/exact.md", &vec![b'x'; MAX_DOCUMENT_BYTES as usize]);

    let scan = scan_home_documents(&home.0).unwrap();

    assert_eq!(scan.documents.len(), 1);
    assert_eq!(scan.documents[0].path, Path::new("memory/exact.md"));
    assert_eq!(
        scan.skipped
            .iter()
            .map(|skip| (skip.path.to_str().unwrap(), skip.reason))
            .collect::<Vec<_>>(),
        [
            ("memory/invalid.md", ScanSkipReason::InvalidUtf8),
            ("memory/large.md", ScanSkipReason::FileTooLarge),
        ]
    );
    assert!(scan.cap_dropped_entries());
}

#[test]
fn reports_the_directory_depth_cap() {
    let home = TempHome::new("depth");
    let mut directory = PathBuf::from("memory");
    for _ in 0..=MAX_DIRECTORY_DEPTH {
        directory.push("d");
    }
    home.write(directory.join("too-deep.md"), b"hidden");

    let scan = scan_home_documents(&home.0).unwrap();

    assert!(scan.documents.is_empty());
    assert_eq!(scan.skipped.len(), 1);
    assert_eq!(scan.skipped[0].reason, ScanSkipReason::DirectoryDepthLimit);
    assert!(scan.cap_dropped_entries());
}

#[cfg(unix)]
#[test]
fn refuses_file_and_directory_symlinks() {
    use std::os::unix::fs::symlink;

    let home = TempHome::new("symlinks");
    let outside = TempHome::new("outside");
    outside.write("memory/secret.md", b"secret");
    home.write("memory/visible.md", b"visible");
    symlink(
        outside.0.join("memory/secret.md"),
        home.0.join("memory/file-link.md"),
    )
    .unwrap();
    symlink(outside.0.join("memory"), home.0.join("memory/dir-link")).unwrap();

    let scan = scan_home_documents(&home.0).unwrap();

    assert_eq!(scan.documents.len(), 1);
    assert_eq!(scan.documents[0].path, Path::new("memory/visible.md"));
}

#[cfg(unix)]
#[test]
fn refuses_a_scaffold_directory_symlink() {
    use std::os::unix::fs::symlink;

    let home = TempHome::new("scaffold-link");
    let outside = TempHome::new("scaffold-outside");
    outside.write("memory/secret.md", b"secret");
    std::fs::remove_dir(home.0.join("agents")).unwrap();
    symlink(outside.0.join("memory"), home.0.join("agents")).unwrap();

    let scan = scan_home_documents(&home.0).unwrap();

    assert!(scan.documents.is_empty());
}

#[cfg(unix)]
#[test]
fn preserves_distinct_non_utf8_paths() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let home = TempHome::new("non-utf8-paths");
    let first = PathBuf::from("memory").join(OsString::from_vec(b"note-\x80.md".to_vec()));
    let second = PathBuf::from("memory").join(OsString::from_vec(b"note-\x81.md".to_vec()));
    home.write(&first, b"first");
    home.write(&second, b"second");

    let scan = scan_home_documents(&home.0).unwrap();

    assert_eq!(scan.documents.len(), 2);
    assert_eq!(scan.documents[0].path, first);
    assert_eq!(scan.documents[1].path, second);
    assert_ne!(scan.documents[0].path, scan.documents[1].path);
}
