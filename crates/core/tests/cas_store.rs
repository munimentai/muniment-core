use muniment_core::cas::{CasError, ContentHash, LocalCas};
use std::fs::{self, FileTimes};
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "muniment-cas-test-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
}

impl AsRef<Path> for TestDirectory {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn object_path(root: &Path, hash: &ContentHash) -> PathBuf {
    let hash = hash.as_str();
    root.join("objects").join(&hash[..2]).join(&hash[2..])
}

#[test]
fn round_trips_empty_and_multi_megabyte_objects() {
    let root = TestDirectory::new();
    let store = LocalCas::open(root.as_ref()).unwrap();
    let cases = [Vec::new(), vec![0x5a; 3 * 1024 * 1024]];

    for bytes in cases {
        let hash = store.put(&bytes).unwrap();
        let expected = if bytes.is_empty() {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        } else {
            "56a51b0cca174fb964839f3e9db1b904c3b5529e626293ca57a0b1c03c43b53a"
        };
        assert_eq!(hash.as_str(), expected);
        assert_eq!(store.get(&hash).unwrap(), Some(bytes));
        assert!(store.has(&hash).unwrap());
        store.verify(&hash).unwrap();
        assert!(object_path(root.as_ref(), &hash).is_file());
    }
}

#[test]
fn putting_existing_content_is_an_idempotent_no_op() {
    let root = TestDirectory::new();
    let store = LocalCas::open(root.as_ref()).unwrap();
    let hash = store.put(b"same content").unwrap();
    let path = object_path(root.as_ref(), &hash);
    let modified = fs::metadata(&path).unwrap().modified().unwrap();

    assert_eq!(store.put(b"same content").unwrap(), hash);
    assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
}

#[test]
fn verify_distinguishes_corruption_from_absence() {
    let root = TestDirectory::new();
    let store = LocalCas::open(root.as_ref()).unwrap();
    let hash = store.put(b"original").unwrap();
    fs::write(object_path(root.as_ref(), &hash), b"tampered").unwrap();

    assert!(matches!(
        store.verify(&hash),
        Err(CasError::Corrupt { expected, .. }) if expected == hash
    ));

    let missing =
        ContentHash::from_str("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
    assert!(matches!(
        store.verify(&missing),
        Err(CasError::NotFound(found)) if found == missing
    ));
    assert!(!store.has(&missing).unwrap());
    assert_eq!(store.get(&missing).unwrap(), None);
}

#[test]
fn rejects_noncanonical_hashes() {
    assert!(ContentHash::from_str("../outside").is_err());
    assert!(ContentHash::from_str(
        "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855"
    )
    .is_err());
}

#[test]
fn streaming_put_and_open_round_trip_a_large_object() {
    let root = TestDirectory::new();
    let store = LocalCas::open(root.as_ref()).unwrap();
    let bytes = vec![0x37; 3 * 1024 * 1024];

    let hash = store.put_reader(&mut Cursor::new(&bytes)).unwrap();
    let mut actual = Vec::new();
    store
        .open_object(&hash)
        .unwrap()
        .unwrap()
        .read_to_end(&mut actual)
        .unwrap();

    assert_eq!(actual, bytes);
}

#[test]
fn streaming_put_of_existing_content_does_not_replace_it() {
    let root = TestDirectory::new();
    let store = LocalCas::open(root.as_ref()).unwrap();
    let hash = store.put(b"same streamed content").unwrap();
    let path = object_path(root.as_ref(), &hash);
    let modified = fs::metadata(&path).unwrap().modified().unwrap();

    assert_eq!(
        store
            .put_reader(&mut Cursor::new(b"same streamed content"))
            .unwrap(),
        hash
    );
    assert_eq!(fs::metadata(path).unwrap().modified().unwrap(), modified);
}

#[test]
fn opening_store_sweeps_only_stale_root_temp_files() {
    let root = TestDirectory::new();
    let stale = root.as_ref().join(".cas-tmp-crashed");
    let fresh = root.as_ref().join(".cas-tmp-live");
    let object_named_like_temp = root.as_ref().join("objects/.cas-tmp-object");
    fs::create_dir(root.as_ref().join("objects")).unwrap();
    fs::write(&stale, b"stale").unwrap();
    fs::write(&fresh, b"fresh").unwrap();
    fs::write(&object_named_like_temp, b"object").unwrap();
    fs::File::options()
        .write(true)
        .open(&stale)
        .unwrap()
        .set_times(FileTimes::new().set_modified(std::time::UNIX_EPOCH))
        .unwrap();

    LocalCas::open(root.as_ref()).unwrap();

    assert!(!stale.exists());
    assert!(fresh.exists());
    assert!(object_named_like_temp.exists());
}
