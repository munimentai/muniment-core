use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_PATH: AtomicU64 = AtomicU64::new(0);

// Keep room for /muniment/attach-v1.sock beneath a 49-byte macOS temp directory.
pub(crate) fn socket_temp_path() -> PathBuf {
    let sequence = NEXT_PATH
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("The test socket path counter overflowed.");
    path_in(&std::env::temp_dir(), std::process::id(), sequence)
}

fn path_in(directory: &Path, process: u32, sequence: u64) -> PathBuf {
    directory.join(format!("mt-{process:x}-{sequence:x}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixListener;

    #[test]
    fn socket_paths_fit_a_49_byte_temp_directory() {
        let directory = PathBuf::from(format!("/tmp/{:0<44}", "muniment"));
        assert_eq!(directory.as_os_str().as_bytes().len(), 49);
        for (process, sequence) in [(0, 0), (u32::MAX, u64::MAX)] {
            let path = path_in(&directory, process, sequence);
            assert!(path.as_os_str().as_bytes().len() < 104);
            assert!(
                path.join("muniment/attach-v1.sock")
                    .as_os_str()
                    .as_bytes()
                    .len()
                    < 104
            );
        }
    }

    #[test]
    fn socket_paths_are_unique_across_threads() {
        let workers: Vec<_> = (0..8)
            .map(|_| {
                std::thread::spawn(|| (0..128).map(|_| socket_temp_path()).collect::<Vec<_>>())
            })
            .collect();
        let mut paths = HashSet::new();
        for worker in workers {
            for path in worker.join().unwrap() {
                assert!(paths.insert(path));
            }
        }
        assert_eq!(paths.len(), 1024);
    }

    #[test]
    fn sockets_bind_under_a_49_byte_temp_directory() {
        let name = socket_temp_path();
        let directory = PathBuf::from(format!(
            "/tmp/{:0<44}",
            name.file_name().unwrap().to_str().unwrap()
        ));
        assert_eq!(directory.as_os_str().as_bytes().len(), 49);
        std::fs::create_dir(&directory).unwrap();
        let direct = path_in(&directory, u32::MAX, u64::MAX);
        let nested = path_in(&directory, u32::MAX - 1, u64::MAX).join("muniment/attach-v1.sock");
        std::fs::create_dir_all(nested.parent().unwrap()).unwrap();
        let first = UnixListener::bind(&direct).unwrap();
        let second = UnixListener::bind(&nested).unwrap();
        drop((first, second));
        std::fs::remove_dir_all(directory).unwrap();
    }
}
