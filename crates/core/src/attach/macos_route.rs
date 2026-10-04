//! macOS attach connection routing.

use std::path::{Path, PathBuf};

use muniment_attach::{decode_frame, Hello};

/// The handler for a new macOS attach connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachConnectionRoute {
    ApprovalPresenter,
    DesktopClient { peer_pid: u32 },
    Companion { peer_pid: u32 },
}

/// Opaque failure from an injected macOS peer read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosPeerReadError;

/// Injected boundary around the connected peer process read.
pub trait MacosAttachRouteReader {
    fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError>;

    /// Whether the process that connected satisfies the designated code requirement of
    /// `expected_desktop_executable`. The kernel records the peer's audit token at
    /// connect, and the token's pid version changes on exec, so a process that execs
    /// the desktop binary after it connects never matches.
    fn peer_code_matches(&self, expected_desktop_executable: &Path) -> bool;

    /// Returns payload-free results from the code check for this connection.
    fn code_check_diagnostic(&self) -> serde_json::Value {
        serde_json::Value::Null
    }

    /// Records a payload-free diagnostic when the peer cannot use desktop routes.
    fn log_companion_fallback(
        &self,
        _peer_pid: u32,
        _path_match: bool,
        _peer_image_path: Option<&Path>,
        _expected_desktop_executable: &Path,
    ) {
    }
}

/// Names the route from the connected peer's code identity.
pub fn name_macos_attach_connection_route(
    reader: &impl MacosAttachRouteReader,
    expected_desktop_executable: &Path,
) -> MacosAttachConnectionRoute {
    let Ok((peer_pid, peer_image_path)) = reader.peer_process() else {
        reader.log_companion_fallback(0, false, None, expected_desktop_executable);
        return MacosAttachConnectionRoute::Companion { peer_pid: 0 };
    };
    let resolved_paths =
        if peer_image_path.is_absolute() && expected_desktop_executable.is_absolute() {
            peer_image_path
                .canonicalize()
                .ok()
                .zip(expected_desktop_executable.canonicalize().ok())
        } else {
            None
        };
    let path_match = resolved_paths
        .as_ref()
        .is_some_and(|(peer, expected)| peer == expected);
    // Chromium can run an identical signed bundle from a code-sign clone.
    // Paths must resolve, but only the audit-token code check admits the peer.
    if peer_pid != 0
        && resolved_paths.is_some()
        && reader.peer_code_matches(expected_desktop_executable)
    {
        MacosAttachConnectionRoute::DesktopClient { peer_pid }
    } else {
        reader.log_companion_fallback(
            peer_pid,
            path_match,
            Some(&peer_image_path),
            expected_desktop_executable,
        );
        MacosAttachConnectionRoute::Companion { peer_pid }
    }
}

/// Names the final route for a desktop-executable peer from its first frame.
pub fn name_macos_desktop_attach_connection_route(
    peer_pid: u32,
    first_frame: &[u8],
) -> MacosAttachConnectionRoute {
    let Ok(Some((hello, consumed))) = decode_frame::<Hello>(first_frame) else {
        return MacosAttachConnectionRoute::Companion { peer_pid };
    };
    if consumed != first_frame.len() {
        return MacosAttachConnectionRoute::Companion { peer_pid };
    }

    match hello.client.kind.as_str() {
        "desktop" => MacosAttachConnectionRoute::ApprovalPresenter,
        "desktop-client" => MacosAttachConnectionRoute::DesktopClient { peer_pid },
        _ => MacosAttachConnectionRoute::Companion { peer_pid },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    struct Bundle {
        root: PathBuf,
        executable: PathBuf,
    }

    impl Bundle {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("muniment-macos-route-{}", uuid::Uuid::new_v4()));
            let executable = root.join("Muniment.app/Contents/MacOS/muniment");
            std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
            std::fs::write(&executable, b"desktop fixture").unwrap();
            Self { root, executable }
        }
    }

    impl Drop for Bundle {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.root).unwrap();
        }
    }

    struct StubRouteReader {
        peer: Result<(u32, PathBuf), MacosPeerReadError>,
        code_matches: bool,
        checked: RefCell<Option<PathBuf>>,
    }

    impl StubRouteReader {
        fn signed(peer: Result<(u32, PathBuf), MacosPeerReadError>) -> Self {
            Self {
                peer,
                code_matches: true,
                checked: RefCell::new(None),
            }
        }
    }

    impl MacosAttachRouteReader for StubRouteReader {
        fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
            self.peer.clone()
        }

        fn peer_code_matches(&self, expected: &Path) -> bool {
            *self.checked.borrow_mut() = Some(expected.to_owned());
            self.code_matches
        }
    }

    #[test]
    fn reports_failed_desktop_checks_without_admitting_the_peer() {
        use std::cell::Cell;

        #[derive(Debug, PartialEq)]
        struct Fallback {
            pid: u32,
            path_match: bool,
            peer: Option<PathBuf>,
            expected: PathBuf,
        }

        struct Reader {
            peer: Result<(u32, PathBuf), MacosPeerReadError>,
            code_matches: bool,
            checked: Cell<bool>,
            fallback: RefCell<Option<Fallback>>,
        }
        impl MacosAttachRouteReader for Reader {
            fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
                self.peer.clone()
            }

            fn peer_code_matches(&self, _: &Path) -> bool {
                self.checked.set(true);
                self.code_matches
            }

            fn log_companion_fallback(
                &self,
                pid: u32,
                path_match: bool,
                peer_image_path: Option<&Path>,
                expected_desktop_executable: &Path,
            ) {
                *self.fallback.borrow_mut() = Some(Fallback {
                    pid,
                    path_match,
                    peer: peer_image_path.map(Path::to_owned),
                    expected: expected_desktop_executable.to_owned(),
                });
            }
        }
        let bundle = Bundle::new();
        let expected = bundle.executable.as_path();
        for (path, code_matches, path_match) in [
            (Some(expected), false, true),
            (
                Some(Path::new("/Applications/Other.app/Contents/MacOS/other")),
                false,
                false,
            ),
            (Some(Path::new("muniment")), true, false),
            (Some(Path::new("")), true, false),
            (None, true, false),
        ] {
            let peer_pid = if path.is_some() { 42 } else { 0 };
            let reader = Reader {
                peer: path
                    .map(|path| (peer_pid, path.to_owned()))
                    .ok_or(MacosPeerReadError),
                code_matches,
                checked: Cell::new(false),
                fallback: RefCell::new(None),
            };
            assert_eq!(
                name_macos_attach_connection_route(&reader, expected),
                MacosAttachConnectionRoute::Companion { peer_pid }
            );
            assert_eq!(reader.checked.get(), path_match);
            assert_eq!(
                *reader.fallback.borrow(),
                Some(Fallback {
                    pid: peer_pid,
                    path_match,
                    peer: path.map(Path::to_owned),
                    expected: expected.to_owned(),
                })
            );
        }
    }

    #[test]
    fn routes_a_matching_path_without_the_code_signature_to_companion() {
        let bundle = Bundle::new();
        let mut reader = StubRouteReader::signed(Ok((42, bundle.executable.clone())));
        reader.code_matches = false;

        assert_eq!(
            name_macos_attach_connection_route(&reader, &bundle.executable),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
        assert_eq!(*reader.checked.borrow(), Some(bundle.executable.clone()));
    }

    #[test]
    fn routes_matching_absolute_image_to_desktop_client() {
        let bundle = Bundle::new();
        let reader = StubRouteReader::signed(Ok((42, bundle.executable.clone())));

        assert_eq!(
            name_macos_attach_connection_route(&reader, &bundle.executable),
            MacosAttachConnectionRoute::DesktopClient { peer_pid: 42 }
        );
        assert_eq!(*reader.checked.borrow(), Some(bundle.executable.clone()));
    }

    #[test]
    fn routes_read_failure_to_companion() {
        let reader = StubRouteReader::signed(Err(MacosPeerReadError));

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::Companion { peer_pid: 0 }
        );
        assert_eq!(*reader.checked.borrow(), None);
    }

    #[test]
    fn routes_relative_peer_image_to_companion() {
        let bundle = Bundle::new();
        let reader = StubRouteReader::signed(Ok((42, PathBuf::from("muniment"))));

        assert_eq!(
            name_macos_attach_connection_route(&reader, &bundle.executable),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
    }

    #[test]
    fn routes_relative_expected_image_to_companion() {
        let bundle = Bundle::new();
        let reader = StubRouteReader::signed(Ok((42, bundle.executable.clone())));

        assert_eq!(
            name_macos_attach_connection_route(&reader, Path::new("muniment")),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
    }

    #[test]
    fn routes_an_unrelated_signed_image_to_companion() {
        let bundle = Bundle::new();
        let other = Bundle::new();
        let mut reader = StubRouteReader::signed(Ok((42, other.executable.clone())));
        reader.code_matches = false;

        assert_eq!(
            name_macos_attach_connection_route(&reader, &bundle.executable),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
        assert_eq!(*reader.checked.borrow(), Some(bundle.executable.clone()));
    }

    #[test]
    fn routes_a_code_sign_clone_only_when_its_code_matches() {
        let bundle = Bundle::new();
        let clone = bundle.root.join(
            "X/ai.muniment.desktop.code_sign_clone/code_sign_clone.fixture/muniment.app.bundle/Contents/MacOS/muniment",
        );
        std::fs::create_dir_all(clone.parent().unwrap()).unwrap();
        std::fs::copy(&bundle.executable, &clone).unwrap();
        assert_ne!(
            clone.canonicalize().unwrap(),
            bundle.executable.canonicalize().unwrap()
        );

        // The runtime can also run from the clone.
        for (peer, expected) in [(&clone, &bundle.executable), (&bundle.executable, &clone)] {
            for code_matches in [true, false] {
                let mut reader = StubRouteReader::signed(Ok((42, peer.clone())));
                reader.code_matches = code_matches;
                assert_eq!(
                    name_macos_attach_connection_route(&reader, expected),
                    if code_matches {
                        MacosAttachConnectionRoute::DesktopClient { peer_pid: 42 }
                    } else {
                        MacosAttachConnectionRoute::Companion { peer_pid: 42 }
                    }
                );
                assert_eq!(*reader.checked.borrow(), Some(expected.clone()));
            }
        }
    }

    #[test]
    fn routes_a_zero_pid_to_companion_without_a_code_check() {
        let bundle = Bundle::new();
        let reader = StubRouteReader::signed(Ok((0, bundle.executable.clone())));
        assert_eq!(
            name_macos_attach_connection_route(&reader, &bundle.executable),
            MacosAttachConnectionRoute::Companion { peer_pid: 0 }
        );
        assert_eq!(*reader.checked.borrow(), None);
    }

    #[test]
    fn routes_unresolvable_paths_to_companion_without_a_code_check() {
        let bundle = Bundle::new();
        let missing = bundle.root.join("missing");
        for (peer, expected) in [
            (&missing, &bundle.executable),
            (&bundle.executable, &missing),
            (&missing, &missing),
        ] {
            let reader = StubRouteReader::signed(Ok((42, peer.clone())));
            assert_eq!(
                name_macos_attach_connection_route(&reader, expected),
                MacosAttachConnectionRoute::Companion { peer_pid: 42 }
            );
            assert_eq!(*reader.checked.borrow(), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn routes_a_symlinked_bundle_location_only_after_the_code_check() {
        let bundle = Bundle::new();
        let location = bundle.root.join("linked-location");
        std::os::unix::fs::symlink(&bundle.root, &location).unwrap();
        let linked = location.join("Muniment.app/Contents/MacOS/muniment");
        let canonical = bundle.executable.canonicalize().unwrap();
        assert_ne!(linked, canonical);

        for (peer, expected) in [(&canonical, &linked), (&linked, &canonical)] {
            for code_matches in [true, false] {
                let mut reader = StubRouteReader::signed(Ok((42, peer.clone())));
                reader.code_matches = code_matches;
                assert_eq!(
                    name_macos_attach_connection_route(&reader, expected),
                    if code_matches {
                        MacosAttachConnectionRoute::DesktopClient { peer_pid: 42 }
                    } else {
                        MacosAttachConnectionRoute::Companion { peer_pid: 42 }
                    }
                );
                assert_eq!(*reader.checked.borrow(), Some(expected.clone()));
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn routes_broken_and_looping_symlinks_to_companion() {
        let bundle = Bundle::new();
        let broken = bundle.root.join("broken");
        let looping = bundle.root.join("looping");
        std::os::unix::fs::symlink(bundle.root.join("missing"), &broken).unwrap();
        std::os::unix::fs::symlink(&looping, &looping).unwrap();

        for path in [&broken, &looping] {
            for (peer, expected) in [
                (path, &bundle.executable),
                (&bundle.executable, path),
                (path, path),
            ] {
                let reader = StubRouteReader::signed(Ok((42, peer.clone())));
                assert_eq!(
                    name_macos_attach_connection_route(&reader, expected),
                    MacosAttachConnectionRoute::Companion { peer_pid: 42 }
                );
                assert_eq!(*reader.checked.borrow(), None);
            }
        }
    }
}
