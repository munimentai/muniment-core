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
}

/// Names the route from the connected peer image path.
pub fn name_macos_attach_connection_route(
    reader: &impl MacosAttachRouteReader,
    expected_desktop_executable: &Path,
) -> MacosAttachConnectionRoute {
    let Ok((peer_pid, peer_image_path)) = reader.peer_process() else {
        return MacosAttachConnectionRoute::Companion { peer_pid: 0 };
    };
    if !peer_image_path.is_absolute() || !expected_desktop_executable.is_absolute() {
        return MacosAttachConnectionRoute::Companion { peer_pid };
    }

    if peer_image_path == expected_desktop_executable
        && reader.peer_code_matches(expected_desktop_executable)
    {
        MacosAttachConnectionRoute::DesktopClient { peer_pid }
    } else {
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

    struct StubRouteReader(Result<(u32, PathBuf), MacosPeerReadError>, bool);

    impl StubRouteReader {
        fn signed(peer: Result<(u32, PathBuf), MacosPeerReadError>) -> Self {
            Self(peer, true)
        }
    }

    impl MacosAttachRouteReader for StubRouteReader {
        fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
            self.0.clone()
        }

        fn peer_code_matches(&self, _: &Path) -> bool {
            self.1
        }
    }

    #[test]
    fn routes_a_matching_path_without_the_code_signature_to_companion() {
        let reader = StubRouteReader(
            Ok((
                42,
                PathBuf::from("/Applications/Muniment.app/Contents/MacOS/muniment"),
            )),
            false,
        );

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
    }

    #[test]
    fn routes_matching_absolute_image_to_desktop_client() {
        let reader = StubRouteReader::signed(Ok((
            42,
            PathBuf::from("/Applications/Muniment.app/Contents/MacOS/muniment"),
        )));

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::DesktopClient { peer_pid: 42 }
        );
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
    }

    #[test]
    fn routes_relative_peer_image_to_companion() {
        let reader = StubRouteReader::signed(Ok((42, PathBuf::from("muniment"))));

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
    }

    #[test]
    fn routes_relative_expected_image_to_companion() {
        let reader = StubRouteReader::signed(Ok((
            42,
            PathBuf::from("/Applications/Muniment.app/Contents/MacOS/muniment"),
        )));

        assert_eq!(
            name_macos_attach_connection_route(&reader, Path::new("muniment")),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
    }

    #[test]
    fn routes_mismatched_image_to_companion() {
        let reader = StubRouteReader::signed(Ok((
            42,
            PathBuf::from("/Applications/Other.app/Contents/MacOS/other"),
        )));

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::Companion { peer_pid: 42 }
        );
    }
}
