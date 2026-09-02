//! macOS attach connection routing.

use std::path::{Path, PathBuf};

/// The handler for a new macOS attach connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MacosAttachConnectionRoute {
    DesktopClient { peer_pid: u32 },
    Companion,
}

/// Opaque failure from an injected macOS peer read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MacosPeerReadError;

/// Injected boundary around the connected peer process read.
pub trait MacosAttachRouteReader {
    fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError>;
}

/// Names the route from the connected peer image path.
pub fn name_macos_attach_connection_route(
    reader: &impl MacosAttachRouteReader,
    expected_desktop_executable: &Path,
) -> MacosAttachConnectionRoute {
    let Ok((peer_pid, peer_image_path)) = reader.peer_process() else {
        return MacosAttachConnectionRoute::Companion;
    };
    if !peer_image_path.is_absolute() || !expected_desktop_executable.is_absolute() {
        return MacosAttachConnectionRoute::Companion;
    }

    if peer_image_path == expected_desktop_executable {
        MacosAttachConnectionRoute::DesktopClient { peer_pid }
    } else {
        MacosAttachConnectionRoute::Companion
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubRouteReader(Result<(u32, PathBuf), MacosPeerReadError>);

    impl MacosAttachRouteReader for StubRouteReader {
        fn peer_process(&self) -> Result<(u32, PathBuf), MacosPeerReadError> {
            self.0.clone()
        }
    }

    #[test]
    fn routes_matching_absolute_image_to_desktop_client() {
        let reader = StubRouteReader(Ok((
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
        let reader = StubRouteReader(Err(MacosPeerReadError));

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::Companion
        );
    }

    #[test]
    fn routes_relative_peer_image_to_companion() {
        let reader = StubRouteReader(Ok((42, PathBuf::from("muniment"))));

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::Companion
        );
    }

    #[test]
    fn routes_relative_expected_image_to_companion() {
        let reader = StubRouteReader(Ok((
            42,
            PathBuf::from("/Applications/Muniment.app/Contents/MacOS/muniment"),
        )));

        assert_eq!(
            name_macos_attach_connection_route(&reader, Path::new("muniment")),
            MacosAttachConnectionRoute::Companion
        );
    }

    #[test]
    fn routes_mismatched_image_to_companion() {
        let reader = StubRouteReader(Ok((
            42,
            PathBuf::from("/Applications/Other.app/Contents/MacOS/other"),
        )));

        assert_eq!(
            name_macos_attach_connection_route(
                &reader,
                Path::new("/Applications/Muniment.app/Contents/MacOS/muniment")
            ),
            MacosAttachConnectionRoute::Companion
        );
    }
}
