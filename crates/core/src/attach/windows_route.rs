//! Windows attach connection routing.

use std::path::{Path, PathBuf};

use muniment_attach::{decode_frame, Hello};

use super::WindowsPeerReadError;

/// The handler for a new Windows attach connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachConnectionRoute {
    ApprovalPresenter,
    DesktopClient { peer_pid: u32 },
    Companion,
}

/// Injected boundary around the connected peer process read.
pub trait WindowsAttachRouteReader {
    fn peer_process(&self) -> Result<(u32, PathBuf), WindowsPeerReadError>;
}

/// Names the route from the connected peer image path.
pub fn name_windows_attach_connection_route(
    reader: &impl WindowsAttachRouteReader,
    expected_desktop_executable: &Path,
) -> WindowsAttachConnectionRoute {
    let Ok((peer_pid, peer_image_path)) = reader.peer_process() else {
        return WindowsAttachConnectionRoute::Companion;
    };
    if !peer_image_path.is_absolute() || !expected_desktop_executable.is_absolute() {
        return WindowsAttachConnectionRoute::Companion;
    }

    if peer_image_path
        .as_os_str()
        .as_encoded_bytes()
        .eq_ignore_ascii_case(expected_desktop_executable.as_os_str().as_encoded_bytes())
    {
        WindowsAttachConnectionRoute::DesktopClient { peer_pid }
    } else {
        WindowsAttachConnectionRoute::Companion
    }
}

/// Names the final route for a desktop-executable peer from its first frame.
pub fn name_windows_desktop_attach_connection_route(
    peer_pid: u32,
    first_frame: &[u8],
) -> WindowsAttachConnectionRoute {
    let Ok(Some((hello, consumed))) = decode_frame::<Hello>(first_frame) else {
        return WindowsAttachConnectionRoute::Companion;
    };
    if consumed != first_frame.len() {
        return WindowsAttachConnectionRoute::Companion;
    }

    match hello.client.kind.as_str() {
        "desktop" => WindowsAttachConnectionRoute::ApprovalPresenter,
        "desktop-client" => WindowsAttachConnectionRoute::DesktopClient { peer_pid },
        _ => WindowsAttachConnectionRoute::Companion,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubRouteReader(Result<(u32, PathBuf), WindowsPeerReadError>);

    impl WindowsAttachRouteReader for StubRouteReader {
        fn peer_process(&self) -> Result<(u32, PathBuf), WindowsPeerReadError> {
            self.0.clone()
        }
    }

    #[test]
    fn routes_matching_absolute_image_to_desktop_client() {
        let reader = StubRouteReader(Ok((
            42,
            PathBuf::from("/Program Files/Muniment/muniment.exe"),
        )));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::DesktopClient { peer_pid: 42 }
        );
    }

    #[test]
    fn compares_image_paths_without_ascii_case() {
        let reader = StubRouteReader(Ok((
            42,
            PathBuf::from("/PROGRAM FILES/MUNIMENT/MUNIMENT.EXE"),
        )));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::DesktopClient { peer_pid: 42 }
        );
    }

    #[test]
    fn routes_read_failure_to_companion() {
        let reader = StubRouteReader(Err(WindowsPeerReadError));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::Companion
        );
    }

    #[test]
    fn routes_relative_peer_image_to_companion() {
        let reader = StubRouteReader(Ok((42, PathBuf::from("muniment.exe"))));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::Companion
        );
    }

    #[test]
    fn routes_relative_expected_image_to_companion() {
        let reader = StubRouteReader(Ok((
            42,
            PathBuf::from("/Program Files/Muniment/muniment.exe"),
        )));

        assert_eq!(
            name_windows_attach_connection_route(&reader, Path::new("muniment.exe")),
            WindowsAttachConnectionRoute::Companion
        );
    }

    #[test]
    fn routes_mismatched_image_to_companion() {
        let reader = StubRouteReader(Ok((42, PathBuf::from("/Program Files/Other/other.exe"))));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::Companion
        );
    }
}
