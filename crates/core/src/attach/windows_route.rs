//! Windows attach connection routing.

use std::path::{Path, PathBuf};

use super::WindowsPeerReadError;

/// The handler for a new Windows attach connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WindowsAttachConnectionRoute {
    DesktopClient,
    Companion,
}

/// Injected boundary around the connected peer image path read.
pub trait WindowsAttachRouteReader {
    fn peer_image_path(&self) -> Result<PathBuf, WindowsPeerReadError>;
}

/// Names the route from the connected peer image path.
pub fn name_windows_attach_connection_route(
    reader: &impl WindowsAttachRouteReader,
    expected_desktop_executable: &Path,
) -> WindowsAttachConnectionRoute {
    let Ok(peer_image_path) = reader.peer_image_path() else {
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
        WindowsAttachConnectionRoute::DesktopClient
    } else {
        WindowsAttachConnectionRoute::Companion
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StubRouteReader(Result<PathBuf, WindowsPeerReadError>);

    impl WindowsAttachRouteReader for StubRouteReader {
        fn peer_image_path(&self) -> Result<PathBuf, WindowsPeerReadError> {
            self.0.clone()
        }
    }

    #[test]
    fn routes_matching_absolute_image_to_desktop_client() {
        let reader = StubRouteReader(Ok(PathBuf::from("/Program Files/Muniment/muniment.exe")));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::DesktopClient
        );
    }

    #[test]
    fn compares_image_paths_without_ascii_case() {
        let reader = StubRouteReader(Ok(PathBuf::from("/PROGRAM FILES/MUNIMENT/MUNIMENT.EXE")));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::DesktopClient
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
        let reader = StubRouteReader(Ok(PathBuf::from("muniment.exe")));

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
        let reader = StubRouteReader(Ok(PathBuf::from("/Program Files/Muniment/muniment.exe")));

        assert_eq!(
            name_windows_attach_connection_route(&reader, Path::new("muniment.exe")),
            WindowsAttachConnectionRoute::Companion
        );
    }

    #[test]
    fn routes_mismatched_image_to_companion() {
        let reader = StubRouteReader(Ok(PathBuf::from("/Program Files/Other/other.exe")));

        assert_eq!(
            name_windows_attach_connection_route(
                &reader,
                Path::new("/Program Files/Muniment/muniment.exe")
            ),
            WindowsAttachConnectionRoute::Companion
        );
    }
}
