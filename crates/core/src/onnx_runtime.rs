//! Native access to the bundled ONNX Runtime C API.

use std::ffi::{c_char, CStr};
use std::io::ErrorKind;
use std::path::Path;
use std::ptr::NonNull;

use libloading::Library;

/// The opaque ONNX Runtime API table.
#[repr(C)]
pub struct OrtApi {
    _private: [u8; 0],
}

#[repr(C)]
struct OrtApiBase {
    get_api: unsafe extern "system" fn(version: u32) -> *const OrtApi,
    get_version_string: unsafe extern "system" fn() -> *const c_char,
}

type OrtGetApiBase = unsafe extern "system" fn() -> *const OrtApiBase;

/// A failure to open or use the bundled ONNX Runtime library.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnnxRuntimeError {
    Missing,
    LoadFailed,
    MissingSymbol,
    UnsupportedApiVersion,
}

impl std::fmt::Display for OnnxRuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "ONNX Runtime library is missing"),
            Self::LoadFailed => write!(f, "ONNX Runtime library could not load"),
            Self::MissingSymbol => write!(f, "ONNX Runtime library is missing OrtGetApiBase"),
            Self::UnsupportedApiVersion => write!(f, "ONNX Runtime API version is unsupported"),
        }
    }
}

impl std::error::Error for OnnxRuntimeError {}

/// A loaded ONNX Runtime library and its C API entry points.
pub struct OnnxRuntimeLibrary {
    _library: Library,
    get_api: unsafe extern "system" fn(version: u32) -> *const OrtApi,
    get_version_string: unsafe extern "system" fn() -> *const c_char,
}

impl OnnxRuntimeLibrary {
    /// Opens the ONNX Runtime library at `path`.
    pub fn open(path: &Path) -> Result<Self, OnnxRuntimeError> {
        let exact_path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| OnnxRuntimeError::LoadFailed)?
                .join(path)
        };
        match exact_path.metadata() {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(OnnxRuntimeError::Missing);
            }
            Err(_) => return Err(OnnxRuntimeError::LoadFailed),
        }

        let library = load_library(&exact_path).map_err(|_| OnnxRuntimeError::LoadFailed)?;
        let get_api_base = {
            // SAFETY: The library remains loaded in the returned value, and the requested symbol
            // has the signature declared by the ONNX Runtime C API.
            let symbol = unsafe { library.get::<OrtGetApiBase>(b"OrtGetApiBase\0") }
                .map_err(|_| OnnxRuntimeError::MissingSymbol)?;
            *symbol
        };
        // SAFETY: OrtGetApiBase takes no arguments and remains valid while the library is loaded.
        let api_base = unsafe { get_api_base() };
        let api_base = NonNull::new(api_base.cast_mut()).ok_or(OnnxRuntimeError::MissingSymbol)?;
        // SAFETY: ONNX Runtime returns a pointer to its static OrtApiBase table.
        let api_base = unsafe { api_base.as_ref() };

        Ok(Self {
            _library: library,
            get_api: api_base.get_api,
            get_version_string: api_base.get_version_string,
        })
    }

    /// Returns the loaded ONNX Runtime version string.
    pub fn version(&self) -> String {
        // SAFETY: The function pointer belongs to the loaded library and takes no arguments.
        let version = unsafe { (self.get_version_string)() };
        if version.is_null() {
            return String::new();
        }
        // SAFETY: GetVersionString returns a static, null-terminated string owned by ONNX Runtime.
        unsafe { CStr::from_ptr(version) }
            .to_string_lossy()
            .into_owned()
    }

    /// Returns the C API table for `version`.
    pub fn api(&self, version: u32) -> Result<NonNull<OrtApi>, OnnxRuntimeError> {
        // SAFETY: The function pointer belongs to the loaded library and accepts every u32 value.
        let api = unsafe { (self.get_api)(version) };
        NonNull::new(api.cast_mut()).ok_or(OnnxRuntimeError::UnsupportedApiVersion)
    }
}

#[cfg(not(windows))]
fn load_library(path: &Path) -> Result<Library, libloading::Error> {
    // SAFETY: The caller selects the native library. OnnxRuntimeLibrary keeps it loaded until drop.
    unsafe { Library::new(path) }
}

#[cfg(windows)]
fn load_library(path: &Path) -> Result<Library, libloading::Error> {
    const LOAD_WITH_ALTERED_SEARCH_PATH: u32 = 0x0000_0008;

    // SAFETY: The caller selects the native library. The flag resolves its dependencies beside it.
    let library = unsafe {
        libloading::os::windows::Library::load_with_flags(path, LOAD_WITH_ALTERED_SEARCH_PATH)
    }?;
    Ok(library.into())
}

/// Returns the bundled ONNX Runtime file name for the current platform.
#[cfg(target_os = "linux")]
pub const fn bundled_library_file_name() -> &'static str {
    "libonnxruntime.so"
}

/// Returns the bundled ONNX Runtime file name for the current platform.
#[cfg(target_os = "macos")]
pub const fn bundled_library_file_name() -> &'static str {
    "libonnxruntime.1.24.4.dylib"
}

/// Returns the bundled ONNX Runtime file name for the current platform.
#[cfg(target_os = "windows")]
pub const fn bundled_library_file_name() -> &'static str {
    "onnxruntime.dll"
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn bundled_file_name_matches_the_build_script() {
        let build_script =
            fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("../build.rs")).unwrap();
        assert!(build_script.contains(&format!("\"{}\"", bundled_library_file_name())));
    }

    #[cfg(unix)]
    #[test]
    fn opens_the_committed_library_and_resolves_the_api() {
        let library = OnnxRuntimeLibrary::open(&committed_library_path()).unwrap();

        assert!(library.version().starts_with("1.24.4"));
        assert!(library.api(24).is_ok());
        assert!(matches!(
            library.api(9999),
            Err(OnnxRuntimeError::UnsupportedApiVersion)
        ));
    }

    #[test]
    fn reports_a_missing_library() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("absent-onnx-runtime-library");
        assert!(matches!(
            OnnxRuntimeLibrary::open(&path),
            Err(OnnxRuntimeError::Missing)
        ));
    }

    #[test]
    fn reports_a_file_that_is_not_a_library() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        assert!(matches!(
            OnnxRuntimeLibrary::open(&path),
            Err(OnnxRuntimeError::LoadFailed)
        ));
    }

    #[cfg(unix)]
    fn committed_library_path() -> PathBuf {
        let platform = if cfg!(target_os = "macos") {
            "macos-universal2"
        } else {
            "linux-x86_64"
        };
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../third-party/sherpa-onnx-v1.13.2")
            .join(platform)
            .join(bundled_library_file_name())
    }
}
