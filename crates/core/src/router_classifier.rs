//! Route taxonomy and model metadata contract for the bundled classifier.

#[cfg(not(windows))]
use std::ffi::CString;
use std::ffi::{c_char, c_void, CStr};
use std::path::Path;
use std::ptr;

use crate::onnx_runtime::{
    OnnxRuntimeLibrary, OrtAllocator, OrtApi, OrtEnv, OrtModelMetadata, OrtSession,
    OrtSessionOptions, OrtStatus,
};

/// The metadata key for the classifier's ordered class list.
///
/// Its value is a JSON array of strings in [`ROUTE_CLASSES`] order.
pub const CLASS_LIST_METADATA_KEY: &str = "muniment.router.classes";

/// A route produced by the bundled classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteClass {
    Cloud,
    Local,
    Proxy,
}

impl RouteClass {
    /// Returns the stable model class name.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cloud => "route.cloud",
            Self::Local => "route.local",
            Self::Proxy => "route.proxy",
        }
    }

    /// Parses a stable model class name.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "route.cloud" => Some(Self::Cloud),
            "route.local" => Some(Self::Local),
            "route.proxy" => Some(Self::Proxy),
            _ => None,
        }
    }
}

/// The classifier classes in model-output order.
pub const ROUTE_CLASSES: [RouteClass; 3] =
    [RouteClass::Cloud, RouteClass::Local, RouteClass::Proxy];

/// A failure to validate the classifier class-list metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassListError {
    MalformedJson,
    NotArray,
    WrongCount,
    Reordered,
    UnknownName,
}

impl std::fmt::Display for ClassListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedJson => write!(f, "classifier class list is malformed JSON"),
            Self::NotArray => write!(f, "classifier class list is not an array"),
            Self::WrongCount => write!(f, "classifier class list has the wrong count"),
            Self::Reordered => write!(f, "classifier class list is reordered"),
            Self::UnknownName => write!(f, "classifier class list contains an unknown name"),
        }
    }
}

impl std::error::Error for ClassListError {}

/// A failure to open a router classifier session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterClassifierError {
    Runtime(String),
    InvalidModelPath,
    MissingClassList,
    ClassList(ClassListError),
}

impl std::fmt::Display for RouterClassifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Runtime(message) => write!(f, "ONNX Runtime failed: {message}"),
            Self::InvalidModelPath => write!(f, "classifier model path contains a null character"),
            Self::MissingClassList => write!(f, "classifier class list metadata is missing"),
            Self::ClassList(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for RouterClassifierError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ClassList(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ClassListError> for RouterClassifierError {
    fn from(error: ClassListError) -> Self {
        Self::ClassList(error)
    }
}

/// An open ONNX Runtime session with a validated classifier contract.
pub struct RouterClassifierSession<'library> {
    api: &'library OrtApi,
    session: *mut OrtSession,
    options: *mut OrtSessionOptions,
    env: *mut OrtEnv,
}

impl<'library> RouterClassifierSession<'library> {
    /// Opens `model_path` and validates its ordered class-list metadata.
    pub fn open(
        library: &'library OnnxRuntimeLibrary,
        model_path: &Path,
    ) -> Result<Self, RouterClassifierError> {
        let api = library
            .api(24)
            .map_err(|error| RouterClassifierError::Runtime(error.to_string()))?;
        // SAFETY: The library owns the static API table and outlives the returned session.
        let api = unsafe { api.as_ref() };
        let mut resources = Self {
            api,
            session: ptr::null_mut(),
            options: ptr::null_mut(),
            env: ptr::null_mut(),
        };

        // SAFETY: Every output pointer is valid, and the strings are null terminated.
        unsafe {
            status_result(
                api,
                (api.create_env)(2, c"muniment-router".as_ptr(), &mut resources.env),
            )?;
            status_result(api, (api.create_session_options)(&mut resources.options))?;
            status_result(api, (api.set_intra_op_num_threads)(resources.options, 1))?;
            status_result(api, (api.set_inter_op_num_threads)(resources.options, 1))?;
        }

        let model_path = model_path_for_ort(model_path)?;
        // SAFETY: The resources came from this API table, and the model path is null terminated.
        unsafe {
            status_result(
                api,
                (api.create_session)(
                    resources.env,
                    model_path.as_ptr(),
                    resources.options,
                    &mut resources.session,
                ),
            )?;
        }
        resources.validate_class_list()?;
        Ok(resources)
    }

    fn validate_class_list(&self) -> Result<(), RouterClassifierError> {
        let mut metadata: *mut OrtModelMetadata = ptr::null_mut();
        // SAFETY: The session is valid and metadata points to writable storage.
        unsafe {
            status_result(
                self.api,
                (self.api.session_get_model_metadata)(self.session, &mut metadata),
            )?;
        }
        let metadata = MetadataGuard {
            api: self.api,
            metadata,
        };

        let mut allocator: *mut OrtAllocator = ptr::null_mut();
        // SAFETY: The allocator output points to writable storage.
        unsafe {
            status_result(
                self.api,
                (self.api.get_allocator_with_default_options)(&mut allocator),
            )?;
        }

        let mut value: *mut c_char = ptr::null_mut();
        // SAFETY: All inputs came from this API table, and the key is null terminated.
        unsafe {
            status_result(
                self.api,
                (self.api.model_metadata_lookup_custom_metadata_map)(
                    metadata.metadata,
                    allocator,
                    c"muniment.router.classes".as_ptr(),
                    &mut value,
                ),
            )?;
        }
        if value.is_null() {
            return Err(RouterClassifierError::MissingClassList);
        }

        // SAFETY: ONNX Runtime returns a null-terminated string for a non-null value.
        let validation = unsafe { CStr::from_ptr(value) }
            .to_str()
            .map_err(|_| ClassListError::MalformedJson)
            .and_then(parse_class_list);
        // SAFETY: The default allocator allocated value, which remains valid until this call.
        let free_result = unsafe {
            status_result(
                self.api,
                (self.api.allocator_free)(allocator, value.cast::<c_void>()),
            )
        };
        free_result?;
        validation.map_err(Into::into)
    }
}

impl Drop for RouterClassifierSession<'_> {
    fn drop(&mut self) {
        // SAFETY: Release functions accept null and each pointer came from this API table.
        unsafe {
            (self.api.release_session)(self.session);
            (self.api.release_session_options)(self.options);
            (self.api.release_env)(self.env);
        }
    }
}

struct MetadataGuard<'api> {
    api: &'api OrtApi,
    metadata: *mut OrtModelMetadata,
}

impl Drop for MetadataGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: The release function accepts null and metadata came from this API table.
        unsafe { (self.api.release_model_metadata)(self.metadata) }
    }
}

unsafe fn status_result(api: &OrtApi, status: *mut OrtStatus) -> Result<(), RouterClassifierError> {
    if status.is_null() {
        return Ok(());
    }
    // SAFETY: ONNX Runtime returned a valid status and owns its message until release.
    let message = unsafe { (api.get_error_message)(status) };
    let message = if message.is_null() {
        String::new()
    } else {
        // SAFETY: A non-null status message is a null-terminated string.
        unsafe { CStr::from_ptr(message) }
            .to_string_lossy()
            .into_owned()
    };
    // SAFETY: This status came from the same API table and has not been released.
    unsafe { (api.release_status)(status) };
    Err(RouterClassifierError::Runtime(message))
}

#[cfg(not(windows))]
fn model_path_for_ort(path: &Path) -> Result<CString, RouterClassifierError> {
    use std::os::unix::ffi::OsStrExt;

    CString::new(path.as_os_str().as_bytes()).map_err(|_| RouterClassifierError::InvalidModelPath)
}

#[cfg(windows)]
fn model_path_for_ort(path: &Path) -> Result<Vec<u16>, RouterClassifierError> {
    use std::os::windows::ffi::OsStrExt;

    let mut path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if path.contains(&0) {
        return Err(RouterClassifierError::InvalidModelPath);
    }
    path.push(0);
    Ok(path)
}

/// Validates the JSON-encoded classifier class list.
pub fn parse_class_list(value: &str) -> Result<(), ClassListError> {
    let value: serde_json::Value =
        serde_json::from_str(value).map_err(|_| ClassListError::MalformedJson)?;
    let classes = value.as_array().ok_or(ClassListError::NotArray)?;
    if classes.len() != ROUTE_CLASSES.len() {
        return Err(ClassListError::WrongCount);
    }

    for (value, expected) in classes.iter().zip(ROUTE_CLASSES) {
        let name = value.as_str().ok_or(ClassListError::UnknownName)?;
        let actual = RouteClass::parse(name).ok_or(ClassListError::UnknownName)?;
        if actual != expected {
            return Err(ClassListError::Reordered);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::path::PathBuf;

    use super::*;
    #[cfg(unix)]
    use crate::onnx_runtime::{bundled_library_file_name, OnnxRuntimeLibrary};

    #[test]
    fn accepts_the_ordered_class_list() {
        assert_eq!(
            parse_class_list(r#"["route.cloud","route.local","route.proxy"]"#),
            Ok(())
        );
    }

    #[test]
    fn rejects_malformed_json() {
        assert_eq!(parse_class_list("["), Err(ClassListError::MalformedJson));
    }

    #[test]
    fn rejects_a_non_array_value() {
        assert_eq!(parse_class_list("{}"), Err(ClassListError::NotArray));
    }

    #[test]
    fn rejects_the_wrong_class_count() {
        assert_eq!(
            parse_class_list(r#"["route.cloud","route.local"]"#),
            Err(ClassListError::WrongCount)
        );
    }

    #[test]
    fn rejects_a_reordered_class_list() {
        assert_eq!(
            parse_class_list(r#"["route.local","route.cloud","route.proxy"]"#),
            Err(ClassListError::Reordered)
        );
    }

    #[test]
    fn rejects_an_unknown_class_name() {
        assert_eq!(
            parse_class_list(r#"["route.cloud","route.unknown","route.proxy"]"#),
            Err(ClassListError::UnknownName)
        );
    }

    #[cfg(unix)]
    #[test]
    fn opens_a_model_with_the_contract_class_list() {
        let library = committed_library();
        let model = fixture_path("router-classifier/contract.onnx");

        RouterClassifierSession::open(&library, &model).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_model_with_reordered_metadata() {
        let library = committed_library();
        let model = fixture_path("router-classifier/reordered.onnx");

        assert!(matches!(
            RouterClassifierSession::open(&library, &model),
            Err(RouterClassifierError::ClassList(ClassListError::Reordered))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_a_model_without_class_list_metadata() {
        let library = committed_library();
        let model = fixture_path("asr-native/encoder.int8.onnx");

        assert!(matches!(
            RouterClassifierSession::open(&library, &model),
            Err(RouterClassifierError::MissingClassList)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn reports_the_runtime_message_for_an_invalid_model() {
        let library = committed_library();
        let model = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");

        match RouterClassifierSession::open(&library, &model) {
            Err(RouterClassifierError::Runtime(message)) => assert!(!message.is_empty()),
            _ => panic!("expected a runtime error"),
        };
    }

    #[cfg(unix)]
    fn committed_library() -> OnnxRuntimeLibrary {
        let platform = if cfg!(target_os = "macos") {
            "macos-universal2"
        } else {
            "linux-x86_64"
        };
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../third-party/sherpa-onnx-v1.13.2")
            .join(platform)
            .join(bundled_library_file_name());
        OnnxRuntimeLibrary::open(&path).unwrap()
    }

    #[cfg(unix)]
    fn fixture_path(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name)
    }
}
