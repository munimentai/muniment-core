use muniment_core::attach::{
    new_windows_attach_pipe_suffix, validate_windows_attach_pipe_path,
    windows_attach_pipe_name_file, windows_attach_pipe_path, WindowsPipePathError,
};
use std::path::Path;

const SUFFIX: &str = "0123456789abcdef0123456789abcdef";

#[test]
fn derives_fixed_pipe_path_vectors() {
    assert_eq!(
        windows_attach_pipe_path("S-1-5-18", SUFFIX),
        Ok(format!(
            r"\\.\pipe\Muniment\attach-v1-593347bdfcc9bfa79cc97429b1142748-{SUFFIX}"
        ))
    );
    assert_eq!(
        windows_attach_pipe_path("S-1-5-21-1000-2000-3000-1001", SUFFIX),
        Ok(format!(
            r"\\.\pipe\Muniment\attach-v1-d07be4ed31604e9cffdf438d2cfe7cd8-{SUFFIX}"
        ))
    );
}

#[test]
fn normalizes_canonical_sid_hex_digit_case() {
    let lowercase = windows_attach_pipe_path("S-1-0xabcdef123456-1", SUFFIX).unwrap();
    let uppercase = windows_attach_pipe_path("S-1-0xABCDEF123456-1", SUFFIX).unwrap();

    assert_eq!(lowercase, uppercase);
    assert_eq!(
        lowercase,
        format!(r"\\.\pipe\Muniment\attach-v1-12c24b93051c284f71935c05e4513f75-{SUFFIX}")
    );
}

#[test]
fn rejects_non_canonical_sids() {
    for sid in [
        "",
        "s-1-5-21-1",
        "S-2-5-21-1",
        "S-1-5",
        "S-1-05-21-1",
        "S-1-5-021-1",
        "S-1-5-4294967296",
        "S-1-281474976710656-1",
        "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
    ] {
        assert_eq!(
            windows_attach_pipe_path(sid, SUFFIX),
            Err(WindowsPipePathError::InvalidSid),
            "{sid}"
        );
    }
}

#[test]
fn generates_and_validates_a_random_suffix() {
    let first = new_windows_attach_pipe_suffix().unwrap();
    let second = new_windows_attach_pipe_suffix().unwrap();
    assert_ne!(first, second);
    let path = windows_attach_pipe_path("S-1-5-18", &first).unwrap();
    assert_eq!(
        validate_windows_attach_pipe_path("S-1-5-18", &path),
        Ok(path.clone())
    );
    // A stored path for another user, or with a malformed suffix, is refused.
    assert_eq!(
        validate_windows_attach_pipe_path("S-1-5-21-1000-2000-3000-1001", &path),
        Err(WindowsPipePathError::InvalidPath)
    );
    for suffix in ["", "0123", &SUFFIX.to_uppercase(), &format!("{SUFFIX}0")] {
        assert_eq!(
            windows_attach_pipe_path("S-1-5-18", suffix),
            Err(WindowsPipePathError::InvalidSuffix),
            "{suffix}"
        );
    }
}

#[test]
fn names_the_pipe_name_file_under_local_app_data() {
    assert_eq!(
        windows_attach_pipe_name_file(Path::new("local")),
        Path::new("local")
            .join("ai.muniment.desktop")
            .join("attach-pipe-name")
    );
}
