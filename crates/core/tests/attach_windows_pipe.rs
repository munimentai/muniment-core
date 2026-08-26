use muniment_core::attach::{windows_attach_pipe_path, WindowsPipePathError};

#[test]
fn derives_fixed_pipe_path_vectors() {
    assert_eq!(
        windows_attach_pipe_path("S-1-5-18"),
        Ok(r"\\.\pipe\Muniment\attach-v1-593347bdfcc9bfa79cc97429b1142748".to_owned())
    );
    assert_eq!(
        windows_attach_pipe_path("S-1-5-21-1000-2000-3000-1001"),
        Ok(r"\\.\pipe\Muniment\attach-v1-d07be4ed31604e9cffdf438d2cfe7cd8".to_owned())
    );
}

#[test]
fn normalizes_canonical_sid_hex_digit_case() {
    let lowercase = windows_attach_pipe_path("S-1-0xabcdef123456-1").unwrap();
    let uppercase = windows_attach_pipe_path("S-1-0xABCDEF123456-1").unwrap();

    assert_eq!(lowercase, uppercase);
    assert_eq!(
        lowercase,
        r"\\.\pipe\Muniment\attach-v1-12c24b93051c284f71935c05e4513f75"
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
            windows_attach_pipe_path(sid),
            Err(WindowsPipePathError::InvalidSid),
            "{sid}"
        );
    }
}
