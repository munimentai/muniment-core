//! Points the server at the speech runtime libraries beside it. The
//! `sherpa-onnx-sys` build script copies them next to each binary it builds,
//! and a dependency's own link arguments do not reach this binary.

fn main() {
    match std::env::var("CARGO_CFG_TARGET_OS").as_deref() {
        Ok("linux") => println!("cargo:rustc-link-arg-bins=-Wl,-rpath,$ORIGIN"),
        Ok("macos") => println!("cargo:rustc-link-arg-bins=-Wl,-rpath,@executable_path"),
        _ => {}
    }
}
