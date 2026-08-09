use std::{env, path::PathBuf, process::ExitCode};

use muniment_code_diff::fixtures::{export, Mode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(root) = args.next() else {
        return usage();
    };
    let mode = match args.next() {
        None => Mode::Write,
        Some(flag) if flag == "--check" => Mode::Check,
        Some(_) => return usage(),
    };
    if args.next().is_some() {
        return usage();
    }
    match export(&PathBuf::from(root), mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("code-diff fixtures are not current: {error}");
            ExitCode::FAILURE
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: export-code-diff-fixtures <directory> [--check]");
    ExitCode::from(2)
}
