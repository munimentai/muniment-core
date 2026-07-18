use std::{env, path::PathBuf, process::ExitCode};

use muniment_attach::fixtures::{export, Mode};

fn main() -> ExitCode {
    let mut args = env::args_os().skip(1);
    let Some(root) = args.next() else {
        eprintln!("usage: export-attach-fixtures <directory> [--check]");
        return ExitCode::from(2);
    };
    let mode = match args.next() {
        None => Mode::Write,
        Some(flag) if flag == "--check" => Mode::Check,
        Some(_) => {
            eprintln!("usage: export-attach-fixtures <directory> [--check]");
            return ExitCode::from(2);
        }
    };
    if args.next().is_some() {
        eprintln!("usage: export-attach-fixtures <directory> [--check]");
        return ExitCode::from(2);
    }
    match export(&PathBuf::from(root), mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("attach fixtures are not current: {error}");
            ExitCode::FAILURE
        }
    }
}
