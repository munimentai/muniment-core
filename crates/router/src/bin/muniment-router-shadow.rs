//! One bounded JSON request per process. Stdout contains only the response envelope.
use muniment_router::headless::{Error, Request, Router, MAX_REQUEST_BYTES, VERSION};
use serde_json::json;
use std::{io::Read, path::Path};

fn main() {
    let result = run();
    match result {
        Ok(response) => println!("{}", serde_json::to_string(&response).unwrap()),
        Err(error) => {
            println!(
                "{}",
                json!({"version": VERSION, "mode": "shadow", "error": error})
            );
            std::process::exit(1);
        }
    }
}

fn run() -> Result<muniment_router::headless::Response, Error> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 || args[0] != "--state" {
        return Err(Error::InvalidRequest);
    }
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::InvalidRequest)?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(Error::InvalidRequest);
    }
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| Error::InvalidRequest)?;
    Router::open(Path::new(&args[1]))?.handle(request)
}
