//! A stub HTTP server for discovery tests.

use serde_json::Value;

/// Answers each `METHOD /path` it knows with its JSON body and anything
/// else with 404, until the test ends. Answers the base URL.
pub fn serve_routes(routes: Vec<(&'static str, Value)>) -> String {
    use std::io::{BufRead, BufReader, Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let (mut route, mut line, mut length) = (String::new(), String::new(), 0);
            reader.read_line(&mut route).unwrap();
            loop {
                line.clear();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            let mut data = vec![0; length];
            reader.read_exact(&mut data).unwrap();
            let route = route.split(' ').take(2).collect::<Vec<_>>().join(" ");
            let model = serde_json::from_slice::<Value>(&data).ok();
            let key = match &model {
                Some(body) => format!("{route} {}", body["model"].as_str().unwrap_or_default()),
                None => route,
            };
            let (status, body) = match routes.iter().find(|(known, _)| *known == key) {
                Some((_, body)) => ("200 OK", body.to_string()),
                None => ("404 Not Found", String::new()),
            };
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        }
    });
    url
}
