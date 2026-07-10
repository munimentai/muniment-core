use std::fs;
use std::io::{self, BufRead, Write};
use std::thread;
use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("echo") => echo(),
        Some("json-rpc") => json_rpc(args.next()),
        Some("crash") => std::process::exit(17),
        Some("once") => {
            let marker = args.next().unwrap();
            if fs::create_dir(&marker).is_ok() {
                std::process::exit(18);
            }
            echo();
        }
        Some("probe-once") => {
            let marker = args.next().unwrap();
            let bad = fs::create_dir(&marker).is_ok();
            for line in io::stdin().lock().lines() {
                let line = line.unwrap();
                if line == "ping" && !bad {
                    println!("pong");
                } else if line != "ping" {
                    println!("{line}");
                }
                io::stdout().flush().unwrap();
            }
        }
        Some("pid") => {
            fs::write(args.next().unwrap(), std::process::id().to_string()).unwrap();
            echo();
        }
        Some("hang") => {
            fs::write(args.next().unwrap(), std::process::id().to_string()).unwrap();
            loop {
                thread::sleep(Duration::from_secs(60));
            }
        }
        _ => std::process::exit(2),
    }
}

fn echo() {
    for line in io::stdin().lock().lines() {
        println!("{}", line.unwrap());
        io::stdout().flush().unwrap();
    }
}

fn json_rpc(ping_marker: Option<String>) {
    let stop_answering_ping = ping_marker
        .as_deref()
        .is_some_and(|marker| fs::create_dir(marker).is_ok());
    let mut answered_ping = false;
    for line in io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        if request.get("id").is_none() {
            continue;
        }
        let id = request["id"].clone();
        match request["method"].as_str() {
            Some("ping") if !stop_answering_ping || !answered_ping => {
                answered_ping = true;
                eprintln!("ping");
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc": "2.0", "result": "pong", "id": id})
                );
            }
            Some("ping") => continue,
            Some("delayed") => {
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc": "2.0", "method": "delayed.started"})
                );
                io::stdout().flush().unwrap();
                thread::sleep(Duration::from_millis(100));
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc": "2.0", "result": "delayed", "id": id})
                );
            }
            Some("round_trip") => println!(
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "result": request.get("params").cloned().unwrap_or(serde_json::Value::Null),
                    "id": id
                })
            ),
            Some("fail") => println!(
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32001, "message": "stub failure", "data": {"retry": false}},
                    "id": id
                })
            ),
            Some("malformed") => println!("{{not json"),
            Some("invalid_version") => println!(
                "{}",
                serde_json::json!({"jsonrpc": "1.0", "result": null, "id": id})
            ),
            Some("invalid_shape") => println!(
                "{}",
                serde_json::json!({"jsonrpc": "2.0", "result": null, "error": {"code": 1, "message": "both"}, "id": id})
            ),
            Some("mismatch") => println!(
                "{}",
                serde_json::json!({"jsonrpc": "2.0", "result": null, "id": "wrong"})
            ),
            Some("count") => {
                let count = request["params"]["count"].as_u64().unwrap();
                for value in 0..count {
                    println!(
                        "{}",
                        serde_json::json!({
                            "jsonrpc": "2.0",
                            "method": "count.progress",
                            "params": {"value": value}
                        })
                    );
                }
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc": "2.0", "result": count, "id": id})
                );
            }
            Some("normalized") => {
                print!("\r\n\r\n");
                print!(
                    "{}\r\n",
                    serde_json::json!({"jsonrpc": "2.0", "result": "ok", "id": id})
                );
            }
            Some("timeout") => continue,
            _ => println!(
                "{}",
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32601, "message": "method not found"},
                    "id": id
                })
            ),
        }
        io::stdout().flush().unwrap();
    }
}
