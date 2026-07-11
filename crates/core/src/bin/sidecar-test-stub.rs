use std::fs;
use std::io::{self, BufRead, Write};
use std::thread;
use std::time::Duration;

fn main() {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if first.as_deref() == Some("--model") {
        llama_server_stub(args);
        return;
    }
    match first.as_deref() {
        Some("echo") => echo(),
        Some("json-rpc") => json_rpc(args.next()),
        Some("pi-rpc-interleaved") => pi_rpc_interleaved(),
        Some("pi-rpc-restart-once") => {
            let marker = args.next().unwrap();
            if fs::create_dir(marker).is_ok() {
                for line in io::stdin().lock().lines() {
                    let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
                    if request["type"] != "get_state" {
                        std::process::exit(24);
                    }
                    println!(
                        "{}",
                        serde_json::json!({"type": "response", "command": "get_state", "success": true, "id": request["id"]})
                    );
                    io::stdout().flush().unwrap();
                }
            }
            pi_rpc_interleaved();
        }
        Some("json-rpc-stale-once") => {
            let marker = args.next().unwrap();
            if fs::create_dir(&marker).is_ok() {
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc": "2.0", "result": "stale", "id": "previous"})
                );
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc": "2.0", "method": "stale.progress", "params": {"value": "stale"}})
                );
                io::stdout().flush().unwrap();
                std::process::exit(19);
            }
            eprintln!("replacement-ready");
            io::stderr().flush().unwrap();
            json_rpc(None);
        }
        Some("json-rpc-crash-call-once") => {
            let marker = args.next().unwrap();
            if fs::create_dir(&marker).is_ok() {
                let _ = io::stdin().lock().lines().next();
                std::process::exit(20);
            }
            json_rpc(None);
        }
        Some("crash") => std::process::exit(17),
        Some("stderr-spam") => {
            let count: usize = args.next().unwrap().parse().unwrap();
            for index in 0..count {
                eprintln!("stderr-{index}");
            }
            io::stderr().flush().unwrap();
            println!("stderr-done");
            io::stdout().flush().unwrap();
            echo();
        }
        Some("stderr-generation") => {
            let marker = args.next().unwrap();
            if fs::create_dir(&marker).is_ok() {
                eprintln!("old-generation");
                io::stderr().flush().unwrap();
                std::process::exit(21);
            }
            eprintln!("new-generation");
            io::stderr().flush().unwrap();
            echo();
        }
        Some("stderr-hang") => {
            eprintln!("health failure detail");
            io::stderr().flush().unwrap();
            echo();
        }
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

fn llama_server_stub(args: impl Iterator<Item = String>) {
    let args: Vec<_> = args.collect();
    if let Ok(path) = std::env::var("LLAMA_STUB_ARGS") {
        fs::write(path, args.join("\n")).unwrap();
    }
    if let Ok(marker) = std::env::var("LLAMA_STUB_EXIT_ONCE") {
        if fs::create_dir(marker).is_ok() {
            std::process::exit(23);
        }
    }
    echo();
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
            eprintln!("{request}");
            io::stderr().flush().unwrap();
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
                let delay_ms = request["params"]["delay_ms"].as_u64().unwrap_or(100);
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc": "2.0", "method": "delayed.started"})
                );
                io::stdout().flush().unwrap();
                thread::sleep(Duration::from_millis(delay_ms));
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
            Some("late_success") => delayed_response(
                id,
                serde_json::json!({"jsonrpc": "2.0", "result": "late"}),
                Duration::from_millis(100),
            ),
            Some("late_error") => delayed_response(
                id,
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {"code": -32800, "message": "cancelled"}
                }),
                Duration::from_millis(100),
            ),
            Some("cancel_race") => delayed_response(
                id,
                serde_json::json!({"jsonrpc": "2.0", "result": "raced"}),
                Duration::ZERO,
            ),
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

fn pi_rpc_interleaved() {
    for line in io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let id = request["id"].clone();
        println!(
            "{}",
            serde_json::json!({"type": "agent_start", "requestId": "unrelated"})
        );
        println!(
            "{}",
            serde_json::json!({
                "type": "response",
                "command": request["type"],
                "success": true,
                "id": "another-call"
            })
        );
        println!(
            "{}",
            serde_json::json!({
                "type": "response",
                "command": request["type"],
                "success": true,
                "id": id
            })
        );
        io::stdout().flush().unwrap();
        if request["type"] == "prompt" {
            thread::sleep(Duration::from_millis(10));
            println!(
                "{}",
                serde_json::json!({"type": "message_update", "requestId": "after-response"})
            );
            io::stdout().flush().unwrap();
        }
    }
}

fn delayed_response(id: serde_json::Value, mut response: serde_json::Value, delay: Duration) {
    thread::spawn(move || {
        thread::sleep(delay);
        response["id"] = id;
        println!("{response}");
        io::stdout().flush().unwrap();
    });
}
