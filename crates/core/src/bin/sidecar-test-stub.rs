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
    if first.as_deref() == Some("--mode") {
        pi_resume(args.collect());
        return;
    }
    match first.as_deref() {
        Some("echo") => echo(),
        Some("json-rpc") => json_rpc(args.next()),
        Some("pi-rpc-interleaved") => pi_rpc_interleaved(),
        Some("pi-chat-queue") => pi_chat_queue(),
        Some("pi-chat-capture") => pi_chat_capture(args.next().unwrap()),
        Some("pi-chat-extension-ui") => pi_chat_extension_ui(args.next().unwrap()),
        Some("pi-chat-late-response") => pi_chat_late_response(),
        Some("pi-session-deferred") => pi_session_deferred(args.next().unwrap(), args.next()),
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

fn pi_resume(args: Vec<String>) {
    if let Ok(path) = std::env::var("PI_RESUME_STUB_ARGS") {
        fs::write(path, args.join("\n")).unwrap();
    }
    let session_file = args
        .windows(2)
        .find(|pair| pair[0] == "--session")
        .map(|pair| std::path::PathBuf::from(&pair[1]))
        .or_else(|| {
            args.windows(2)
                .find(|pair| pair[0] == "--session-dir")
                .map(|pair| {
                    std::path::Path::new(&pair[1])
                        .join(format!("stub-{}.jsonl", std::process::id()))
                })
        })
        .unwrap();
    for line in io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        match request["type"].as_str().unwrap() {
            "get_state" => println!(
                "{}",
                serde_json::json!({
                    "type":"response", "command":"get_state", "success":true,
                    "id":request["id"], "data":{"sessionFile":session_file}
                })
            ),
            "prompt" => {
                if let Ok(path) = std::env::var("PI_RESUME_STUB_REQUESTS") {
                    let mut requests = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .unwrap();
                    writeln!(requests, "{request}").unwrap();
                }
                if !session_file.exists() {
                    if let Some(parent) = session_file.parent() {
                        fs::create_dir_all(parent).unwrap();
                    }
                    fs::write(&session_file, "{}\n").unwrap();
                }
                if let Ok(path) = std::env::var("PI_RESUME_STUB_PROMPTS") {
                    let mut prompts = fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)
                        .unwrap();
                    writeln!(prompts, "{}", request["message"].as_str().unwrap()).unwrap();
                }
                println!(
                    "{}",
                    serde_json::json!({"type":"response", "command":"prompt", "success":true, "id":request["id"]})
                );
                if std::env::var_os("PI_RESUME_STUB_STEER_CAPTURE").is_some() {
                    // Keep the run active until the test sends a steer command.
                } else if let Ok(query) = std::env::var("PI_RESUME_STUB_MEMORY_QUERY") {
                    println!(
                        "{}",
                        serde_json::json!({
                            "type":"extension_ui_request", "id":"memory-1", "method":"editor",
                            "title":"muniment:memory-search",
                            "prefill":serde_json::json!({"query":query}).to_string()
                        })
                    );
                } else {
                    println!(
                        "{}",
                        serde_json::json!({"type":"message_update", "assistantMessageEvent":{"type":"text_delta", "delta":" resumed"}})
                    );
                    println!("{}", serde_json::json!({"type":"agent_end"}));
                }
            }
            "steer" => {
                if let Ok(path) = std::env::var("PI_RESUME_STUB_STEER_CAPTURE") {
                    fs::write(path, request.to_string()).unwrap();
                }
                println!(
                    "{}",
                    serde_json::json!({"type":"response", "command":"steer", "success":true, "id":request["id"]})
                );
                println!(
                    "{}",
                    serde_json::json!({"type":"message_update", "assistantMessageEvent":{"type":"text_delta", "delta":" steered"}})
                );
                println!("{}", serde_json::json!({"type":"agent_end"}));
            }
            "extension_ui_response" => {
                println!(
                    "{}",
                    serde_json::json!({"type":"message_update", "assistantMessageEvent":{"type":"text_delta", "delta":" resumed"}})
                );
                println!("{}", serde_json::json!({"type":"agent_end"}));
            }
            "abort" => println!(
                "{}",
                serde_json::json!({"type":"response", "command":"abort", "success":true, "id":request["id"]})
            ),
            command => panic!("unexpected command: {command}"),
        }
        io::stdout().flush().unwrap();
    }
}

fn pi_session_deferred(session_file: String, cancel_marker: Option<String>) {
    let mut prompt_accepted = false;
    let mut state_calls = 0;
    for line in io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let command = request["type"].as_str().unwrap();
        match command {
            "get_state" => {
                state_calls += 1;
                if prompt_accepted && state_calls >= 3 && cancel_marker.is_none() {
                    fs::write(&session_file, "{}\n").unwrap();
                }
                println!(
                    "{}",
                    serde_json::json!({
                        "type":"response", "command":"get_state", "success":true,
                        "id":request["id"], "data":{"sessionFile":session_file}
                    })
                );
                if prompt_accepted && state_calls == 2 {
                    println!(
                        "{}",
                        serde_json::json!({"type":"message_update",
                        "assistantMessageEvent":{"type":"text_delta", "delta":"buffered"}})
                    );
                }
            }
            "prompt" => {
                prompt_accepted = true;
                println!(
                    "{}",
                    serde_json::json!({"type":"response", "command":"prompt",
                    "success":true, "id":request["id"]})
                );
            }
            "abort" => {
                if let Some(marker) = &cancel_marker {
                    fs::write(marker, "cancelled").unwrap();
                }
                println!(
                    "{}",
                    serde_json::json!({"type":"response", "command":"abort",
                    "success":true, "id":request["id"]})
                );
                println!("{}", serde_json::json!({"type":"cancelled"}));
            }
            _ => unreachable!(),
        }
        io::stdout().flush().unwrap();
    }
}

fn pi_chat_queue() {
    for line in io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let command = request["type"].as_str().unwrap();
        if matches!(command, "steer" | "follow_up") {
            println!("{}", serde_json::json!({"type":"tool_execution_start"}));
        }
        let response_command = if request["message"] == "mismatch" {
            "other"
        } else {
            command
        };
        let success = request["message"] != "failed";
        println!(
            "{}",
            serde_json::json!({
                "type":"response", "command":response_command, "success":success,
                "message":"private upstream detail", "id":request["id"]
            })
        );
        if matches!(command, "steer" | "follow_up") {
            println!(
                "{}",
                serde_json::json!({"type":"message_update", "assistantMessageEvent":{
                    "type":"text_delta", "delta":"still streaming"
                }})
            );
        }
        io::stdout().flush().unwrap();
    }
}

fn pi_chat_capture(output: String) {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        let command = request["type"].as_str().unwrap();
        if command == "prompt" {
            fs::write(&output, line).unwrap();
        }
        println!(
            "{}",
            serde_json::json!({
                "type":"response", "command":command, "success":true, "id":request["id"]
            })
        );
        io::stdout().flush().unwrap();
    }
}

fn pi_chat_extension_ui(output: String) {
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        match request["type"].as_str().unwrap() {
            "get_state" => println!(
                "{}",
                serde_json::json!({
                    "type":"response", "command":"get_state", "success":true, "id":request["id"]
                })
            ),
            "prompt" if request["message"] == "wait" => {
                fs::write(format!("{output}.waiting"), "").unwrap();
                continue;
            }
            "prompt" => println!(
                "{}",
                serde_json::json!({
                    "type":"response", "command":"prompt", "success":true, "id":request["id"]
                })
            ),
            "extension_ui_response" => {
                let mut capture = fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&output)
                    .unwrap();
                writeln!(capture, "{line}").unwrap();
            }
            command => panic!("unexpected command: {command}"),
        }
        io::stdout().flush().unwrap();
    }
}

fn pi_chat_late_response() {
    let mut prompted = false;
    for line in io::stdin().lock().lines() {
        let request: serde_json::Value = serde_json::from_str(&line.unwrap()).unwrap();
        let command = request["type"].as_str().unwrap();
        if command == "prompt" {
            prompted = true;
        } else if command == "get_state" && prompted {
            thread::sleep(Duration::from_millis(25));
        }
        println!(
            "{}",
            serde_json::json!({
                "type":"response", "command":command, "success":true, "id":request["id"]
            })
        );
        if command == "get_state" && prompted {
            println!(
                "{}",
                serde_json::json!({"type":"message_update", "assistantMessageEvent":{
                    "type":"text_delta", "delta":"after late response"
                }})
            );
        }
        io::stdout().flush().unwrap();
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
