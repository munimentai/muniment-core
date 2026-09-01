use crate::desktop_client::DesktopClient;
use serde_json::Value;
use std::time::Duration;

pub trait ChatEventSupervisorStop {
    fn stopped(&self) -> bool;

    fn wait_for_retry(&self, retry_interval: Duration) -> bool;
}

pub fn serve_chat_events_with<S>(
    mut connect: impl FnMut() -> Option<DesktopClient>,
    stop: S,
    retry_interval: Duration,
    mut observe: impl FnMut(bool),
    mut deliver: impl FnMut(Value),
) where
    S: ChatEventSupervisorStop,
{
    loop {
        if stop.stopped() {
            return;
        }

        if let Some(mut client) = connect() {
            if client.subscribe_chat_events().is_ok() {
                observe(true);
                while let Ok(event) = client.read_chat_event() {
                    deliver(event);
                }
                observe(false);
            }
        }

        if !stop.wait_for_retry(retry_interval) {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{serve_chat_events_with, ChatEventSupervisorStop};
    use crate::{
        encode_frame, handshake_desktop_client, reconnect_welcome, ClientStream, Event, EventName,
        Id, Protocol, Response, Success,
    };
    use serde_json::{json, Value};
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::{self, Read, Write};
    use std::time::Duration;

    const SUBSCRIPTION_ID: &str = "00000000000000000000000000000190";

    struct FixtureStream {
        reads: VecDeque<u8>,
        events: Vec<Value>,
        writes: usize,
    }

    impl FixtureStream {
        fn new(events: Vec<Value>) -> Self {
            Self {
                reads: VecDeque::new(),
                events,
                writes: 0,
            }
        }

        fn queue<T: serde::Serialize>(&mut self, value: &T) {
            self.reads.extend(encode_frame(value).unwrap());
        }
    }

    impl Read for FixtureStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let count = bytes.len().min(self.reads.len());
            for byte in &mut bytes[..count] {
                *byte = self.reads.pop_front().unwrap();
            }
            Ok(count)
        }
    }

    impl Write for FixtureStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            match self.writes {
                1 => {
                    self.queue(&reconnect_welcome(1, "0.0.1", "11".repeat(16), ""));
                    self.queue(&json!({
                        "profile_id": "profile-1",
                        "capability": "33".repeat(32),
                        "expires_at": 60,
                        "idle_timeout_seconds": 30,
                        "workspace_scopes": {},
                    }));
                }
                2 => {
                    let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
                    let request: Value = serde_json::from_slice(&bytes[4..4 + length]).unwrap();
                    self.queue(&Response {
                        protocol: Protocol,
                        request_id: Id::new(request["request_id"].as_str().unwrap()).unwrap(),
                        ok: Success,
                        body: json!({"subscription_id": SUBSCRIPTION_ID}),
                    });
                    let events = std::mem::take(&mut self.events);
                    for body in events {
                        self.queue(&Event {
                            protocol: Protocol,
                            subscription_id: Id::new(SUBSCRIPTION_ID).unwrap(),
                            event: EventName::ChatEvent,
                            run_id: None,
                            run_seq: None,
                            body,
                        });
                    }
                }
                _ => panic!("unexpected fixture write"),
            }
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ClientStream for FixtureStream {
        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    fn client(events: Vec<Value>) -> crate::DesktopClient {
        handshake_desktop_client(
            Box::new(FixtureStream::new(events)),
            "0.0.1",
            Duration::from_secs(1),
        )
        .unwrap()
    }

    struct StopAfterRetries {
        retries: Cell<usize>,
        retry_limit: usize,
        stopped: Cell<bool>,
    }

    impl StopAfterRetries {
        fn new(retry_limit: usize) -> Self {
            Self {
                retries: Cell::new(0),
                retry_limit,
                stopped: Cell::new(false),
            }
        }
    }

    impl ChatEventSupervisorStop for &StopAfterRetries {
        fn stopped(&self) -> bool {
            self.stopped.get()
        }

        fn wait_for_retry(&self, _retry_interval: Duration) -> bool {
            let retries = self.retries.get() + 1;
            self.retries.set(retries);
            if retries >= self.retry_limit {
                self.stopped.set(true);
                false
            } else {
                true
            }
        }
    }

    #[test]
    fn delivers_events_and_reports_the_subscription() {
        let stop = StopAfterRetries::new(1);
        let mut observed = Vec::new();
        let mut delivered = Vec::new();
        let mut connection = Some(client(vec![json!({"message": "hello"})]));

        serve_chat_events_with(
            || connection.take(),
            &stop,
            Duration::ZERO,
            |connected| observed.push(connected),
            |event| delivered.push(event),
        );

        assert_eq!(observed, [true, false]);
        assert_eq!(delivered, [json!({"message": "hello"})]);
    }

    #[test]
    fn reconnects_after_the_stream_drops() {
        let stop = StopAfterRetries::new(2);
        let mut clients = VecDeque::from([
            client(vec![json!({"attempt": 1})]),
            client(vec![json!({"attempt": 2})]),
        ]);
        let mut observed = Vec::new();
        let mut delivered = Vec::new();

        serve_chat_events_with(
            || clients.pop_front(),
            &stop,
            Duration::ZERO,
            |connected| observed.push(connected),
            |event| delivered.push(event),
        );

        assert_eq!(observed, [true, false, true, false]);
        assert_eq!(delivered, [json!({"attempt": 1}), json!({"attempt": 2})]);
        assert!(clients.is_empty());
    }

    #[test]
    fn returns_when_stopped_during_the_retry_wait() {
        let stop = StopAfterRetries::new(1);
        let connects = Cell::new(0);

        serve_chat_events_with(
            || {
                connects.set(connects.get() + 1);
                None
            },
            &stop,
            Duration::from_secs(60),
            |_| panic!("a failed connection must not report a subscription"),
            |_| panic!("a failed connection must not deliver an event"),
        );

        assert_eq!(connects.get(), 1);
        assert_eq!(stop.retries.get(), 1);
        assert!(stop.stopped.get());
    }
}
