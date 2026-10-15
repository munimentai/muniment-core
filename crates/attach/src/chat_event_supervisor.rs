use crate::desktop_client::{DesktopClient, SubscriptionEvent};
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
    mut deliver: impl FnMut(SubscriptionEvent),
) where
    S: ChatEventSupervisorStop,
{
    // Each reconnect resumes after the newest chat event already delivered.
    let mut cursor = None;
    loop {
        if stop.stopped() {
            return;
        }

        if let Some(mut client) = connect() {
            if client.subscribe_chat_events_after(cursor).is_ok() {
                observe(true);
                while let Ok(event) = client.read_subscription_event() {
                    deliver(event);
                }
                cursor = client.chat_cursor().or(cursor);
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
    use super::{serve_chat_events_with, ChatEventSupervisorStop, SubscriptionEvent};
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
        requests: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    }

    impl FixtureStream {
        fn new(events: Vec<Value>) -> Self {
            Self {
                reads: VecDeque::new(),
                events,
                writes: 0,
                requests: Default::default(),
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
                    self.requests.lock().unwrap().push(request["body"].clone());
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
        recorded_client(events, Default::default())
    }

    fn recorded_client(
        events: Vec<Value>,
        requests: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
    ) -> crate::DesktopClient {
        let mut stream = FixtureStream::new(events);
        stream.requests = requests;
        handshake_desktop_client(Box::new(stream), "0.0.1", Duration::from_secs(1)).unwrap()
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
        assert_eq!(
            delivered,
            [SubscriptionEvent::Chat(json!({"message": "hello"}))]
        );
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
        assert_eq!(
            delivered,
            [
                SubscriptionEvent::Chat(json!({"attempt": 1})),
                SubscriptionEvent::Chat(json!({"attempt": 2}))
            ]
        );
        assert!(clients.is_empty());
    }

    #[test]
    fn a_reconnect_resumes_after_the_newest_delivered_event() {
        let stop = StopAfterRetries::new(3);
        let requests = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut clients = VecDeque::from([
            recorded_client(vec![json!({"seq": 7}), json!({"seq": 9})], requests.clone()),
            recorded_client(vec![json!({"text": "no position"})], requests.clone()),
            recorded_client(Vec::new(), requests.clone()),
        ]);

        serve_chat_events_with(
            || clients.pop_front(),
            &stop,
            Duration::ZERO,
            |_| {},
            |_| {},
        );

        assert_eq!(
            *requests.lock().unwrap(),
            [
                json!({"snapshot_chunks": true}),
                json!({"cursor": 9, "snapshot_chunks": true}),
                json!({"cursor": 9, "snapshot_chunks": true}),
            ]
        );
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
