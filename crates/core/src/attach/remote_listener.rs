//! The TCP and TLS listener of the remote attach route.
//!
//! The listener is off unless a host binds it. It caps live connections,
//! bounds the TLS handshake and the first frame by deadlines, and holds back
//! a peer address after repeated refused pairing secrets or credentials.
//! Each connection runs on its own thread, like the local listeners.

use std::cell::RefCell;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{Receiver, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use muniment_attach::{TlsReadable, TlsStream};

use super::deadline_io::{read_exact_before, DeadlineStream, ReadableWait};
use super::desktop_admission::write_protocol_error;
use super::remote_access::RemoteAccess;
use super::remote_session::{admit_remote_client, serve_remote_client, RemoteAdmissionError};
use super::remote_settings::is_public_peer;
use super::thread_service::ThreadListService;
use super::{ProtocolError, SignedWorkspaceApproval};

const ACCEPT_POLL_INTERVAL: Duration = Duration::from_millis(25);
/// The largest first frame read before the peer is authenticated. A hello
/// is far smaller, so an unauthenticated peer cannot make the listener hold
/// a full-size frame per connection.
const MAX_HELLO_FRAME_LENGTH: usize = 16 * 1024;

/// Where and how the remote listener serves.
#[derive(Clone, Debug)]
pub struct RemoteListenerConfig {
    pub address: SocketAddr,
    /// The most connections served at once, handshakes included.
    pub max_connections: usize,
    /// The bound on the TLS handshake.
    pub handshake_timeout: Duration,
    /// The bound on the first frame after the handshake.
    pub first_frame_timeout: Duration,
    pub backoff: FailureBackoffPolicy,
    /// Whether peers on public addresses may connect. Off, only loopback,
    /// private LAN and overlay peers reach the handshake.
    pub allow_public: bool,
}

impl RemoteListenerConfig {
    pub fn new(address: SocketAddr) -> Self {
        Self {
            address,
            max_connections: 32,
            handshake_timeout: Duration::from_secs(10),
            first_frame_timeout: Duration::from_secs(5),
            backoff: FailureBackoffPolicy::default(),
            allow_public: false,
        }
    }
}

/// How refused admissions from one peer slow that peer down.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FailureBackoffPolicy {
    /// Refusals a peer may collect before it is held back.
    pub free_attempts: u32,
    /// The first hold. Each later refusal doubles it.
    pub base_delay: Duration,
    pub max_delay: Duration,
    /// How long a peer's refusals are remembered after its last one.
    pub memory: Duration,
}

impl Default for FailureBackoffPolicy {
    fn default() -> Self {
        Self {
            free_attempts: 5,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5 * 60),
            memory: Duration::from_secs(15 * 60),
        }
    }
}

const MAX_TRACKED_PEERS: usize = 4096;

struct PeerFailures {
    count: u32,
    held_until: Instant,
    last: Instant,
}

/// Refused admissions per peer. IPv6 peers count by their /64 prefix, since
/// one host can rotate addresses inside it.
pub struct FailureBackoff {
    policy: FailureBackoffPolicy,
    peers: Mutex<HashMap<IpAddr, PeerFailures>>,
}

impl FailureBackoff {
    pub fn new(policy: FailureBackoffPolicy) -> Self {
        Self {
            policy,
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Whether `peer` may try now.
    pub fn allows(&self, peer: IpAddr, now: Instant) -> bool {
        self.peers()
            .get(&peer_key(peer))
            .is_none_or(|failures| failures.held_until <= now)
    }

    pub fn record_failure(&self, peer: IpAddr, now: Instant) {
        let policy = self.policy;
        let mut peers = self.peers();
        if peers.len() >= MAX_TRACKED_PEERS {
            peers
                .retain(|_, failures| now.saturating_duration_since(failures.last) < policy.memory);
        }
        if peers.len() >= MAX_TRACKED_PEERS {
            // A flood of distinct peers cannot grow the table further. Every
            // new peer is held for the longest delay instead.
            if let Some(oldest) = peers
                .iter()
                .min_by_key(|(_, failures)| failures.last)
                .map(|(peer, _)| *peer)
            {
                peers.remove(&oldest);
            }
        }
        let failures = peers.entry(peer_key(peer)).or_insert(PeerFailures {
            count: 0,
            held_until: now,
            last: now,
        });
        if now.saturating_duration_since(failures.last) >= policy.memory {
            failures.count = 0;
        }
        failures.count = failures.count.saturating_add(1);
        failures.last = now;
        if failures.count >= policy.free_attempts {
            let doublings = (failures.count - policy.free_attempts).min(16);
            let delay = policy
                .base_delay
                .saturating_mul(1 << doublings)
                .min(policy.max_delay);
            failures.held_until = now + delay;
        }
    }

    pub fn record_success(&self, peer: IpAddr) {
        self.peers().remove(&peer_key(peer));
    }

    fn peers(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, PeerFailures>> {
        self.peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn peer_key(peer: IpAddr) -> IpAddr {
    match peer {
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mut segments = address.segments();
                segments[4..].fill(0);
                IpAddr::V6(segments.into())
            }
        },
        v4 => v4,
    }
}

/// A server TLS stream as the attach session sees it. Plaintext rustls
/// already decrypted counts as readable.
pub struct RemoteStream {
    inner: RefCell<TlsStream>,
}

impl RemoteStream {
    pub fn new(stream: TlsStream) -> Self {
        Self {
            inner: RefCell::new(stream),
        }
    }

    pub fn into_inner(self) -> TlsStream {
        self.inner.into_inner()
    }
}

impl Read for RemoteStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.get_mut().read(bytes)
    }
}

impl Write for RemoteStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.get_mut().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.get_mut().flush()
    }
}

impl DeadlineStream for RemoteStream {
    fn wait_until_readable(&self, deadline: Instant) -> ReadableWait {
        match self.inner.borrow_mut().wait_until_readable(deadline) {
            TlsReadable::Ready => ReadableWait::Ready,
            TlsReadable::Timeout => ReadableWait::Timeout,
            TlsReadable::Closed => ReadableWait::Closed,
        }
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.borrow().socket().set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.borrow().socket().set_write_timeout(timeout)
    }
}

/// Why the remote listener stopped serving.
#[derive(Debug)]
pub enum RemoteListenerError {
    Bind(io::Error),
    Accept(io::Error),
}

impl std::fmt::Display for RemoteListenerError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bind(error) => write!(formatter, "remote attach listener bind failed: {error}"),
            Self::Accept(error) => {
                write!(formatter, "remote attach listener accept failed: {error}")
            }
        }
    }
}

impl std::error::Error for RemoteListenerError {}

/// A bound remote listener that has not started serving.
pub struct RemoteListener {
    listener: TcpListener,
    config: RemoteListenerConfig,
}

impl RemoteListener {
    pub fn bind(config: RemoteListenerConfig) -> Result<Self, RemoteListenerError> {
        let listener = TcpListener::bind(config.address).map_err(RemoteListenerError::Bind)?;
        listener
            .set_nonblocking(true)
            .map_err(RemoteListenerError::Bind)?;
        Ok(Self { listener, config })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Serves remote clients until `stop` fires or its sender drops, then
    /// closes every live connection.
    pub fn serve<S, F, E>(
        self,
        access: RemoteAccess,
        approval: SignedWorkspaceApproval,
        service_factory: F,
        stop: Receiver<()>,
    ) -> Result<(), RemoteListenerError>
    where
        S: ThreadListService + 'static,
        F: Fn() -> Result<S, E> + Send + Sync + 'static,
    {
        let shared = Arc::new(Shared {
            access,
            approval,
            service_factory: Box::new(move || service_factory().ok()),
            backoff: FailureBackoff::new(self.config.backoff),
            active: AtomicUsize::new(0),
            next_connection: AtomicU64::new(0),
            live: Mutex::new(HashMap::new()),
            config: self.config,
        });
        let result = loop {
            match stop.try_recv() {
                Ok(()) | Err(TryRecvError::Disconnected) => break Ok(()),
                Err(TryRecvError::Empty) => {}
            }
            let (socket, peer) = match self.listener.accept() {
                Ok(accepted) => accepted,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    std::thread::sleep(ACCEPT_POLL_INTERVAL);
                    continue;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionAborted | io::ErrorKind::ConnectionReset
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    crate::runtime_eprintln!(
                        "muniment-runtime: remote attach accept failed reason={error}"
                    );
                    std::thread::sleep(ACCEPT_POLL_INTERVAL);
                    continue;
                }
            };
            if !shared.config.allow_public && is_public_peer(peer.ip()) {
                crate::runtime_eprintln!(
                    "muniment-runtime: remote attach refused peer={peer} reason=public address"
                );
                continue;
            }
            if !shared.backoff.allows(peer.ip(), Instant::now()) {
                crate::runtime_eprintln!(
                    "muniment-runtime: remote attach refused peer={peer} reason=backoff"
                );
                continue;
            }
            let Some(slot) = ConnectionSlot::claim(&shared) else {
                crate::runtime_eprintln!(
                    "muniment-runtime: remote attach refused peer={peer} reason=connection cap"
                );
                continue;
            };
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || serve_connection(socket, peer, slot, &shared));
        };
        for socket in shared.live().values() {
            let _ = socket.shutdown(std::net::Shutdown::Both);
        }
        result
    }
}

/// Binds `config.address` and serves remote clients until `stop` fires.
pub fn run_remote_listener<S, F, E>(
    config: RemoteListenerConfig,
    access: RemoteAccess,
    approval: SignedWorkspaceApproval,
    service_factory: F,
    stop: Receiver<()>,
) -> Result<(), RemoteListenerError>
where
    S: ThreadListService + 'static,
    F: Fn() -> Result<S, E> + Send + Sync + 'static,
{
    RemoteListener::bind(config)?.serve(access, approval, service_factory, stop)
}

type ServiceFactory<S> = Box<dyn Fn() -> Option<S> + Send + Sync>;

struct Shared<S> {
    access: RemoteAccess,
    approval: SignedWorkspaceApproval,
    service_factory: ServiceFactory<S>,
    backoff: FailureBackoff,
    active: AtomicUsize,
    next_connection: AtomicU64,
    live: Mutex<HashMap<u64, TcpStream>>,
    config: RemoteListenerConfig,
}

impl<S> Shared<S> {
    fn live(&self) -> std::sync::MutexGuard<'_, HashMap<u64, TcpStream>> {
        self.live
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One claimed connection slot, released when the connection ends.
struct ConnectionSlot<S> {
    shared: Arc<Shared<S>>,
    id: u64,
}

impl<S> ConnectionSlot<S> {
    fn claim(shared: &Arc<Shared<S>>) -> Option<Self> {
        if shared.active.fetch_add(1, Ordering::AcqRel) >= shared.config.max_connections {
            shared.active.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self {
            shared: Arc::clone(shared),
            id: shared.next_connection.fetch_add(1, Ordering::Relaxed),
        })
    }
}

impl<S> Drop for ConnectionSlot<S> {
    fn drop(&mut self) {
        self.shared.live().remove(&self.id);
        self.shared.active.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_connection<S: ThreadListService>(
    socket: TcpStream,
    peer: SocketAddr,
    slot: ConnectionSlot<S>,
    shared: &Shared<S>,
) {
    // Accepted sockets inherit non-blocking mode on some platforms.
    if socket.set_nonblocking(false).is_err() {
        return;
    }
    let _ = socket.set_nodelay(true);
    if let Ok(clone) = socket.try_clone() {
        shared.live().insert(slot.id, clone);
    }
    let connection = match rustls::ServerConnection::new(shared.access.server_config()) {
        Ok(connection) => connection,
        Err(_) => return,
    };
    let mut tls = TlsStream::new(connection, socket);
    if let Err(error) = tls.handshake_before(Instant::now() + shared.config.handshake_timeout) {
        // A peer that holds a connection slot through the whole handshake
        // bound counts as a refusal, so it cannot keep the slots forever.
        if super::deadline_io::is_timeout(&error) {
            shared.backoff.record_failure(peer.ip(), Instant::now());
        }
        crate::runtime_eprintln!(
            "muniment-runtime: remote attach handshake failed peer={peer} reason={:?}",
            error.kind()
        );
        tls.close();
        return;
    }
    let mut stream = RemoteStream::new(tls);
    let deadline = Instant::now() + shared.config.first_frame_timeout;
    let admitted = read_first_frame(&mut stream, deadline).and_then(|frame| {
        admit_remote_client(
            &mut stream,
            &frame,
            &shared.access,
            shared.approval.approval().as_ref(),
            deadline,
        )
    });
    let admitted = match admitted {
        Ok(admitted) => {
            shared.backoff.record_success(peer.ip());
            admitted
        }
        Err(error) => {
            if error.is_failed_attempt() {
                shared.backoff.record_failure(peer.ip(), Instant::now());
            }
            crate::runtime_eprintln!(
                "muniment-runtime: remote attach refused peer={peer} reason={error:?}"
            );
            stream.into_inner().close();
            return;
        }
    };
    crate::runtime_eprintln!(
        "muniment-runtime: remote attach accepted peer={peer} device_id={}",
        admitted.device_id
    );
    let Some(mut service) = (shared.service_factory)() else {
        crate::runtime_eprintln!(
            "muniment-runtime: remote attach closed peer={peer} reason=service creation failed"
        );
        stream.into_inner().close();
        return;
    };
    let result = serve_remote_client(&mut stream, &admitted, &shared.access, &mut service);
    crate::runtime_eprintln!(
        "muniment-runtime: remote attach closed peer={peer} device_id={} reason={result:?}",
        admitted.device_id
    );
    stream.into_inner().close();
}

fn read_first_frame(
    stream: &mut RemoteStream,
    deadline: Instant,
) -> Result<Vec<u8>, RemoteAdmissionError> {
    let map = |error: io::Error| {
        if super::deadline_io::is_timeout(&error) {
            RemoteAdmissionError::Timeout
        } else {
            RemoteAdmissionError::Closed
        }
    };
    let mut prefix = [0_u8; 4];
    read_exact_before(stream, &mut prefix, deadline).map_err(map)?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length > MAX_HELLO_FRAME_LENGTH {
        write_protocol_error(stream, ProtocolError::payload_too_large(), deadline);
        return Err(RemoteAdmissionError::PayloadTooLarge);
    }
    let mut frame = vec![0_u8; 4 + length];
    frame[..4].copy_from_slice(&prefix);
    read_exact_before(stream, &mut frame[4..], deadline).map_err(map)?;
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> FailureBackoffPolicy {
        FailureBackoffPolicy {
            free_attempts: 3,
            base_delay: Duration::from_secs(2),
            max_delay: Duration::from_secs(10),
            memory: Duration::from_secs(60),
        }
    }

    #[test]
    fn refusals_hold_a_peer_back_with_a_doubling_bounded_delay() {
        let backoff = FailureBackoff::new(policy());
        let peer: IpAddr = "192.0.2.7".parse().unwrap();
        let other: IpAddr = "192.0.2.8".parse().unwrap();
        let start = Instant::now();
        for _ in 0..2 {
            backoff.record_failure(peer, start);
            assert!(backoff.allows(peer, start));
        }
        backoff.record_failure(peer, start);
        assert!(!backoff.allows(peer, start));
        assert!(backoff.allows(other, start));
        assert!(backoff.allows(peer, start + Duration::from_secs(2)));
        backoff.record_failure(peer, start + Duration::from_secs(2));
        assert!(!backoff.allows(peer, start + Duration::from_secs(5)));
        assert!(backoff.allows(peer, start + Duration::from_secs(6)));
        for _ in 0..10 {
            backoff.record_failure(peer, start + Duration::from_secs(6));
        }
        assert!(!backoff.allows(peer, start + Duration::from_secs(15)));
        assert!(backoff.allows(peer, start + Duration::from_secs(16)));
        backoff.record_success(peer);
        backoff.record_failure(peer, start + Duration::from_secs(16));
        assert!(backoff.allows(peer, start + Duration::from_secs(16)));
    }

    #[test]
    fn refusals_are_forgotten_after_the_memory_window() {
        let backoff = FailureBackoff::new(policy());
        let peer: IpAddr = "192.0.2.9".parse().unwrap();
        let start = Instant::now();
        backoff.record_failure(peer, start);
        backoff.record_failure(peer, start);
        let later = start + Duration::from_secs(61);
        backoff.record_failure(peer, later);
        assert!(backoff.allows(peer, later));
    }

    #[test]
    fn plaintext_rustls_already_holds_counts_as_readable() {
        let directory =
            std::env::temp_dir().join(format!("muniment-remote-readable-{}", uuid::Uuid::now_v7()));
        let access = RemoteAccess::open(
            &directory,
            super::super::RemoteAccessOptions {
                runtime_name: None,
                runtime_version: "1.0.0".into(),
                install_kind: muniment_attach::InstallKind::Server,
            },
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let fingerprint = access.certificate_fingerprint();
        let (close_tx, close_rx) = std::sync::mpsc::channel::<()>();
        let client = std::thread::spawn(move || {
            let mut stream = muniment_attach::connect_pinned(
                &[address.to_string()],
                fingerprint,
                Duration::from_secs(5),
            )
            .unwrap();
            let mut frames = muniment_attach::encode_frame(&serde_json::json!({"n": 1})).unwrap();
            frames.extend(muniment_attach::encode_frame(&serde_json::json!({"n": 2})).unwrap());
            // One write sends both frames in one TLS record.
            stream.write_all(&frames).unwrap();
            close_rx.recv().unwrap();
            stream.close();
        });
        let (socket, _) = listener.accept().unwrap();
        let mut tls = TlsStream::new(
            rustls::ServerConnection::new(access.server_config()).unwrap(),
            socket,
        );
        tls.handshake_before(Instant::now() + Duration::from_secs(5))
            .unwrap();
        let mut stream = RemoteStream::new(tls);
        let deadline = Instant::now() + Duration::from_secs(5);
        let first = read_first_frame(&mut stream, deadline).unwrap();
        assert_eq!(&first[4..], br#"{"n":1}"#);

        // The second frame sits decrypted in rustls and the socket is empty.
        {
            let inner = stream.inner.borrow();
            inner.socket().set_nonblocking(true).unwrap();
            let peeked = inner.socket().peek(&mut [0_u8; 1]);
            assert_eq!(peeked.unwrap_err().kind(), io::ErrorKind::WouldBlock);
            inner.socket().set_nonblocking(false).unwrap();
        }
        assert_eq!(
            stream.wait_until_readable(Instant::now() + Duration::from_millis(50)),
            ReadableWait::Ready
        );
        let second = read_first_frame(&mut stream, deadline).unwrap();
        assert_eq!(&second[4..], br#"{"n":2}"#);
        assert_eq!(
            stream.wait_until_readable(Instant::now() + Duration::from_millis(50)),
            ReadableWait::Timeout
        );
        close_tx.send(()).unwrap();
        client.join().unwrap();
        assert_eq!(
            stream.wait_until_readable(Instant::now() + Duration::from_secs(5)),
            ReadableWait::Closed
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn ipv6_peers_share_their_prefix_and_mapped_ipv4_is_ipv4() {
        let backoff = FailureBackoff::new(policy());
        let start = Instant::now();
        for host in 1..=3 {
            let peer: IpAddr = format!("2001:db8:1:2::{host}").parse().unwrap();
            backoff.record_failure(peer, start);
        }
        assert!(!backoff.allows("2001:db8:1:2::ffff".parse().unwrap(), start));
        assert!(backoff.allows("2001:db8:1:3::1".parse().unwrap(), start));
        for _ in 0..3 {
            backoff.record_failure("::ffff:192.0.2.10".parse().unwrap(), start);
        }
        assert!(!backoff.allows("192.0.2.10".parse().unwrap(), start));
    }
}
