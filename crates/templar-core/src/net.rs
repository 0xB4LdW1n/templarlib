//! TCP (and TLS) streams bounded by a deadline for a whole call, not per
//! read.
//!
//! A socket read timeout bounds one `read`; a server that trickles a byte
//! just before each timeout keeps a call alive for ever, and with it the
//! engine mutex. [`DeadlineStream`] sets the socket timeout to the time
//! left before every read and write and fails once the deadline has
//! passed, so the TLS handshake, a WebSocket upgrade and every answer are
//! bounded together. The owner moves the deadline forward per call
//! ([`Deadline::reset`]).
//!
//! Name resolution (`getaddrinfo`) is not covered: the system resolver has
//! no deadline of its own.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A deadline shared between a stream and its owner.
#[derive(Clone, Debug)]
pub struct Deadline(Arc<Mutex<Instant>>);

impl Deadline {
    /// A deadline `budget` from now.
    pub fn new(budget: Duration) -> Self {
        Self(Arc::new(Mutex::new(Instant::now() + budget)))
    }

    /// Moves the deadline to `budget` from now.
    pub fn reset(&self, budget: Duration) {
        *self.0.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now() + budget;
    }

    /// The time left, or a `TimedOut` error once it has passed.
    pub fn left(&self) -> io::Result<Duration> {
        let at = *self.0.lock().unwrap_or_else(|e| e.into_inner());
        let left = at.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the server did not answer in time",
            ));
        }
        Ok(left)
    }
}

/// A TCP stream whose every read and write ends by its [`Deadline`].
#[derive(Debug)]
pub struct DeadlineStream {
    tcp: TcpStream,
    deadline: Deadline,
}

impl DeadlineStream {
    fn arm(&self) -> io::Result<()> {
        let left = self.deadline.left()?;
        self.tcp.set_read_timeout(Some(left))?;
        self.tcp.set_write_timeout(Some(left))
    }
}

/// A socket timeout surfaces as `WouldBlock` on some platforms (macOS) and
/// `TimedOut` on others; callers that treat `WouldBlock` as "try again"
/// (a non-blocking handshake) must see a timeout for what it is.
fn timed_out(e: io::Error) -> io::Error {
    if e.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "the server did not answer in time")
    } else {
        e
    }
}

impl Read for DeadlineStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.arm()?;
        self.tcp.read(buf).map_err(timed_out)
    }
}

impl Write for DeadlineStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.arm()?;
        self.tcp.write(buf).map_err(timed_out)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.arm()?;
        self.tcp.flush().map_err(timed_out)
    }
}

/// Connects to `host:port` within `max_connect` and the deadline, trying
/// each resolved address in turn.
pub fn connect(
    host: &str,
    port: u16,
    deadline: &Deadline,
    max_connect: Duration,
) -> io::Result<DeadlineStream> {
    let host = host.trim_matches(['[', ']']);
    let mut last = io::Error::new(io::ErrorKind::NotFound, format!("cannot resolve {host}"));
    for addr in (host, port).to_socket_addrs()? {
        let budget = deadline.left()?.min(max_connect);
        match TcpStream::connect_timeout(&addr, budget) {
            Ok(tcp) => {
                return Ok(DeadlineStream {
                    tcp,
                    deadline: deadline.clone(),
                })
            }
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// A rustls client config: the ring provider, the webpki roots, safe
/// default protocol versions. Certificates are validated against the host.
pub fn tls_config() -> io::Result<Arc<rustls::ClientConfig>> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| io::Error::other(format!("TLS: {e}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// TLS over a deadline-bound stream (the handshake runs on first use and is
/// bounded by the same deadline).
pub fn tls(
    stream: DeadlineStream,
    host: &str,
) -> io::Result<rustls::StreamOwned<rustls::ClientConnection, DeadlineStream>> {
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "not a TLS host name"))?;
    let conn = rustls::ClientConnection::new(tls_config()?, name)
        .map_err(|e| io::Error::other(format!("TLS: {e}")))?;
    Ok(rustls::StreamOwned::new(conn, stream))
}

/// A loopback server that trickles `reply` one byte per `every` to each
/// connection, after reading what the client sends first: for the
/// deadline tests here and in the clients built on this module.
#[cfg(test)]
pub(crate) fn trickling_server(reply: Vec<u8>, every: Duration) -> std::net::SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let reply = reply.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
                let _ = stream.read(&mut buf);
                for b in reply.iter().cycle() {
                    if stream.write_all(&[*b]).is_err() {
                        return;
                    }
                    std::thread::sleep(every);
                }
            });
        }
    });
    addr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trickling_server_is_cut_off_at_the_deadline() {
        let addr = trickling_server(b"x".to_vec(), Duration::from_millis(50));
        let deadline = Deadline::new(Duration::from_millis(700));
        let mut s = connect(
            &addr.ip().to_string(),
            addr.port(),
            &deadline,
            Duration::from_secs(1),
        )
        .unwrap();
        s.write_all(b"hello").unwrap();
        let started = Instant::now();
        let mut sink = Vec::new();
        // Each read gets a byte well within any per-read timeout; only the
        // deadline ends it.
        let err = s.read_to_end(&mut sink).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "{:?}",
            started.elapsed()
        );
        assert!(!sink.is_empty());
        // A reset deadline opens the stream again.
        deadline.reset(Duration::from_millis(200));
        let mut one = [0u8; 1];
        s.read_exact(&mut one).unwrap();
    }
}
