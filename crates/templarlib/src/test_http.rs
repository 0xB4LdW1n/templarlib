//! A loopback HTTP server for offline tests: every request is recorded and
//! answered by a closure, so a test can stand in for the order book, the
//! HTLC coordinator, the asset registry or a lab's faucet.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

/// One request the server received.
#[derive(Debug, Clone)]
pub struct Seen {
    pub method: String,
    /// Path and query, e.g. `/api/assets?network=liquid-regtest`.
    pub target: String,
    pub body: String,
}

/// An answer: status, extra headers, body.
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Reply {
    pub fn json(status: u16, body: impl Into<String>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }

    pub fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// A running server: its base URL and what it received.
pub struct MockHttp {
    pub url: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl MockHttp {
    /// Starts a server answering each request with `handler`.
    pub fn start(handler: impl Fn(&Seen) -> Reply + Send + 'static) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                log.lock().unwrap().push(request.clone());
                let reply = handler(&request);
                let mut head = format!(
                    "HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                     Connection: close\r\n",
                    reply.status,
                    reply.body.len()
                );
                for (k, v) in &reply.headers {
                    head.push_str(&format!("{k}: {v}\r\n"));
                }
                head.push_str("\r\n");
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(reply.body.as_bytes());
            }
        });
        Self { url, seen }
    }

    /// The requests received so far.
    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Seen> {
    let mut req = Vec::new();
    let mut buf = [0u8; 8192];
    let at = loop {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => return None,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
        if let Some(at) = req.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
    };
    let head = String::from_utf8_lossy(&req[..at]).to_string();
    let len = head
        .lines()
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            k.eq_ignore_ascii_case("content-length")
                .then(|| v.trim().parse::<usize>().ok())?
        })
        .unwrap_or(0);
    while req.len() < at + 4 + len {
        match stream.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => req.extend_from_slice(&buf[..n]),
        }
    }
    let mut first = head.lines().next().unwrap_or("").split_whitespace();
    Some(Seen {
        method: first.next().unwrap_or("").to_string(),
        target: first.next().unwrap_or("").to_string(),
        body: String::from_utf8_lossy(&req[(at + 4).min(req.len())..]).to_string(),
    })
}

/// A local port nothing listens on (bound, then released).
pub fn closed_port_url() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    format!("http://{}", l.local_addr().unwrap())
}
