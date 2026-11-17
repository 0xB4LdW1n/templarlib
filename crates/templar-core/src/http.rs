//! The one way the engine reads an HTTP service it does not control (the
//! order book, the HTLC coordinator, the public asset registry): no
//! redirects, a connect and a whole-request timeout, a bounded body, and
//! error texts that are printable, bounded and free of the request URL
//! (which may carry credentials). `test_server::fetch_profile` follows the
//! same rules with its own, smaller bound.

use std::io::Read;
use std::time::Duration;

use reqwest::blocking::{Client, RequestBuilder};
use reqwest::StatusCode;

/// TCP connect bound.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest error text kept from a server.
const MAX_EXCERPT_CHARS: usize = 240;

/// A client with no redirects, a connect bound and `timeout` for the whole
/// request.
pub fn client(timeout: Duration) -> Result<Client, String> {
    Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| error_text(&e))
}

/// A reqwest error without the URL it was about.
pub fn error_text(e: &reqwest::Error) -> String {
    let mut s = strip_url(&e.to_string());
    let mut cur = std::error::Error::source(e);
    while let Some(err) = cur {
        s.push_str(": ");
        s.push_str(&strip_url(&err.to_string()));
        cur = err.source();
    }
    printable(&s, MAX_EXCERPT_CHARS)
}

/// reqwest renders "… for url (http://…)": drop that part.
fn strip_url(s: &str) -> String {
    match s.find(" for url (") {
        Some(i) => {
            let rest = &s[i..];
            match rest.find(')') {
                Some(j) => format!("{}{}", &s[..i], &rest[j + 1..]),
                None => s[..i].to_string(),
            }
        }
        None => s.to_string(),
    }
}

/// At most `max` characters of `s`, control characters removed.
pub fn printable(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// What a server said in an error answer: its JSON `error` field when it
/// has one, else the body; printable and bounded.
pub fn excerpt(body: &str) -> String {
    let message = serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_string))
        .unwrap_or_else(|| body.trim().to_string());
    printable(&message, MAX_EXCERPT_CHARS)
}

/// An answer: its status, `Retry-After` in seconds when given, and its
/// body (at most `max_bytes`, UTF-8).
pub struct Answer {
    pub status: StatusCode,
    pub retry_after: Option<u64>,
    pub body: String,
}

/// Sends `request` and reads the answer. A redirect is refused (the URL
/// must be the one configured), a body larger than `max_bytes` is an
/// error, and neither the URL nor more than a bounded excerpt of a body
/// ever reaches an error text.
pub fn send(request: RequestBuilder, max_bytes: u64) -> Result<Answer, String> {
    let resp = request.send().map_err(|e| error_text(&e))?;
    let status = resp.status();
    if status.is_redirection() {
        return Err(format!(
            "the server redirects (HTTP {}); configure the URL it points to",
            status.as_u16()
        ));
    }
    let retry_after = resp
        .headers()
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse::<u64>().ok());
    if resp.content_length().is_some_and(|n| n > max_bytes) {
        return Err(format!("the answer is larger than {max_bytes} bytes"));
    }
    let mut body = Vec::new();
    resp.take(max_bytes + 1)
        .read_to_end(&mut body)
        .map_err(|e| printable(&e.to_string(), MAX_EXCERPT_CHARS))?;
    if body.len() as u64 > max_bytes {
        return Err(format!("the answer is larger than {max_bytes} bytes"));
    }
    let body = String::from_utf8(body).map_err(|_| "the answer is not UTF-8".to_string())?;
    Ok(Answer {
        status,
        retry_after,
        body,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Write;

    /// A loopback server answering every request with `raw` (a whole HTTP
    /// response). Returns its base URL.
    pub(crate) fn serve_raw(raw: Vec<u8>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let mut buf = [0u8; 4096];
                let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
                let _ = std::io::Read::read(&mut stream, &mut buf);
                let _ = stream.write_all(&raw);
            }
        });
        url
    }

    fn get(url: &str, max: u64) -> Result<Answer, String> {
        send(client(Duration::from_secs(5)).unwrap().get(url), max)
    }

    #[test]
    fn redirects_are_refused() {
        let url = serve_raw(
            b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/x\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        );
        let err = get(&url, 1000).err().unwrap();
        assert!(err.contains("redirects (HTTP 302)"), "{err}");
    }

    #[test]
    fn large_bodies_are_refused_announced_or_not() {
        let big = "x".repeat(5_000);
        let url = serve_raw(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{big}",
                big.len()
            )
            .into_bytes(),
        );
        assert!(get(&url, 1_000).err().unwrap().contains("larger than 1000"));
        // No Content-Length: the read itself is bounded.
        let url =
            serve_raw(format!("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{big}").into_bytes());
        assert!(get(&url, 1_000).err().unwrap().contains("larger than 1000"));
        let ok = get(&url, 10_000).ok().unwrap();
        assert_eq!(ok.body.len(), 5_000);
    }

    #[test]
    fn error_texts_are_bounded_printable_and_url_free() {
        let hostile = format!("\u{1b}[31m{}", "e".repeat(10_000));
        let ex = excerpt(&hostile);
        assert_eq!(ex.chars().count(), MAX_EXCERPT_CHARS);
        assert!(!ex.contains('\u{1b}'));
        assert_eq!(excerpt(r#"{"error":"nope"}"#), "nope");
        // A refused connection to a URL with credentials: no credentials in
        // the error.
        let closed = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let err = get(&format!("http://user:secret@127.0.0.1:{closed}/x"), 10)
            .err()
            .unwrap();
        assert!(!err.contains("secret") && !err.contains("user:"), "{err}");
        assert_eq!(
            strip_url("error sending request for url (http://u:p@h/x): boom"),
            "error sending request: boom"
        );
    }
}
