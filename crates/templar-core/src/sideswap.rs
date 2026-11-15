//! SideSwap's public peg API on Liquid **testnet**: JSON-RPC over a
//! WebSocket (`server_status`, `peg`, `peg_status`; <https://sideswap.io/docs/>).
//!
//! On testnet this is not a peg: Liquid testnet has no parent chain, and
//! SideSwap — a third party — swaps Bitcoin testnet coins for Liquid
//! testnet coins out of its own wallets, custodially. Hosts label it so.
//!
//! The server is untrusted. Only a receive address and the order's own
//! parameters (direction, a fee rate) are sent; nothing about the wallet.
//! Everything received is parsed strictly (bounded sizes, hex ids, integer
//! amounts, printable text) and a server that answers for another chain
//! (its `policy_asset` is not Liquid testnet L-BTC) is refused, so a
//! broken or malicious server can only make an order fail. Every call is
//! bounded in time; the socket lives for one call.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Map, Value};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Connector, Message, WebSocket};

use crate::error::{PegError, TemplarError};
use crate::liquid::liquidex::LBTC_TESTNET_ASSET_ID;

/// SideSwap's testnet endpoint.
pub const DEFAULT_TESTNET_URL: &str = "wss://api-testnet.sideswap.io/json-rpc-ws";
/// Overrides the SideSwap endpoint (see [`crate::Endpoints::peg_provider`]).
pub const ENV_SIDESWAP_URL: &str = "TEMPLAR_SIDESWAP_URL";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest message read. A `peg_status` with a long transaction list is a
/// few kB.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;
/// Messages read while waiting for one answer (notifications are skipped).
const MAX_MESSAGES_PER_CALL: usize = 16;
/// Largest list of deposits in one `peg_status`.
const MAX_PEG_TXS: usize = 64;
/// 21 million BTC.
const MAX_MONEY: u64 = 2_100_000_000_000_000;

fn bad(msg: impl Into<String>) -> TemplarError {
    PegError::Chain(format!("SideSwap: {}", msg.into())).into()
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// `server_status`: the service's terms.
#[derive(Debug, Clone, PartialEq)]
pub struct ServerStatus {
    pub min_peg_in_amount: u64,
    pub min_peg_out_amount: u64,
    /// Percent of the amount SideSwap keeps (0.1 = 0.1 %).
    pub server_fee_percent_peg_in: f64,
    pub server_fee_percent_peg_out: f64,
    /// Size of SideSwap's Bitcoin payout transaction; a peg-out's network
    /// fee is this times the fee rate.
    pub peg_out_bitcoin_tx_vsize: u64,
    /// `(confirmation target in blocks, sat/vB)`, fastest first.
    pub bitcoin_fee_rates: Vec<(u32, f64)>,
}

impl ServerStatus {
    /// The fee rate for the fastest target SideSwap quotes.
    pub fn fastest_fee_rate(&self) -> Option<f64> {
        self.bitcoin_fee_rates.first().map(|(_, rate)| *rate)
    }
}

/// `peg`: a new order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegOrder {
    pub order_id: String,
    /// Where to send the coins: a Bitcoin testnet address for a peg-in, a
    /// Liquid testnet address for a peg-out. The caller checks it.
    pub peg_addr: String,
    /// Unix milliseconds.
    pub created_at: u64,
    /// Unix milliseconds; 0 = no expiry.
    pub expires_at: u64,
}

/// Where SideSwap is with one deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxState {
    /// Final: the deposit does not cover the fees; nothing is paid.
    InsufficientAmount,
    /// Waiting for confirmations.
    Detected,
    /// Deep enough; the payout is being made.
    Processing,
    /// Final: paid.
    Done,
}

/// One deposit of an order, as SideSwap reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegTx {
    pub tx_hash: String,
    pub vout: u32,
    /// SideSwap's own words, e.g. `"0/2"` (printable, at most 64 chars).
    pub status: String,
    pub amount: u64,
    pub payout: Option<u64>,
    pub state: TxState,
    pub detected_confs: Option<u32>,
    pub total_confs: Option<u32>,
    pub payout_txid: Option<String>,
}

/// `peg_status`: an order and its deposits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PegStatus {
    pub order_id: String,
    pub peg_in: bool,
    /// The deposit address.
    pub addr: String,
    /// The receive address.
    pub addr_recv: String,
    pub list: Vec<PegTx>,
}

// ---------------------------------------------------------------------------
// Strict parsing
// ---------------------------------------------------------------------------

fn obj<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>, TemplarError> {
    v.as_object()
        .ok_or_else(|| bad(format!("{what} is not an object")))
}

fn field<'a>(o: &'a Map<String, Value>, key: &str) -> Result<&'a Value, TemplarError> {
    o.get(key).ok_or_else(|| bad(format!("{key} is missing")))
}

fn amount(o: &Map<String, Value>, key: &str) -> Result<u64, TemplarError> {
    field(o, key)?
        .as_u64()
        .filter(|n| *n <= MAX_MONEY)
        .ok_or_else(|| bad(format!("{key} is not an amount")))
}

fn opt_amount(o: &Map<String, Value>, key: &str) -> Result<Option<u64>, TemplarError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => amount(o, key).map(Some),
    }
}

fn small(o: &Map<String, Value>, key: &str) -> Result<Option<u32>, TemplarError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n <= 10_000)
            .map(Some)
            .ok_or_else(|| bad(format!("{key} is not a small number"))),
    }
}

fn timestamp(o: &Map<String, Value>, key: &str) -> Result<u64, TemplarError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(0),
        Some(v) => v
            .as_u64()
            .ok_or_else(|| bad(format!("{key} is not a timestamp"))),
    }
}

fn percent(o: &Map<String, Value>, key: &str) -> Result<f64, TemplarError> {
    field(o, key)?
        .as_f64()
        .filter(|p| p.is_finite() && (0.0..=100.0).contains(p))
        .ok_or_else(|| bad(format!("{key} is not a percentage")))
}

fn hex64(o: &Map<String, Value>, key: &str) -> Result<String, TemplarError> {
    let s = field(o, key)?
        .as_str()
        .ok_or_else(|| bad(format!("{key} is not a string")))?;
    if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad(format!("{key} is not 64 hex characters")));
    }
    Ok(s.to_ascii_lowercase())
}

fn opt_hex64(o: &Map<String, Value>, key: &str) -> Result<Option<String>, TemplarError> {
    match o.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => hex64(o, key).map(Some),
    }
}

/// An address-like string: 1–128 ASCII alphanumerics. Whether it is an
/// address of the right network is the caller's check.
fn address(o: &Map<String, Value>, key: &str) -> Result<String, TemplarError> {
    let s = field(o, key)?
        .as_str()
        .ok_or_else(|| bad(format!("{key} is not a string")))?;
    if s.is_empty() || s.len() > 128 || !s.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(bad(format!("{key} is not an address")));
    }
    Ok(s.to_string())
}

fn text(o: &Map<String, Value>, key: &str) -> Result<String, TemplarError> {
    let s = field(o, key)?
        .as_str()
        .ok_or_else(|| bad(format!("{key} is not a string")))?;
    Ok(printable(s, 64))
}

/// At most `max` printable characters of a server's text.
fn printable(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}

/// Parses a `server_status` result. Refuses a server of another chain.
pub fn parse_server_status(v: &Value) -> Result<ServerStatus, TemplarError> {
    let o = obj(v, "server_status")?;
    let asset = field(o, "policy_asset")?
        .as_str()
        .ok_or_else(|| bad("policy_asset is not a string"))?;
    if !asset.eq_ignore_ascii_case(LBTC_TESTNET_ASSET_ID) {
        return Err(bad(
            "the server is not on Liquid testnet (its policy asset is another chain's)",
        ));
    }
    let rates = field(o, "bitcoin_fee_rates")?
        .as_array()
        .ok_or_else(|| bad("bitcoin_fee_rates is not a list"))?;
    let mut bitcoin_fee_rates = Vec::new();
    for r in rates.iter().take(16) {
        let r = obj(r, "a fee rate")?;
        let blocks = small(r, "blocks")?.ok_or_else(|| bad("blocks is missing"))?;
        let value = field(r, "value")?
            .as_f64()
            .filter(|v| v.is_finite() && *v > 0.0 && *v <= 10_000.0)
            .ok_or_else(|| bad("a fee rate is out of range"))?;
        bitcoin_fee_rates.push((blocks, value));
    }
    bitcoin_fee_rates.sort_by_key(|(blocks, _)| *blocks);
    let vsize = field(o, "peg_out_bitcoin_tx_vsize")?
        .as_u64()
        .filter(|n| *n > 0 && *n <= 100_000)
        .ok_or_else(|| bad("peg_out_bitcoin_tx_vsize is out of range"))?;
    Ok(ServerStatus {
        min_peg_in_amount: amount(o, "min_peg_in_amount")?,
        min_peg_out_amount: amount(o, "min_peg_out_amount")?,
        server_fee_percent_peg_in: percent(o, "server_fee_percent_peg_in")?,
        server_fee_percent_peg_out: percent(o, "server_fee_percent_peg_out")?,
        peg_out_bitcoin_tx_vsize: vsize,
        bitcoin_fee_rates,
    })
}

/// Parses a `peg` result.
pub fn parse_peg(v: &Value) -> Result<PegOrder, TemplarError> {
    let o = obj(v, "peg")?;
    Ok(PegOrder {
        order_id: hex64(o, "order_id")?,
        peg_addr: address(o, "peg_addr")?,
        created_at: timestamp(o, "created_at")?,
        expires_at: timestamp(o, "expires_at")?,
    })
}

fn parse_tx(v: &Value) -> Result<PegTx, TemplarError> {
    let o = obj(v, "a deposit")?;
    let state = match field(o, "tx_state")?.as_str() {
        Some("InsufficientAmount") => TxState::InsufficientAmount,
        Some("Detected") => TxState::Detected,
        Some("Processing") => TxState::Processing,
        Some("Done") => TxState::Done,
        _ => return Err(bad("tx_state is not a known state")),
    };
    let payout_txid = opt_hex64(o, "payout_txid")?;
    if state == TxState::Done && payout_txid.is_none() {
        return Err(bad("a paid deposit has no payout_txid"));
    }
    Ok(PegTx {
        tx_hash: hex64(o, "tx_hash")?,
        vout: small(o, "vout")?.ok_or_else(|| bad("vout is missing"))?,
        status: text(o, "status")?,
        amount: amount(o, "amount")?,
        payout: opt_amount(o, "payout")?,
        state,
        detected_confs: small(o, "detected_confs")?,
        total_confs: small(o, "total_confs")?,
        payout_txid,
    })
}

/// Parses a `peg_status` result.
pub fn parse_peg_status(v: &Value) -> Result<PegStatus, TemplarError> {
    let o = obj(v, "peg_status")?;
    let list = field(o, "list")?
        .as_array()
        .ok_or_else(|| bad("list is not a list"))?;
    if list.len() > MAX_PEG_TXS {
        return Err(bad("too many deposits"));
    }
    Ok(PegStatus {
        order_id: hex64(o, "order_id")?,
        peg_in: field(o, "peg_in")?
            .as_bool()
            .ok_or_else(|| bad("peg_in is not a boolean"))?,
        addr: address(o, "addr")?,
        addr_recv: address(o, "addr_recv")?,
        list: list.iter().map(parse_tx).collect::<Result<_, _>>()?,
    })
}

/// The `result` of the answer to request `id` in `text`; `None` for a
/// message that is not that answer (a notification). An error answer is
/// an error, with the server's message reduced to printable text.
pub fn parse_answer(text: &str, id: u64) -> Result<Option<Value>, TemplarError> {
    let v: Value = serde_json::from_str(text).map_err(|_| bad("an answer is not JSON"))?;
    let o = obj(&v, "an answer")?;
    if o.get("id").and_then(Value::as_u64) != Some(id) {
        return Ok(None);
    }
    if let Some(err) = o.get("error") {
        let msg = err
            .get("message")
            .and_then(Value::as_str)
            .map(|m| printable(m, 160))
            .unwrap_or_else(|| "an error without a message".into());
        return Err(bad(format!("the server refused: {msg}")));
    }
    o.get("result")
        .cloned()
        .map(Some)
        .ok_or_else(|| bad("an answer has no result"))
}

// ---------------------------------------------------------------------------
// The socket
// ---------------------------------------------------------------------------

/// Checks a SideSwap endpoint: `wss://host[:port]/path`, or `ws://` to a
/// loopback host (a local test server). No credentials, query or fragment.
pub fn check_url(raw: &str) -> Result<reqwest::Url, TemplarError> {
    let invalid = |why: &str| -> TemplarError {
        // The URL itself is not echoed: it may carry credentials.
        PegError::Unavailable(format!("the SideSwap URL is not usable: {why}")).into()
    };
    let url = reqwest::Url::parse(raw.trim()).map_err(|_| invalid("not a URL"))?;
    let host = url.host_str().unwrap_or_default().to_string();
    let loopback = matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]");
    match url.scheme() {
        "wss" => {}
        "ws" if loopback => {}
        _ => return Err(invalid("only wss:// (or ws:// on this computer)")),
    }
    if host.is_empty() {
        return Err(invalid("no host"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid("no credentials allowed"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(invalid("no query or fragment allowed"));
    }
    Ok(url)
}

/// One connection to SideSwap, for the calls of one engine call.
pub struct SideSwapClient {
    socket: WebSocket<MaybeTlsStream<TcpStream>>,
    next_id: u64,
}

impl SideSwapClient {
    /// Connects to `url` (see [`check_url`]): TCP with a timeout, TLS with
    /// the webpki roots through the ring provider, then the WebSocket
    /// handshake with bounded frames and messages.
    pub fn connect(url: &str) -> Result<Self, TemplarError> {
        let url = check_url(url)?;
        let host = url.host_str().unwrap_or_default().trim_matches(['[', ']']);
        let port = url.port_or_known_default().unwrap_or(443);
        let addr = (host, port)
            .to_socket_addrs()
            .map_err(|e| bad(format!("cannot resolve {host}: {e}")))?
            .next()
            .ok_or_else(|| bad(format!("cannot resolve {host}")))?;
        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)
            .map_err(|e| bad(format!("cannot connect: {e}")))?;
        tcp.set_read_timeout(Some(IO_TIMEOUT))
            .and_then(|_| tcp.set_write_timeout(Some(IO_TIMEOUT)))
            .map_err(|e| bad(format!("socket: {e}")))?;
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let roots = rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        };
        let tls = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| bad(format!("TLS: {e}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let config = WebSocketConfig::default()
            .max_message_size(Some(MAX_MESSAGE_BYTES))
            .max_frame_size(Some(MAX_MESSAGE_BYTES));
        let (socket, _) = tungstenite::client_tls_with_config(
            url.as_str(),
            tcp,
            Some(config),
            Some(Connector::Rustls(Arc::new(tls))),
        )
        .map_err(|e| bad(format!("handshake: {e}")))?;
        Ok(Self { socket, next_id: 1 })
    }

    /// One JSON-RPC call: its `result`. Notifications in between are
    /// skipped, up to a bound.
    pub fn call(&mut self, method: &str, params: Value) -> Result<Value, TemplarError> {
        let id = self.next_id;
        self.next_id += 1;
        let request = json!({ "id": id, "method": method, "params": params });
        self.socket
            .send(Message::text(request.to_string()))
            .map_err(|e| bad(format!("{method}: {e}")))?;
        for _ in 0..MAX_MESSAGES_PER_CALL {
            let msg = self
                .socket
                .read()
                .map_err(|e| bad(format!("{method}: {e}")))?;
            let text = match msg {
                Message::Text(t) => t.to_string(),
                Message::Binary(b) => String::from_utf8(b.to_vec())
                    .map_err(|_| bad(format!("{method}: a binary answer")))?,
                Message::Close(_) => return Err(bad(format!("{method}: the server closed"))),
                _ => continue,
            };
            if let Some(result) = parse_answer(&text, id)? {
                return Ok(result);
            }
        }
        Err(bad(format!("{method}: no answer")))
    }

    pub fn server_status(&mut self) -> Result<ServerStatus, TemplarError> {
        let v = self.call("server_status", Value::Null)?;
        parse_server_status(&v)
    }

    /// Opens an order paying `recv_addr`. `fee_rate` (sat/vB) is the
    /// Bitcoin rate of a peg-out's payout.
    pub fn peg(
        &mut self,
        peg_in: bool,
        recv_addr: &str,
        fee_rate: Option<f64>,
    ) -> Result<PegOrder, TemplarError> {
        let mut params = json!({ "peg_in": peg_in, "recv_addr": recv_addr });
        if let Some(rate) = fee_rate {
            params["fee_rate"] = json!(rate);
        }
        let v = self.call("peg", params)?;
        parse_peg(&v)
    }

    pub fn peg_status(&mut self, peg_in: bool, order_id: &str) -> Result<PegStatus, TemplarError> {
        let v = self.call(
            "peg_status",
            json!({ "peg_in": peg_in, "order_id": order_id }),
        )?;
        let status = parse_peg_status(&v)?;
        if status.order_id != order_id || status.peg_in != peg_in {
            return Err(bad("the status is for another order"));
        }
        Ok(status)
    }
}

impl Drop for SideSwapClient {
    fn drop(&mut self) {
        let _ = self.socket.close(None);
        let _ = self.socket.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The live testnet answer of 2026-11-15.
    const STATUS: &str = r#"{"bitcoin_fee_rates":[{"blocks":2,"value":3.0},{"blocks":4,"value":3.0},{"blocks":6,"value":1.0},{"blocks":12,"value":1.0},{"blocks":24,"value":1.0}],"elements_fee_rate":0.1,"min_peg_in_amount":10000,"min_peg_out_amount":25000,"min_submit_amount":2000,"peg_out_bitcoin_tx_vsize":141,"policy_asset":"144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49","price_band":0.101,"server_fee_percent_peg_in":0.1,"server_fee_percent_peg_out":0.1,"upload_url":"https://api-testnet.sideswap.io/json-rpc"}"#;

    fn status_with(mutate: impl FnOnce(&mut Value)) -> Result<ServerStatus, String> {
        let mut v: Value = serde_json::from_str(STATUS).unwrap();
        mutate(&mut v);
        parse_server_status(&v).map_err(|e| e.to_string())
    }

    #[test]
    fn the_testnet_server_status_parses() {
        let s = status_with(|_| {}).unwrap();
        assert_eq!(s.min_peg_in_amount, 10_000);
        assert_eq!(s.min_peg_out_amount, 25_000);
        assert_eq!(s.server_fee_percent_peg_in, 0.1);
        assert_eq!(s.peg_out_bitcoin_tx_vsize, 141);
        assert_eq!(s.fastest_fee_rate(), Some(3.0));
    }

    #[test]
    fn hostile_server_status_is_refused() {
        let mainnet = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
        type Mutation = Box<dyn FnOnce(&mut Value)>;
        let cases: Vec<(Mutation, &str)> = vec![
            (
                Box::new(move |v| v["policy_asset"] = mainnet.into()),
                "not on Liquid testnet",
            ),
            (
                Box::new(|v| v["min_peg_in_amount"] = (-1).into()),
                "min_peg_in_amount",
            ),
            (
                Box::new(|v| v["min_peg_out_amount"] = "1".into()),
                "min_peg_out_amount",
            ),
            (
                Box::new(|v| v["min_peg_in_amount"] = 1e300.into()),
                "min_peg_in_amount",
            ),
            (
                Box::new(|v| v["server_fee_percent_peg_in"] = 150.into()),
                "percentage",
            ),
            (
                Box::new(|v| v["server_fee_percent_peg_out"] = (-0.1).into()),
                "percentage",
            ),
            (
                Box::new(|v| v["peg_out_bitcoin_tx_vsize"] = 0.into()),
                "vsize",
            ),
            (
                Box::new(|v| v["bitcoin_fee_rates"][0]["value"] = 1e9.into()),
                "out of range",
            ),
            (
                Box::new(|v| v["bitcoin_fee_rates"] = "fast".into()),
                "not a list",
            ),
            (
                Box::new(|v| {
                    v.as_object_mut().unwrap().remove("policy_asset");
                }),
                "missing",
            ),
        ];
        for (mutate, want) in cases {
            let err = status_with(mutate).unwrap_err();
            assert!(
                err.contains("SideSwap") && err.contains(want),
                "{want}: {err}"
            );
        }
        assert!(parse_server_status(&json!([1, 2])).is_err());
    }

    const PEG: &str = r#"{"order_id":"9a0c7d1e0b8f4a6e2c3b5d7f9e1a2c4b6d8f0e2a4c6b8d0f2e4a6c8b0d2f4e6a","peg_addr":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx","created_at":1794768000000,"expires_at":0,"recv_amount":null}"#;

    #[test]
    fn a_peg_answer_parses_and_hostile_ones_do_not() {
        let v: Value = serde_json::from_str(PEG).unwrap();
        let p = parse_peg(&v).unwrap();
        assert_eq!(p.order_id.len(), 64);
        assert_eq!(p.peg_addr, "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx");
        assert_eq!(p.created_at, 1_794_768_000_000);
        assert_eq!(p.expires_at, 0);
        for (key, value) in [
            ("order_id", json!("../../etc/passwd")),
            ("order_id", json!(12)),
            ("peg_addr", json!("tb1q<script>")),
            ("peg_addr", json!("a".repeat(200))),
            ("peg_addr", json!("")),
            ("created_at", json!(-5)),
        ] {
            let mut bad_v = v.clone();
            bad_v[key] = value.clone();
            assert!(parse_peg(&bad_v).is_err(), "{key} = {value} accepted");
        }
    }

    fn status_json(state: &str, extra: Value) -> Value {
        let mut tx = json!({
            "tx_hash": "aa".repeat(32), "vout": 1, "status": "0/2", "amount": 100000,
            "payout": 99900, "tx_state": state, "tx_state_code": 2,
            "detected_confs": 0, "total_confs": 2, "created_at": 1794768000000u64
        });
        for (k, v) in extra.as_object().unwrap() {
            tx[k] = v.clone();
        }
        json!({
            "order_id": "bb".repeat(32), "peg_in": true,
            "addr": "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            "addr_recv": "tlq1qqfake", "created_at": 1, "expires_at": 0, "list": [tx]
        })
    }

    #[test]
    fn peg_status_answers_parse_strictly() {
        let s = parse_peg_status(&status_json("Detected", json!({}))).unwrap();
        assert_eq!(s.list[0].state, TxState::Detected);
        assert_eq!(s.list[0].total_confs, Some(2));
        let done = parse_peg_status(&status_json(
            "Done",
            json!({ "payout_txid": "cc".repeat(32) }),
        ))
        .unwrap();
        assert_eq!(done.list[0].payout_txid, Some("cc".repeat(32)));
        // Done without a payout txid, an unknown state, a hostile status
        // text, amounts and counts out of range: refused or tamed.
        assert!(parse_peg_status(&status_json("Done", json!({}))).is_err());
        assert!(parse_peg_status(&status_json("Stolen", json!({}))).is_err());
        assert!(parse_peg_status(&status_json("Detected", json!({ "amount": -1 }))).is_err());
        assert!(parse_peg_status(&status_json("Detected", json!({ "vout": 1e12 }))).is_err());
        assert!(
            parse_peg_status(&status_json("Detected", json!({ "detected_confs": "2" }))).is_err()
        );
        let long = parse_peg_status(&status_json(
            "Detected",
            json!({ "status": format!("\u{1b}[31m{}", "x".repeat(500)) }),
        ))
        .unwrap();
        assert_eq!(long.list[0].status.chars().count(), 64);
        assert!(!long.list[0].status.contains('\u{1b}'));
        let mut many = status_json("Detected", json!({}));
        let tx = many["list"][0].clone();
        many["list"] = Value::Array(vec![tx; 65]);
        assert!(parse_peg_status(&many).is_err());
    }

    #[test]
    fn answers_are_matched_by_id_and_errors_are_tamed() {
        assert_eq!(
            parse_answer(r#"{"id":3,"result":{"a":1}}"#, 3).unwrap(),
            Some(json!({"a":1}))
        );
        // A notification, another id: not ours.
        assert_eq!(
            parse_answer(r#"{"method":"update","params":{}}"#, 3).unwrap(),
            None
        );
        assert_eq!(parse_answer(r#"{"id":4,"result":1}"#, 3).unwrap(), None);
        let err = parse_answer(
            r#"{"id":3,"error":{"code":"InvalidParams","message":"bad\u0007 addr"}}"#,
            3,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("the server refused: bad addr"), "{err}");
        assert!(parse_answer("not json", 3).is_err());
        assert!(parse_answer(r#"{"id":3}"#, 3).is_err());
    }

    #[test]
    fn only_secure_or_local_urls_are_used() {
        assert!(check_url(DEFAULT_TESTNET_URL).is_ok());
        assert!(check_url("ws://127.0.0.1:9001/ws").is_ok());
        for bad_url in [
            "ws://api-testnet.sideswap.io/json-rpc-ws",
            "https://api-testnet.sideswap.io",
            "wss://user:pw@api-testnet.sideswap.io/x",
            "wss://api-testnet.sideswap.io/x?k=1",
            "not a url",
        ] {
            let err = check_url(bad_url).unwrap_err().to_string();
            assert!(err.starts_with("PEG_UNAVAILABLE:"), "{bad_url}: {err}");
            assert!(!err.contains("pw@"), "credentials echoed: {err}");
        }
    }

    /// A loopback WebSocket server answering with `answers` in order, after
    /// one notification each; for the call loop.
    fn mock_server(answers: Vec<String>) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("ws://{}/ws", listener.local_addr().unwrap());
        std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut ws = tungstenite::accept(stream).unwrap();
            for answer in answers {
                let Ok(_request) = ws.read() else { return };
                let _ = ws.send(Message::text(r#"{"method":"news","params":{}}"#));
                let _ = ws.send(Message::text(answer));
            }
        });
        url
    }

    #[test]
    fn the_call_loop_skips_notifications_and_bounds_messages() {
        let url = mock_server(vec![
            format!(r#"{{"id":1,"method":"server_status","result":{STATUS}}}"#),
            format!(r#"{{"id":2,"result":"{}"}}"#, "x".repeat(MAX_MESSAGE_BYTES)),
        ]);
        let mut c = SideSwapClient::connect(&url).unwrap();
        assert_eq!(c.server_status().unwrap().min_peg_out_amount, 25_000);
        // An answer larger than the bound fails the call, nothing else.
        let err = c.call("big", Value::Null).unwrap_err().to_string();
        assert!(err.contains("SideSwap"), "{err}");
    }
}
