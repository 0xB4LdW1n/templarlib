//! The native Elements peg of a Templar test server's regtest
//! (`templar-testlab/docs/api-config.md`): the peg-out output, the Bitcoin
//! side the wallet watches, and the verification of a peg-in claim's
//! evidence.
//!
//! **Who is trusted for what.** The wallet's own Bitcoin Electrum server
//! (the one its Bitcoin wallet syncs through) is the chain view: it says
//! which transaction paid a deposit address, at which height, which header
//! sits at that height and how deep the chain is. The Esplora server named by
//! the test server only supplies bytes the claim needs and Electrum cannot
//! give — the raw deposit transaction and its merkle proof — and those bytes
//! are checked against the chain view before anything is built on them
//! ([`verify_pegin_evidence`]). An Esplora server that lies can make a claim
//! fail; it cannot make the wallet sign one for a transaction or a block its
//! chain view does not have.
//!
//! Every network client here is built inside the call that needs it, with a
//! timeout (the engine mutex is held while it waits).

use std::io::{self, Read, Write};
use std::str::FromStr;
use std::time::Duration;

use electrum_client::raw_client::RawClient;
use electrum_client::{ElectrumApi, Param};
use lwk_wollet::elements::bitcoin::{self, hashes::Hash, BlockHash, ScriptBuf, Txid};
use lwk_wollet::elements::{self, opcodes, script::Builder};
use lwk_wollet::{PeginAddress, PeginFunding};

use crate::error::{PegError, TemplarError};
use crate::net::{self, Deadline, DeadlineStream};

/// Smallest peg-in or peg-out the wallet starts: it leaves room for the
/// claim's or the payout's fee and stays far above any dust limit.
pub const MIN_PEG_SATS: u64 = 10_000;
/// 21 million BTC: the largest amount any peg-in can carry.
pub const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

/// Longest TCP connect to the Bitcoin Electrum server, as the Bitcoin
/// wallet's socket timeout.
const ELECTRUM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one step of the Bitcoin chain view may take, first byte to
/// last ([`crate::net`]).
#[derive(Debug, Clone, Copy)]
pub struct ElectrumBudget {
    /// TCP connect, TLS handshake and the `server.version` exchange.
    pub connect: Duration,
    /// One request and its answer.
    pub call: Duration,
}

/// The budgets every engine call uses.
pub const ELECTRUM_BUDGET: ElectrumBudget = ElectrumBudget {
    connect: Duration::from_secs(10),
    call: Duration::from_secs(10),
};
/// Esplora whole-request bound (connect: [`crate::http`]'s).
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// Largest raw transaction read from Esplora (hex characters): a standard
/// transaction is at most 400 000 weight units, 400 kB, 800 000 hex.
pub const MAX_TX_HEX_CHARS: u64 = 1_000_000;
/// Largest merkle-block proof read (hex characters): 80-byte header, a
/// count, and one 32-byte hash per tree level and sibling — a few kB.
pub const MAX_PROOF_HEX_CHARS: u64 = 200_000;

fn chain_err(ctx: &str, e: impl std::fmt::Display) -> TemplarError {
    PegError::Chain(format!("{ctx}: {e}")).into()
}

fn rejected(msg: impl Into<String>) -> TemplarError {
    PegError::ProofRejected(msg.into()).into()
}

// ---------------------------------------------------------------------------
// Peg-out output
// ---------------------------------------------------------------------------

/// The scriptPubKey of a peg-out output: `OP_RETURN <parent genesis hash,
/// internal byte order> <the Bitcoin scriptPubKey to pay>`, what
/// `elementsd sendtomainchain` writes (no PAK proof: the lab does not
/// enforce PAK). The output carrying it must have an explicit L-BTC value.
pub fn pegout_script(
    parent_genesis: &BlockHash,
    destination: &bitcoin::Script,
) -> elements::Script {
    Builder::new()
        .push_opcode(opcodes::all::OP_RETURN)
        .push_slice(&parent_genesis.to_byte_array())
        .push_slice(destination.as_bytes())
        .into_script()
}

/// Parses a Bitcoin address on `network` into its scriptPubKey. Refuses an
/// address of another network.
pub fn bitcoin_script_for(
    address: &str,
    network: bitcoin::Network,
) -> Result<ScriptBuf, TemplarError> {
    let parsed = bitcoin::Address::from_str(address.trim())
        .map_err(|e| PegError::Build(format!("Invalid Bitcoin address: {e}")))?
        .require_network(network)
        .map_err(|e| PegError::Build(format!("Bitcoin address of another network: {e}")))?;
    Ok(parsed.script_pubkey())
}

// ---------------------------------------------------------------------------
// The wallet's Bitcoin chain view (Electrum)
// ---------------------------------------------------------------------------

/// One transaction touching a script, as Electrum reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptHistoryItem {
    pub txid: Txid,
    /// Confirmation height; `None` while in the mempool.
    pub height: Option<u32>,
}

/// The Electrum connection: plain TCP or TLS, both under one deadline.
enum ElectrumStream {
    Plain(DeadlineStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, DeadlineStream>>),
}

impl Read for ElectrumStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ElectrumStream::Plain(s) => s.read(buf),
            ElectrumStream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for ElectrumStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ElectrumStream::Plain(s) => s.write(buf),
            ElectrumStream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ElectrumStream::Plain(s) => s.flush(),
            ElectrumStream::Tls(s) => s.flush(),
        }
    }
}

/// The wallet's Bitcoin Electrum server, read with bitcoin 0.32 types (the
/// ones LWK's peg-in types use). Built per call; nothing is kept open. The
/// connection and every request are bounded by a deadline for the whole
/// step, so a server that trickles bytes cannot hold the engine.
pub struct BitcoinChainView {
    client: RawClient<ElectrumStream>,
    deadline: Deadline,
    call_budget: Duration,
}

impl BitcoinChainView {
    /// Connects to `backend`'s Electrum server and checks it is on the
    /// backend's chain (its block 0 is that network's genesis,
    /// [`crate::bitcoin::wallet::require_genesis`]). TLS certificates are
    /// validated against the host.
    pub fn connect(backend: &crate::BitcoinBackend) -> Result<Self, TemplarError> {
        let view = Self::connect_with(&backend.electrum_url, ELECTRUM_BUDGET)?;
        let got = view.block_hash_at(0)?.to_string();
        crate::bitcoin::wallet::require_genesis(backend.network, &got)
            .map_err(|e| chain_err("Bitcoin Electrum", e))?;
        Ok(view)
    }

    /// [`Self::connect`] with explicit budgets (tests use short ones).
    pub fn connect_with(electrum_url: &str, budget: ElectrumBudget) -> Result<Self, TemplarError> {
        let fail = |e: &dyn std::fmt::Display| chain_err("Bitcoin Electrum connection failed", e);
        let (tls, rest) = match electrum_url.split_once("://") {
            Some(("ssl", rest)) => (true, rest),
            Some(("tcp", rest)) => (false, rest),
            Some((other, _)) => return Err(fail(&format!("unknown scheme {other:?}"))),
            None => (false, electrum_url),
        };
        let (host, port) = rest
            .rsplit_once(':')
            .and_then(|(h, p)| Some((h, p.parse::<u16>().ok()?)))
            .ok_or_else(|| fail(&"no host:port"))?;
        let host = host.trim_matches(['[', ']']);
        let deadline = Deadline::new(budget.connect);
        let tcp =
            net::connect(host, port, &deadline, ELECTRUM_CONNECT_TIMEOUT).map_err(|e| fail(&e))?;
        let stream = if tls {
            ElectrumStream::Tls(Box::new(net::tls(tcp, host).map_err(|e| fail(&e))?))
        } else {
            ElectrumStream::Plain(tcp)
        };
        let client = RawClient::from(stream);
        // The protocol's opening exchange, inside the connect budget.
        client
            .raw_call(
                "server.version",
                vec![
                    Param::String("templar".into()),
                    Param::StringVec(vec!["1.4".into(), "1.6".into()]),
                ],
            )
            .map_err(|e| fail(&e))?;
        Ok(Self {
            client,
            deadline,
            call_budget: budget.call,
        })
    }

    /// Opens the deadline of one request.
    fn step(&self) -> &RawClient<ElectrumStream> {
        self.deadline.reset(self.call_budget);
        &self.client
    }

    /// Height of the best chain's tip.
    pub fn tip_height(&self) -> Result<u32, TemplarError> {
        let tip = self
            .step()
            .block_headers_subscribe()
            .map_err(|e| chain_err("Bitcoin tip", e))?;
        u32::try_from(tip.height).map_err(|e| chain_err("Bitcoin tip", e))
    }

    /// Hash of the best chain's block at `height`.
    pub fn block_hash_at(&self, height: u32) -> Result<BlockHash, TemplarError> {
        let header = self
            .step()
            .block_header(height as usize)
            .map_err(|e| chain_err("Bitcoin block header", e))?;
        Ok(header.block_hash())
    }

    /// Every transaction that pays or spends `script`.
    pub fn history(
        &self,
        script: &bitcoin::Script,
    ) -> Result<Vec<ScriptHistoryItem>, TemplarError> {
        let items = self
            .step()
            .script_get_history(script)
            .map_err(|e| chain_err("Bitcoin script history", e))?;
        Ok(items
            .into_iter()
            .map(|i| ScriptHistoryItem {
                txid: i.tx_hash,
                height: u32::try_from(i.height).ok().filter(|h| *h > 0),
            })
            .collect())
    }

    /// A transaction by id; its bytes are checked to hash to `txid`.
    pub fn transaction(&self, txid: &Txid) -> Result<bitcoin::Transaction, TemplarError> {
        let raw = self
            .step()
            .transaction_get_raw(txid)
            .map_err(|e| chain_err("Bitcoin transaction", e))?;
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&raw)
            .map_err(|e| chain_err("Bitcoin transaction decode", e))?;
        if tx.compute_txid() != *txid {
            return Err(chain_err(
                "Bitcoin transaction",
                format!("the server answered another transaction for {txid}"),
            ));
        }
        Ok(tx)
    }

    /// Broadcasts a serialized transaction; returns its txid.
    pub fn broadcast_raw(&self, raw: &[u8]) -> Result<Txid, TemplarError> {
        self.step()
            .transaction_broadcast_raw(raw)
            .map_err(|e| chain_err("Bitcoin broadcast", e))
    }

    /// Confirmations of the history item (0 in the mempool).
    pub fn confirmations(item: &ScriptHistoryItem, tip: u32) -> u32 {
        item.height
            .map(|h| tip.saturating_sub(h).saturating_add(1))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Esplora (claim evidence only)
// ---------------------------------------------------------------------------

/// Reads a hex document `GET {base}{path}` of at most `max_chars`
/// characters and decodes it. No redirects; bounded in time and size.
fn esplora_hex(base: &str, path: &str, max_chars: u64) -> Result<Vec<u8>, TemplarError> {
    let url = format!("{}{path}", base.trim_end_matches('/'));
    let client = crate::http::client(HTTP_TIMEOUT).map_err(|e| chain_err("Esplora client", e))?;
    let answer = crate::http::send(client.get(&url), max_chars)
        .map_err(|e| chain_err("Esplora request", e))?;
    if !answer.status.is_success() {
        return Err(chain_err(
            "Esplora request",
            format!("HTTP {} for {path}", answer.status.as_u16()),
        ));
    }
    hex::decode(answer.body.trim())
        .map_err(|_| chain_err("Esplora request", format!("{path} is not hex")))
}

/// The raw deposit transaction and its merkle-block proof (bitcoind's
/// `gettxoutproof` format) from the Esplora server at `base`. Unverified:
/// hand them to [`verify_pegin_evidence`].
pub fn fetch_pegin_evidence(base: &str, txid: &Txid) -> Result<(Vec<u8>, Vec<u8>), TemplarError> {
    let tx = esplora_hex(base, &format!("/tx/{txid}/hex"), MAX_TX_HEX_CHARS)?;
    let proof = esplora_hex(
        base,
        &format!("/tx/{txid}/merkleblock-proof"),
        MAX_PROOF_HEX_CHARS,
    )?;
    Ok((tx, proof))
}

// ---------------------------------------------------------------------------
// Claim evidence
// ---------------------------------------------------------------------------

/// What the wallet's own Bitcoin chain view says about a peg-in deposit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DepositFacts {
    /// The transaction Electrum lists as paying the deposit address.
    pub txid: Txid,
    /// Its confirmation height.
    pub height: u32,
    /// The best chain's block hash at `height`.
    pub block_hash: BlockHash,
    /// The best chain's tip height.
    pub tip_height: u32,
}

impl DepositFacts {
    /// Reads the facts for `txid` (one of `script`'s history items) from the
    /// chain view. Errors when the transaction is not confirmed.
    pub fn read(
        view: &BitcoinChainView,
        script: &bitcoin::Script,
        txid: &Txid,
    ) -> Result<Self, TemplarError> {
        let item = view
            .history(script)?
            .into_iter()
            .find(|i| i.txid == *txid)
            .ok_or_else(|| {
                PegError::NotReady(format!(
                    "the wallet's Bitcoin server does not list deposit {txid} any more"
                ))
            })?;
        let height = item
            .height
            .ok_or_else(|| PegError::NotReady(format!("deposit {txid} is not confirmed yet")))?;
        Ok(Self {
            txid: *txid,
            height,
            block_hash: view.block_hash_at(height)?,
            tip_height: view.tip_height()?,
        })
    }

    /// Confirmations of the deposit (the including block counts as one).
    pub fn confirmations(&self) -> u32 {
        self.tip_height
            .saturating_sub(self.height)
            .saturating_add(1)
    }
}

/// Checks a peg-in claim's evidence before anything is built on it, and
/// returns it as LWK's [`PeginFunding`]:
///
/// 1. the transaction pays `pegin_address` exactly once and the proof's
///    partial merkle tree is valid and includes it ([`PeginFunding::from_raw`]);
/// 2. it is the transaction the wallet's chain view listed (`facts.txid`);
/// 3. the proof's block is the chain view's block at the deposit's height —
///    a proof built on any other header (a fork, a made-up block) is
///    refused, which LWK alone does not check;
/// 4. the deposit is at least `required_confirmations` deep in that chain.
pub fn verify_pegin_evidence(
    pegin_address: PeginAddress,
    facts: &DepositFacts,
    tx_bytes: &[u8],
    proof_bytes: &[u8],
    required_confirmations: u32,
) -> Result<PeginFunding, TemplarError> {
    let funding = PeginFunding::from_raw(pegin_address, tx_bytes, proof_bytes)
        .map_err(|e| rejected(format!("the deposit evidence does not check out: {e}")))?;
    let txid = funding.deposit().outpoint().txid;
    if txid != facts.txid {
        return Err(rejected(format!(
            "the evidence is for transaction {txid}, not for the deposit {} the wallet's \
             Bitcoin server lists",
            facts.txid
        )));
    }
    if funding.referenced_block() != facts.block_hash {
        return Err(rejected(format!(
            "the merkle proof's block {} is not the block {} the wallet's Bitcoin server has \
             at height {}",
            funding.referenced_block(),
            facts.block_hash,
            facts.height
        )));
    }
    let confirmations = facts.confirmations();
    if confirmations < required_confirmations {
        return Err(PegError::NotReady(format!(
            "the deposit has {confirmations} of the {required_confirmations} Bitcoin \
             confirmations a claim needs"
        ))
        .into());
    }
    Ok(funding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::{Header, Version};
    use bitcoin::{absolute::LockTime, transaction, Amount, CompactTarget, MerkleBlock, TxOut};
    use lwk_wollet::{FedPeg, WolletDescriptor};

    /// A real peg-out output of the testlab chain, written by
    /// `elementsd sendtomainchain bcrt1ql2elf5cduwsuea5vl33lsctrl7vyzh7uq4vv4n 0.5`
    /// (Liquid tx 5e5fa221…36e7, output 1): the lab's documented format.
    const LAB_PEGOUT_SCRIPT: &str = "6a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf\
                                     188910f160014fab3f4d30de3a1ccf68cfc63f86163ff98415fdc";
    const LAB_PEGOUT_ADDRESS: &str = "bcrt1ql2elf5cduwsuea5vl33lsctrl7vyzh7uq4vv4n";

    fn regtest_genesis() -> BlockHash {
        bitcoin::constants::genesis_block(bitcoin::Network::Regtest)
            .header
            .block_hash()
    }

    #[test]
    fn pegout_script_matches_the_labs_sendtomainchain_output() {
        let dest = bitcoin_script_for(LAB_PEGOUT_ADDRESS, bitcoin::Network::Regtest).unwrap();
        let script = pegout_script(&regtest_genesis(), &dest);
        assert_eq!(
            hex::encode(script.as_bytes()),
            LAB_PEGOUT_SCRIPT.replace(' ', "")
        );
        // Elements reads it back as a peg-out to that script on that chain.
        let out = elements::TxOut {
            asset: elements::confidential::Asset::Explicit(elements::AssetId::default()),
            value: elements::confidential::Value::Explicit(50_000_000),
            nonce: elements::confidential::Nonce::Null,
            script_pubkey: script,
            witness: Default::default(),
        };
        let data = out.pegout_data().expect("a peg-out");
        assert_eq!(data.genesis_hash, regtest_genesis());
        assert_eq!(data.script_pubkey, dest);
        assert_eq!(data.value, 50_000_000);
        assert!(data.extra_data.is_empty());
    }

    #[test]
    fn bitcoin_addresses_of_other_networks_are_refused() {
        assert!(bitcoin_script_for(LAB_PEGOUT_ADDRESS, bitcoin::Network::Regtest).is_ok());
        let err = bitcoin_script_for(LAB_PEGOUT_ADDRESS, bitcoin::Network::Testnet)
            .unwrap_err()
            .to_string();
        assert!(err.contains("another network"), "{err}");
        let err = bitcoin_script_for("not an address", bitcoin::Network::Regtest)
            .unwrap_err()
            .to_string();
        assert!(err.contains("Invalid Bitcoin address"), "{err}");
    }

    // -- Claim evidence ------------------------------------------------------

    /// The test server's federation: `wsh(multi(1, <lab key>))` in a
    /// P2SH-P2WSH program, as the lab's dynafed headers carry it.
    const LAB_FEDPEG_SCRIPT: &str =
        "5121035a5368bd34fd0178050dc283d4b5902e69b27a1cbfd0fb57adf331aaaa3639e851ae";

    fn lab_network() -> lwk_wollet::Network {
        crate::LiquidNetwork::regtest_with_genesis(
            "b0b2bef620ac742b2399a0085bc84e4860ae2c65b5375e3b94399debec69aa6b",
            "d51392db10c135e2e5f7bcfeab36e859ca4e69d6f76439ec0ebcb0a8da7be248",
        )
        .unwrap()
        .elements()
    }

    /// A dynafed header at height 150 carrying the lab's full parameters.
    fn lab_fed_peg() -> FedPeg {
        use elements::dynafed::{FullParams, Params};
        let fedpeg_script = bitcoin::ScriptBuf::from_hex(LAB_FEDPEG_SCRIPT).unwrap();
        let wsh = bitcoin::ScriptBuf::new_p2wsh(&fedpeg_script.wscript_hash());
        let program = bitcoin::ScriptBuf::new_p2sh(&wsh.script_hash());
        let full = Params::Full(FullParams::new(
            elements::Script::new(),
            0,
            program,
            fedpeg_script.to_bytes(),
            vec![],
        ));
        let header = elements::BlockHeader {
            version: 0x2000_0000,
            prev_blockhash: elements::BlockHash::from_byte_array([0; 32]),
            merkle_root: elements::TxMerkleNode::from_byte_array([0; 32]),
            time: 0,
            height: 150,
            ext: elements::BlockExtData::Dynafed {
                current: full.clone(),
                proposed: Params::Null,
                signblock_witness: vec![],
            },
        };
        FedPeg::from_block_header(lab_network(), &header).unwrap()
    }

    fn pegin_address() -> PeginAddress {
        let signer = lwk_signer::SwSigner::new_with_network(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
             abandon about",
            lwk_wollet::Network::TestnetLiquid,
        )
        .unwrap();
        let desc = lwk_common::singlesig_desc(
            &signer,
            lwk_common::Singlesig::Wpkh,
            lwk_common::DescriptorBlindingKey::Slip77,
        )
        .unwrap();
        let desc: WolletDescriptor = desc.parse().unwrap();
        desc.pegin_address(3, &lab_fed_peg()).unwrap()
    }

    fn deposit_tx(address: &PeginAddress, sats: u64) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![
                TxOut {
                    value: Amount::from_sat(sats),
                    script_pubkey: address.address().script_pubkey(),
                },
                TxOut {
                    value: Amount::from_sat(1_234),
                    script_pubkey: ScriptBuf::new_op_return([7u8; 4]),
                },
            ],
        }
    }

    /// A block holding `txids` (proof for the first) and its merkle proof.
    fn proof_for(txids: &[Txid], prev: BlockHash) -> MerkleBlock {
        let leaves: Vec<_> = txids.iter().map(|t| t.to_raw_hash()).collect();
        let root = bitcoin::merkle_tree::calculate_root(leaves.into_iter()).unwrap();
        let header = Header {
            version: Version::ONE,
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::from_raw_hash(root),
            time: 1_700_000_000,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        let first = txids[0];
        MerkleBlock::from_header_txids_with_predicate(&header, txids, |t| *t == first)
    }

    struct Case {
        address: PeginAddress,
        tx: Vec<u8>,
        proof: Vec<u8>,
        facts: DepositFacts,
    }

    fn good_case() -> Case {
        let address = pegin_address();
        let tx = deposit_tx(&address, 100_000);
        let txid = tx.compute_txid();
        let other = Txid::from_byte_array([9u8; 32]);
        let proof = proof_for(&[txid, other], regtest_genesis());
        Case {
            facts: DepositFacts {
                txid,
                height: 240,
                block_hash: proof.header.block_hash(),
                tip_height: 241,
            },
            address,
            tx: bitcoin::consensus::serialize(&tx),
            proof: bitcoin::consensus::serialize(&proof),
        }
    }

    fn verify(c: &Case) -> Result<PeginFunding, String> {
        verify_pegin_evidence(c.address.clone(), &c.facts, &c.tx, &c.proof, 2)
            .map_err(|e| e.to_string())
    }

    #[test]
    fn a_deposit_proven_in_the_wallets_chain_at_depth_verifies() {
        let c = good_case();
        let funding = verify(&c).unwrap();
        assert_eq!(funding.deposit().amount().to_sat(), 100_000);
        assert_eq!(funding.deposit().outpoint().vout, 0);
        assert_eq!(funding.referenced_block(), c.facts.block_hash);
        // It becomes an L-BTC input of the lab's chain.
        let input = lwk_wollet::PeginInput::from(funding);
        assert_eq!(input.parent_genesis_hash(), regtest_genesis());
        assert_eq!(
            input.pegged_asset(),
            *lab_network().policy_asset(),
            "the claim mints the lab's L-BTC"
        );
    }

    /// The wallet's own claim of a verified deposit: refused by every
    /// co-signing route (a peg-in input), signed by
    /// `sign_own_pegin_claim` against the order's record only.
    #[test]
    fn the_wallets_own_claim_signs_only_against_its_order() {
        let c = good_case();
        let claim_script = c.address.claim_script().clone();
        let funding = verify(&c).unwrap();
        let deposit = funding.deposit().outpoint();
        let network = crate::LiquidNetwork::regtest_with_genesis(
            "b0b2bef620ac742b2399a0085bc84e4860ae2c65b5375e3b94399debec69aa6b",
            "d51392db10c135e2e5f7bcfeab36e859ca4e69d6f76439ec0ebcb0a8da7be248",
        )
        .unwrap();
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon \
                        abandon abandon abandon about";
        let wallet =
            crate::LiquidWalletManager::from_mnemonic_with_persist_on(&network, mnemonic, None)
                .unwrap();
        let payout = wallet.get_new_address().unwrap();
        let claim = wallet
            .create_pegin_claim(lwk_wollet::PeginInput::from(funding), &payout)
            .unwrap();

        // No co-signing route signs a peg-in input.
        let mut a = claim.clone();
        let err = wallet.sign(&mut a).unwrap_err().to_string();
        assert!(
            err.starts_with("Signing failed: refusing to sign input 0:") && err.contains("peg-in"),
            "{err}"
        );
        let mut b = claim.clone();
        let err = crate::LiquidMultisigSetup::sign_pset_with_mnemonics(
            &mut b,
            &[mnemonic.to_string()],
            wallet.signing_descriptor(),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("peg-in"), "{err}");
        assert!(wallet.refuse_unsafe_signing(&claim).is_err());
        assert!(a.inputs()[0].partial_sigs.is_empty() && b.inputs()[0].partial_sigs.is_empty());

        // Any record but the order's own is refused.
        let index_4 = wallet
            .pegin_address(4, &lab_fed_peg())
            .unwrap()
            .claim_script()
            .clone();
        let other_vout = bitcoin::OutPoint::new(deposit.txid, 1);
        let other_txid = bitcoin::OutPoint::new(Txid::from_byte_array([9u8; 32]), deposit.vout);
        for (outpoint, index, script, words) in [
            (other_vout, 3, &claim_script, "another deposit"),
            (other_txid, 3, &claim_script, "another deposit"),
            (deposit, 4, &claim_script, "not this wallet's script"),
            (deposit, 4, &index_4, "claim script is not this order's"),
        ] {
            let mut p = claim.clone();
            let err = wallet
                .sign_own_pegin_claim(&mut p, &outpoint, index, script)
                .unwrap_err()
                .to_string();
            assert!(err.contains(words), "{words}: {err}");
            assert!(p.inputs()[0].partial_sigs.is_empty());
        }
        // A claim with a second input is not a claim.
        let mut two = claim.clone();
        two.add_input(lwk_wollet::elements::pset::Input::from_prevout(
            lwk_wollet::elements::OutPoint::new(
                lwk_wollet::elements::Txid::from_byte_array([8u8; 32]),
                0,
            ),
        ));
        let err = wallet
            .sign_own_pegin_claim(&mut two, &deposit, 3, &claim_script)
            .unwrap_err()
            .to_string();
        assert!(err.contains("nothing else"), "{err}");

        // The order's own record signs it, and it finalizes as a peg-in.
        let mut signed = claim.clone();
        assert_eq!(
            wallet
                .sign_own_pegin_claim(&mut signed, &deposit, 3, &claim_script)
                .unwrap(),
            1
        );
        let tx = wallet.finalize(&mut signed).unwrap();
        assert!(tx.input.len() == 1 && tx.input[0].is_pegin);
    }

    #[test]
    fn a_tampered_proof_is_rejected() {
        let mut c = good_case();
        // Flip a byte of the first hash after the header, count and flags.
        let n = c.proof.len();
        c.proof[n - 10] ^= 0x01;
        let err = verify(&c).unwrap_err();
        assert!(err.starts_with("PEG_PROOF_REJECTED:"), "{err}");
        // A proof cut short does not even decode.
        let mut c = good_case();
        c.proof.truncate(90);
        assert!(verify(&c).unwrap_err().starts_with("PEG_PROOF_REJECTED:"));
    }

    #[test]
    fn a_proof_for_another_transaction_is_rejected() {
        let mut c = good_case();
        let other = Txid::from_byte_array([5u8; 32]);
        let proof = proof_for(&[other, c.facts.txid], regtest_genesis());
        c.proof = bitcoin::consensus::serialize(&proof);
        c.facts.block_hash = proof.header.block_hash();
        let err = verify(&c).unwrap_err();
        assert!(err.starts_with("PEG_PROOF_REJECTED:"), "{err}");
        assert!(err.contains("not included in the txout proof"), "{err}");
    }

    #[test]
    fn a_transaction_the_chain_view_did_not_list_is_rejected() {
        let mut c = good_case();
        // Another transaction paying the same address, with a valid proof.
        let tx = deposit_tx(&c.address, 99_999);
        let proof = proof_for(&[tx.compute_txid()], regtest_genesis());
        c.tx = bitcoin::consensus::serialize(&tx);
        c.proof = bitcoin::consensus::serialize(&proof);
        c.facts.block_hash = proof.header.block_hash();
        let err = verify(&c).unwrap_err();
        assert!(err.contains("not for the deposit"), "{err}");
    }

    #[test]
    fn a_header_not_in_the_wallets_chain_is_rejected() {
        let mut c = good_case();
        // The chain view has a different block at that height.
        c.facts.block_hash = BlockHash::from_byte_array([3u8; 32]);
        let err = verify(&c).unwrap_err();
        assert!(err.starts_with("PEG_PROOF_REJECTED:"), "{err}");
        assert!(err.contains("is not the block"), "{err}");
    }

    #[test]
    fn a_deposit_too_shallow_is_not_ready() {
        let mut c = good_case();
        c.facts.tip_height = c.facts.height; // one confirmation, two needed
        let err = verify(&c).unwrap_err();
        assert!(err.starts_with("PEG_NOT_READY:"), "{err}");
        assert!(err.contains("1 of the 2"), "{err}");
    }

    #[test]
    fn a_transaction_not_paying_the_address_is_rejected() {
        let mut c = good_case();
        let mut tx = deposit_tx(&c.address, 100_000);
        tx.output[0].script_pubkey = ScriptBuf::new_op_return([1u8; 4]);
        let proof = proof_for(&[tx.compute_txid()], regtest_genesis());
        c.tx = bitcoin::consensus::serialize(&tx);
        c.proof = bitcoin::consensus::serialize(&proof);
        c.facts.txid = tx.compute_txid();
        c.facts.block_hash = proof.header.block_hash();
        let err = verify(&c).unwrap_err();
        assert!(err.starts_with("PEG_PROOF_REJECTED:"), "{err}");
    }

    #[test]
    fn a_trickling_electrum_server_is_cut_off() {
        let short = ElectrumBudget {
            connect: Duration::from_millis(800),
            call: Duration::from_millis(800),
        };
        // An answer to server.version that never ends.
        let addr = crate::net::trickling_server(
            br#"{"jsonrpc":"2.0","id":0,"result":["electrs","1.4"#.to_vec(),
            Duration::from_millis(50),
        );
        let started = std::time::Instant::now();
        let err = BitcoinChainView::connect_with(&format!("tcp://{addr}"), short)
            .err()
            .expect("must time out")
            .to_string();
        assert!(err.contains("Bitcoin Electrum connection failed"), "{err}");
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "held for {:?}",
            started.elapsed()
        );
        assert!(BitcoinChainView::connect_with("udp://h:1", short).is_err());
        assert!(BitcoinChainView::connect_with("tcp://nohostport", short).is_err());
    }

    #[test]
    fn the_chain_view_refuses_a_server_on_another_chain() {
        use bdk::bitcoin::Network;
        let testnet_server = crate::bitcoin::wallet::mock_electrum(Network::Testnet);
        let err = BitcoinChainView::connect(&crate::BitcoinBackend::regtest(&testnet_server))
            .err()
            .expect("a testnet server for a regtest wallet")
            .to_string();
        assert!(err.contains("not on Bitcoin regtest"), "{err}");
        let regtest_server = crate::bitcoin::wallet::mock_electrum(Network::Regtest);
        assert!(
            BitcoinChainView::connect(&crate::BitcoinBackend::regtest(&regtest_server)).is_ok()
        );
    }

    #[test]
    fn confirmations_count_the_including_block() {
        let item = ScriptHistoryItem {
            txid: Txid::all_zeros(),
            height: Some(100),
        };
        assert_eq!(BitcoinChainView::confirmations(&item, 100), 1);
        assert_eq!(BitcoinChainView::confirmations(&item, 101), 2);
        let mempool = ScriptHistoryItem {
            txid: Txid::all_zeros(),
            height: None,
        };
        assert_eq!(BitcoinChainView::confirmations(&mempool, 101), 0);
    }
}
