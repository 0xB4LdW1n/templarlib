//! PSET (Partially Signed Elements Transaction) inspection types.
//!
//! Provides structured details about a PSET for display in the UI,
//! including fee, recipients, and signer status.
//! Built from `Wollet::get_details()` output.
//!
//! # What a co-signer may believe
//!
//! A PSET's explicit `amount` / `asset` fields are metadata anyone can
//! write; the signature commits to the *commitments*. LWK only checks the
//! blind proofs of the outputs it classifies as the wallet's own, so every
//! other amount shown here is verified against its commitment first
//! ([`verified_output_claims`], [`verified_input_claims`]) and reported as
//! unverifiable — never as a number — when that check cannot be made.

use std::collections::{BTreeMap, BTreeSet};

use lwk_wollet::bitcoin::bip32::Fingerprint;
use lwk_wollet::elements::confidential::{Asset, Value};
use lwk_wollet::elements::pset::{Input, Output, PartiallySignedTransaction};
use lwk_wollet::elements::secp256k1_zkp::{All, Secp256k1};
use lwk_wollet::elements::AssetId;

use crate::error::{LiquidError, TemplarError};

/// A recipient in a PSET output.
#[derive(Debug, Clone)]
pub struct PsetRecipient {
    /// Index of the output in the transaction.
    pub vout: u32,
    /// Confidential address of the recipient (None if unrecognized script).
    pub address: Option<String>,
    /// Asset ID being sent (None if confidential and not yet unblinded).
    pub asset: Option<String>,
    /// Amount in satoshis (None if confidential and not yet unblinded).
    pub amount: Option<u64>,
    /// The PSET's explicit asset/amount could not be checked against the
    /// output's commitments — see [`PsetOutputInfo::unverified`]. Both
    /// fields above are `None` then.
    pub unverified: bool,
}

/// One input of a PSET, as far as the inspecting wallet can read it.
///
/// Built from the PSET's own fields (no chain access): `witness_utxo`,
/// `witness_script`, `bip32_derivation`, explicit asset/amount. That is
/// what a signer has to judge a Templar Protocol escrow spend by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsetInputInfo {
    pub index: u32,
    /// `txid:vout` of the coin being spent.
    pub outpoint: String,
    /// One of this wallet's master fingerprints appears in the input's key
    /// derivations — the input asks for this wallet's signature. This is the
    /// same match `SwSigner::sign` makes, so it holds for the wallet's own
    /// coins and for a loan escrow that names the wallet's `2121'` key.
    pub is_ours: bool,
    /// `p2wsh` | `p2wpkh` | `p2sh` | `other` | `unknown` (no `witness_utxo`).
    pub script_type: String,
    /// Witness script (hex) of a P2WSH input — the contract being spent.
    pub witness_script: Option<String>,
    /// The same script disassembled.
    pub witness_script_asm: Option<String>,
    /// Asset id of the coin: the wallet's own unblinded record for its own
    /// coins, else the PSET's explicit value once its blind proof checks
    /// out against the prevout commitment. `None` when unverifiable.
    pub asset: Option<String>,
    /// Amount in satoshis, on the same terms as `asset`.
    pub amount: Option<u64>,
    /// Neither the wallet nor a blind proof vouches for the amount and asset
    /// the PSET claims for this coin; both are `None`.
    pub unverified: bool,
    /// Master fingerprints of every key the input's derivations name.
    pub key_fingerprints: Vec<String>,
    /// Fingerprints that already signed this input.
    pub signed_by: Vec<String>,
    /// `k` of a `k-of-n CHECKMULTISIG` at the start of the witness script —
    /// the number of signatures the input's primary spending path needs,
    /// read off the script itself so a co-signer's wallet reports the right
    /// quorum for a transaction it did not build. `None` for anything that
    /// does not begin with a multisig.
    pub threshold: Option<u32>,
}

/// `k` of a `k-of-n CHECKMULTISIG` that opens the script: `OP_k <n pubkeys>
/// OP_n OP_CHECKMULTISIG`, whatever follows. That covers a bare multisig and
/// the `or_d(multi(k,…), …)` shape of a loan escrow, whose script goes on
/// with `OP_IFDUP OP_NOTIF … OP_ENDIF`. A script that starts any other way —
/// a single key, a timelock first — is not judged here.
pub fn multisig_threshold(script: &[u8]) -> Option<u32> {
    const OP_PUSHNUM_1: u8 = 0x51;
    const OP_PUSHNUM_16: u8 = 0x60;
    const OP_CHECKMULTISIG: u8 = 0xae;
    let pushnum = |b: u8| {
        (OP_PUSHNUM_1..=OP_PUSHNUM_16)
            .contains(&b)
            .then(|| u32::from(b - OP_PUSHNUM_1 + 1))
    };
    let k = pushnum(*script.first()?)?;
    let mut at = 1;
    let mut keys = 0u32;
    loop {
        let byte = *script.get(at)?;
        if let Some(n) = pushnum(byte) {
            let closes = *script.get(at + 1)? == OP_CHECKMULTISIG;
            return (closes && keys == n && k <= n).then_some(k);
        }
        // Compressed (33) or uncompressed (65) key pushes only.
        let len = match byte {
            0x21 | 0x41 => usize::from(byte),
            _ => return None,
        };
        at += 1 + len;
        keys += 1;
    }
}

/// One output of a PSET, classified from the inspecting wallet's side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PsetOutputInfo {
    pub index: u32,
    /// `own` (this wallet's script) | `escrow` (a P2WSH contract) |
    /// `external` | `fee`.
    pub kind: String,
    /// `p2wsh` | `p2wpkh` | `p2sh` | `other` | `fee`.
    pub script_type: String,
    /// Confidential address when a blinding key is attached, else the
    /// unconfidential one; `None` for the fee output.
    pub address: Option<String>,
    /// Asset id, only once it is provably what the signature commits to: an
    /// explicit output with no commitment, or a blinded one whose blind
    /// asset proof verifies. `None` otherwise.
    pub asset: Option<String>,
    /// Amount in satoshis, on the same terms as `asset`.
    pub amount: Option<u64>,
    /// The PSET's claimed asset/amount could not be tied to the output's
    /// commitments — a missing or failing blind proof, or a commitment on
    /// an output that also claims to be explicit. Both fields above are
    /// `None`, and the transaction must not be signed on the strength of
    /// what it says about this output.
    pub unverified: bool,
}

/// The `(asset, amount)` an output provably carries, or `None` when its
/// explicit fields cannot be checked against its commitments.
///
/// Explicit outputs must carry no commitment at all; blinded outputs must
/// name both values and prove each with the proof the blinder attached
/// (`blind_asset_proof` / `blind_value_proof`), the same check LWK makes
/// for the wallet's own outputs. Partially blinded outputs are refused.
pub fn verified_output_claims(secp: &Secp256k1<All>, output: &Output) -> Option<(AssetId, u64)> {
    match (output.asset_comm, output.amount_comm) {
        (None, None) => Some((output.asset?, output.amount?)),
        (Some(asset_comm), Some(amount_comm)) => {
            let asset = output.asset?;
            let amount = output.amount?;
            let asset_ok = output
                .blind_asset_proof
                .as_ref()?
                .blind_asset_proof_verify(secp, asset, asset_comm);
            let amount_ok = output.blind_value_proof.as_ref()?.blind_value_proof_verify(
                secp,
                amount,
                asset_comm,
                amount_comm,
            );
            (asset_ok && amount_ok).then_some((asset, amount))
        }
        _ => None,
    }
}

/// The `(asset, amount)` a foreign input provably spends, judged from the
/// PSET alone: an explicit `witness_utxo` speaks for itself (and any
/// explicit field must agree with it); a blinded one needs the input's
/// blind proofs to tie the claimed values to its commitments. `None` when
/// there is no prevout or the check fails. The wallet's own coins are not
/// judged here — their unblinded record is the better source.
pub fn verified_input_claims(secp: &Secp256k1<All>, input: &Input) -> Option<(AssetId, u64)> {
    let utxo = input.witness_utxo.as_ref()?;
    match (utxo.asset, utxo.value) {
        (Asset::Explicit(asset), Value::Explicit(amount)) => {
            let agrees =
                input.asset.is_none_or(|a| a == asset) && input.amount.is_none_or(|v| v == amount);
            agrees.then_some((asset, amount))
        }
        (Asset::Confidential(asset_comm), Value::Confidential(amount_comm)) => {
            let asset = input.asset?;
            let amount = input.amount?;
            let asset_ok = input
                .blind_asset_proof
                .as_ref()?
                .blind_asset_proof_verify(secp, asset, asset_comm);
            let amount_ok = input.blind_value_proof.as_ref()?.blind_value_proof_verify(
                secp,
                amount,
                asset_comm,
                amount_comm,
            );
            (asset_ok && amount_ok).then_some((asset, amount))
        }
        _ => None,
    }
}

/// Refuses a PSET that asks one of `ours` (lower-case hex master
/// fingerprints) to sign under a derivation whose coin type is not `1'`.
///
/// `SwSigner::sign` and Jade derive whatever path the PSET names for a
/// matching fingerprint, so a `m/84'/1776'/0'/0/i` entry — Liquid mainnet —
/// would be signed with a seed the tester also uses on mainnet. The wallet
/// is advertised as never signing mainnet; this is the check that holds
/// regardless of which caller reached the signer. Paths of other wallets'
/// keys are not judged.
pub fn refuse_non_testnet_paths(
    pset: &PartiallySignedTransaction,
    ours: &BTreeSet<String>,
) -> Result<(), TemplarError> {
    use lwk_wollet::bitcoin::bip32::ChildNumber;
    let testnet = ChildNumber::from_hardened_idx(1).expect("1 is a valid index");
    for (index, input) in pset.inputs().iter().enumerate() {
        for (fp, path) in input.bip32_derivation.values() {
            if !ours.contains(&fp.to_string().to_lowercase()) {
                continue;
            }
            if path.as_ref().get(1) != Some(&testnet) {
                return Err(LiquidError::NetworkMismatch(format!(
                    "input {index} asks key {fp} to sign at {path}, which is not a \
                     test-network derivation (coin type 1') — this wallet never signs \
                     for Liquid mainnet"
                ))
                .into());
            }
        }
    }
    Ok(())
}

/// Sighash type value of SIGHASH_ALL.
const SIGHASH_ALL: u32 = 0x01;
/// Sighash type value of SIGHASH_DEFAULT (taproot only; commits like ALL).
const SIGHASH_DEFAULT: u32 = 0x00;

/// Whether a key with one of `signers` as master fingerprint would sign
/// `input`: the fingerprint appears in its `bip32_derivation` (ECDSA) or
/// `tap_key_origins` (taproot) — the match LWK's `SwSigner` and Jade make.
fn signs_input(input: &Input, signers: &[Fingerprint]) -> bool {
    input
        .bip32_derivation
        .values()
        .any(|(fp, _)| signers.contains(fp))
        || input
            .tap_key_origins
            .values()
            .any(|(_, (fp, _))| signers.contains(fp))
}

/// Refuses a PSET whose fee outputs are not exactly one, with LWK 0.9's
/// words. LWK 0.9 refused such a PSET while reading it, so no co-signing
/// route signed one; LWK 0.20 reads it (the fee is their sum) and the rule
/// now lives here.
pub fn refuse_bad_fee_outputs(pset: &PartiallySignedTransaction) -> Result<(), TemplarError> {
    let fee_outputs = pset
        .outputs()
        .iter()
        .filter(|o| o.script_pubkey.is_empty())
        .count();
    match fee_outputs {
        1 => Ok(()),
        0 => Err(
            LiquidError::PsetInspectionFailed("PSET doesn't contain a fee output".into()).into(),
        ),
        _ => Err(LiquidError::PsetInspectionFailed("Multiple fee outputs".into()).into()),
    }
}

/// The check every signer of this crate runs before a key with one of
/// `signers` as master fingerprint touches `pset`. It only refuses; when
/// none of `signers` would sign any input it lets the PSET through, since
/// the signer then adds nothing.
///
/// - Every input such a key would sign declares no sighash type or
///   SIGHASH_ALL (SIGHASH_DEFAULT too on a taproot input). LWK 0.9's
///   signers always produced SIGHASH_ALL signatures; 0.20's sign whatever
///   type the input declares, and a SIGHASH_NONE, SINGLE or ANYONECANPAY
///   signature lets whoever holds the PSET change what it pays. Inputs only
///   other keys sign are not judged: their sighash is their signer's call.
/// - Exactly one fee output ([`refuse_bad_fee_outputs`]).
pub fn refuse_unsafe_signing(
    pset: &PartiallySignedTransaction,
    signers: &[Fingerprint],
) -> Result<(), TemplarError> {
    let ours: Vec<(usize, &Input)> = pset
        .inputs()
        .iter()
        .enumerate()
        .filter(|(_, input)| signs_input(input, signers))
        .collect();
    if ours.is_empty() {
        return Ok(());
    }
    refuse_bad_fee_outputs(pset)?;
    for (index, input) in ours {
        let Some(declared) = input.sighash_type else {
            continue;
        };
        let declared = declared.to_u32();
        let taproot_default = declared == SIGHASH_DEFAULT && lwk_common::is_taproot_input(input);
        if declared != SIGHASH_ALL && !taproot_default {
            return Err(LiquidError::SigningFailed(format!(
                "refusing to sign input {index}: it asks for sighash type 0x{declared:02x}, \
                 and this wallet signs SIGHASH_ALL only — any other type would let \
                 whoever holds the transaction change what it pays"
            ))
            .into());
        }
    }
    Ok(())
}

/// Structured details about a PSET, for display before signing.
#[derive(Debug, Clone)]
pub struct PsetDetails {
    /// Network the inspecting wallet read the PSET on (`liquid-testnet` |
    /// `liquid-regtest`); empty when built from LWK details alone.
    pub network: String,
    /// Every input, with whether it asks for this wallet's signature. Empty
    /// when built from LWK details alone (see [`Self::from_lwk`]).
    pub inputs: Vec<PsetInputInfo>,
    /// Every output, classified. Empty when built from LWK details alone.
    pub outputs: Vec<PsetOutputInfo>,
    /// Transaction fee in satoshis.
    pub fee: u64,
    /// What this transaction does to the wallet's balance, per asset id
    /// (negative = leaves the wallet, fee included). LWK computes it by
    /// really unblinding the wallet's own inputs and outputs, so unlike the
    /// explicit fields it cannot be spoofed by whoever built the PSET.
    pub net_change: BTreeMap<String, i64>,
    /// List of recipients (outputs going out of the wallet).
    pub recipients: Vec<PsetRecipient>,
    /// Fingerprints of signers who have already signed.
    pub signers_present: Vec<String>,
    /// Fingerprints of signers still needed.
    ///
    /// LWK reports every key without a signature, so on an M-of-N wallet this
    /// stays non-empty even once the PSET is finalizable — the N-M keys that
    /// never sign are "missing" forever. Read it as "who could still sign",
    /// not "who must".
    pub signers_missing: Vec<String>,
    /// True if all required signatures are present.
    ///
    /// Only meaningful for singlesig. See [`sigs_present_min`](Self::sigs_present_min)
    /// for the threshold-aware count a multisig needs.
    pub is_complete: bool,
    /// Signatures on the *least*-signed input — the number that has to reach
    /// the wallet's threshold before the PSET can be finalized. A per-input
    /// minimum, not a total: one input signed twice and another signed once
    /// leaves the transaction one signature short, and any count that averaged
    /// them would claim otherwise.
    pub sigs_present_min: u32,
    /// Keys that could sign an input (signed + unsigned) — N in M-of-N.
    pub signer_slots: u32,
}

impl PsetDetails {
    /// Returns a human-readable summary for logging/debugging.
    pub fn summary(&self) -> String {
        let status = if self.is_complete {
            "complete"
        } else {
            "incomplete"
        };
        format!(
            "Fee: {} sat, {} recipient(s), {}/{} signers, {}",
            self.fee,
            self.recipients.len(),
            self.signers_present.len(),
            self.signers_present.len() + self.signers_missing.len(),
            status,
        )
    }

    /// Converts from LWK's native `PsetDetails` into our simplified struct.
    /// The script view (`network`, `inputs`, `outputs`) stays empty here;
    /// [`crate::LiquidWalletManager::inspect_pset`] fills it in.
    pub fn from_lwk(lwk: lwk_common::PsetDetails) -> Self {
        // LWK reports the fee outputs per asset; LWK 0.9 required exactly
        // one, whose amount this was.
        let fee = lwk
            .fees()
            .values()
            .fold(0u64, |total, fee| total.saturating_add(*fee));
        let net_change: BTreeMap<String, i64> = lwk
            .balances()
            .iter()
            .map(|(asset, delta)| (asset.to_string(), *delta))
            .collect();

        // LWK copies the explicit fields of every output that is not the
        // wallet's own — unchecked. `inspect_pset` clears the ones whose
        // proofs fail once the script view is built.
        let recipients: Vec<PsetRecipient> = lwk
            .recipients()
            .iter()
            .map(|r| PsetRecipient {
                vout: r.vout(),
                address: r.address().map(|a| a.to_string()),
                asset: r.asset().map(|a| a.to_string()),
                amount: r.value(),
                unverified: false,
            })
            .collect();

        let signers_present: Vec<String> = lwk
            .fingerprints_has()
            .iter()
            .map(|fp| format!("{}", fp))
            .collect();

        let signers_missing: Vec<String> = lwk
            .fingerprints_missing()
            .iter()
            .map(|fp| format!("{}", fp))
            .collect();

        let is_complete = signers_missing.is_empty();

        let sigs_present_min = lwk
            .sig_details()
            .iter()
            .map(|s| s.has_signature().len() as u32)
            .min()
            .unwrap_or(0);
        let signer_slots = lwk
            .sig_details()
            .iter()
            .map(|s| (s.has_signature().len() + s.missing_signature().len()) as u32)
            .max()
            .unwrap_or(0);

        Self {
            network: String::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee,
            net_change,
            recipients,
            signers_present,
            signers_missing,
            is_complete,
            sigs_present_min,
            signer_slots,
        }
    }

    /// Inputs this wallet is asked to sign.
    pub fn our_inputs(&self) -> Vec<&PsetInputInfo> {
        self.inputs.iter().filter(|i| i.is_ours).collect()
    }

    /// Some output other than the fee carries an amount or asset that could
    /// not be verified against its commitment. A legitimate LWK, Jade or
    /// Templar Protocol PSET always carries the proofs, so this is the signal to
    /// refuse signing rather than a cosmetic gap.
    pub fn has_unverified_outputs(&self) -> bool {
        self.outputs.iter().any(|o| o.kind != "fee" && o.unverified)
    }

    /// Whether the PSET funds or spends a P2WSH contract (a loan escrow).
    pub fn touches_escrow(&self) -> bool {
        self.inputs.iter().any(|i| i.script_type == "p2wsh")
            || self.outputs.iter().any(|o| o.kind == "escrow")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn sample_details(complete: bool) -> PsetDetails {
        PsetDetails {
            network: String::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 250,
            net_change: BTreeMap::new(),
            recipients: vec![
                PsetRecipient {
                    vout: 0,
                    address: Some("tex1qaddr1...".into()),
                    asset: Some("144c6543...".into()),
                    amount: Some(100_000),
                    unverified: false,
                },
                PsetRecipient {
                    vout: 1,
                    address: None,
                    asset: None,
                    amount: None,
                    unverified: false,
                },
            ],
            signers_present: vec!["aabbccdd".into()],
            signers_missing: if complete {
                vec![]
            } else {
                vec!["11223344".into()]
            },
            is_complete: complete,
            sigs_present_min: 1,
            signer_slots: 2,
        }
    }

    #[test]
    fn pset_details_summary_incomplete() {
        let d = sample_details(false);
        let s = d.summary();
        assert!(s.contains("250 sat"));
        assert!(s.contains("2 recipient(s)"));
        assert!(s.contains("1/2 signers"));
        assert!(s.contains("incomplete"));
    }

    #[test]
    fn pset_details_summary_complete() {
        let d = sample_details(true);
        let s = d.summary();
        assert!(s.contains("1/1 signers"));
        assert!(s.contains("complete"));
        assert!(!s.contains("incomplete"));
    }

    #[test]
    fn pset_recipient_optional_fields() {
        let r = PsetRecipient {
            vout: 0,
            address: None,
            asset: None,
            amount: None,
            unverified: false,
        };
        assert!(r.address.is_none());
        assert!(r.asset.is_none());
        assert!(r.amount.is_none());
    }

    #[test]
    fn pset_details_no_recipients() {
        let d = PsetDetails {
            network: String::new(),
            inputs: Vec::new(),
            outputs: Vec::new(),
            fee: 0,
            net_change: BTreeMap::new(),
            recipients: vec![],
            signers_present: vec![],
            signers_missing: vec![],
            is_complete: true,
            sigs_present_min: 0,
            signer_slots: 0,
        };
        assert!(d.is_complete);
        assert!(d.summary().contains("0 recipient(s)"));
        assert!(d.summary().contains("0/0 signers"));
    }

    fn output_info(kind: &str, unverified: bool) -> PsetOutputInfo {
        PsetOutputInfo {
            index: 0,
            kind: kind.into(),
            script_type: "p2wpkh".into(),
            address: None,
            asset: None,
            amount: None,
            unverified,
        }
    }

    #[test]
    fn unverified_outputs_are_flagged_except_the_fee() {
        let mut d = sample_details(true);
        d.outputs = vec![output_info("own", false), output_info("fee", true)];
        assert!(!d.has_unverified_outputs());
        d.outputs.push(output_info("external", true));
        assert!(d.has_unverified_outputs());
    }

    // -- blind proof verification -------------------------------------------

    use lwk_wollet::elements::confidential::{AssetBlindingFactor, Nonce, ValueBlindingFactor};
    use lwk_wollet::elements::secp256k1_zkp::{Generator, PedersenCommitment};
    use lwk_wollet::elements::{OutPoint, Script, TxOut, Txid};
    use lwk_wollet::elements::{RangeProof, SurjectionProof};

    struct Blinded {
        asset: AssetId,
        asset_comm: Generator,
        amount_comm: PedersenCommitment,
        asset_proof: SurjectionProof,
        value_proof: RangeProof,
    }

    /// Commitments to `amount` of a fixed asset plus the blind proofs an
    /// honest blinder attaches (what LWK's `blind_last` / `add_input` do).
    fn blinded(secp: &Secp256k1<All>, amount: u64) -> Blinded {
        let mut rng = rand::thread_rng();
        let asset = AssetId::from_byte_array([7u8; 32]);
        let abf = AssetBlindingFactor::new(&mut rng);
        let vbf = ValueBlindingFactor::new(&mut rng);
        let asset_comm = Generator::new_blinded(secp, asset.into_tag(), abf.into_inner());
        let amount_comm = PedersenCommitment::new(secp, amount, vbf.into_inner(), asset_comm);
        Blinded {
            asset,
            asset_comm,
            amount_comm,
            asset_proof: SurjectionProof::blind_asset_proof(&mut rng, secp, asset, abf).unwrap(),
            value_proof: RangeProof::blind_value_proof(
                &mut rng,
                secp,
                amount,
                amount_comm,
                asset_comm,
                vbf,
            )
            .unwrap(),
        }
    }

    fn blinded_output(b: &Blinded, claimed_amount: u64) -> Output {
        Output {
            script_pubkey: Script::from(vec![0u8, 20, 1, 2, 3]),
            amount: Some(claimed_amount),
            amount_comm: Some(b.amount_comm),
            asset: Some(b.asset),
            asset_comm: Some(b.asset_comm),
            blind_value_proof: Some(b.value_proof.clone()),
            blind_asset_proof: Some(b.asset_proof.clone()),
            ..Default::default()
        }
    }

    #[test]
    fn output_claims_verify_only_when_the_proofs_match_the_commitments() {
        let secp = Secp256k1::new();
        let b = blinded(&secp, 1_000);
        let honest = blinded_output(&b, 1_000);
        assert_eq!(
            verified_output_claims(&secp, &honest),
            Some((b.asset, 1_000))
        );

        // The scenario from the review: the commitment says 1000, the
        // explicit field says 1 — the proof no longer matches.
        let lying = blinded_output(&b, 1);
        assert_eq!(verified_output_claims(&secp, &lying), None);

        // No proof at all: nothing ties the claim to the commitment.
        let mut bare = blinded_output(&b, 1_000);
        bare.blind_value_proof = None;
        assert_eq!(verified_output_claims(&secp, &bare), None);
        let mut bare = blinded_output(&b, 1_000);
        bare.blind_asset_proof = None;
        assert_eq!(verified_output_claims(&secp, &bare), None);

        // A wrong asset with the right amount fails the asset proof.
        let mut wrong_asset = blinded_output(&b, 1_000);
        wrong_asset.asset = Some(AssetId::from_byte_array([9u8; 32]));
        assert_eq!(verified_output_claims(&secp, &wrong_asset), None);
    }

    #[test]
    fn explicit_outputs_verify_only_without_commitments() {
        let secp = Secp256k1::new();
        let asset = AssetId::from_byte_array([7u8; 32]);
        let explicit = Output::new_explicit(Script::from(vec![0u8, 20, 1]), 500, asset, None);
        assert_eq!(verified_output_claims(&secp, &explicit), Some((asset, 500)));

        // "Explicit" fields next to a commitment: the commitment is what
        // gets signed, the fields are decoration.
        let b = blinded(&secp, 999_000);
        let mut half = explicit.clone();
        half.amount_comm = Some(b.amount_comm);
        assert_eq!(verified_output_claims(&secp, &half), None);
        let mut half = explicit.clone();
        half.asset_comm = Some(b.asset_comm);
        assert_eq!(verified_output_claims(&secp, &half), None);

        // An output that says nothing is not verified either.
        let mut silent = explicit;
        silent.amount = None;
        assert_eq!(verified_output_claims(&secp, &silent), None);
    }

    fn input_with(utxo: TxOut) -> Input {
        let txid =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();
        let mut input = Input::from_prevout(OutPoint::new(txid, 0));
        input.witness_utxo = Some(utxo);
        input
    }

    #[test]
    fn foreign_input_claims_need_proofs_against_the_prevout_commitments() {
        let secp = Secp256k1::new();
        let b = blinded(&secp, 2_000);
        let utxo = TxOut {
            asset: Asset::Confidential(b.asset_comm),
            value: Value::Confidential(b.amount_comm),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0u8, 20, 1]),
            witness: Default::default(),
        };
        let mut input = input_with(utxo.clone());
        input.asset = Some(b.asset);
        input.amount = Some(2_000);
        input.blind_asset_proof = Some(b.asset_proof.clone());
        input.blind_value_proof = Some(b.value_proof.clone());
        assert_eq!(verified_input_claims(&secp, &input), Some((b.asset, 2_000)));

        input.amount = Some(1_500);
        assert_eq!(verified_input_claims(&secp, &input), None);

        let mut unproven = input_with(utxo);
        unproven.asset = Some(b.asset);
        unproven.amount = Some(2_000);
        assert_eq!(verified_input_claims(&secp, &unproven), None);

        // No prevout at all: nothing to check against.
        let mut blind = Input::from_prevout(OutPoint::default());
        blind.amount = Some(2_000);
        assert_eq!(verified_input_claims(&secp, &blind), None);
    }

    #[test]
    fn explicit_prevouts_speak_for_themselves_but_must_agree() {
        let secp = Secp256k1::new();
        let asset = AssetId::from_byte_array([7u8; 32]);
        let utxo = TxOut {
            asset: Asset::Explicit(asset),
            value: Value::Explicit(3_000),
            nonce: Nonce::Null,
            script_pubkey: Script::from(vec![0u8, 20, 1]),
            witness: Default::default(),
        };
        let quiet = input_with(utxo.clone());
        assert_eq!(verified_input_claims(&secp, &quiet), Some((asset, 3_000)));
        let mut lying = input_with(utxo);
        lying.amount = Some(30);
        assert_eq!(verified_input_claims(&secp, &lying), None);
    }

    // -- coin type refusal ---------------------------------------------------

    fn pset_asking(fp: &str, path: &str) -> PartiallySignedTransaction {
        use lwk_wollet::bitcoin::bip32::{DerivationPath, Fingerprint};
        use lwk_wollet::bitcoin::PublicKey;
        let secp = Secp256k1::new();
        let pk = PublicKey::new(
            lwk_wollet::elements::secp256k1_zkp::SecretKey::new(&mut rand::thread_rng())
                .public_key(&secp),
        );
        let mut input = Input::from_prevout(OutPoint::default());
        input.bip32_derivation.insert(
            pk,
            (
                Fingerprint::from_str(fp).unwrap(),
                DerivationPath::from_str(path).unwrap(),
            ),
        );
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(input);
        pset
    }

    #[test]
    fn our_keys_are_refused_on_a_mainnet_coin_type() {
        let ours: BTreeSet<String> = ["73c5da0a".to_string()].into_iter().collect();
        for ok in ["m/84'/1'/0'/0/5", "m/87'/1'/0'/1/0", "m/2121'/1'/0'/0/7"] {
            refuse_non_testnet_paths(&pset_asking("73c5da0a", ok), &ours)
                .unwrap_or_else(|e| panic!("{ok}: {e}"));
        }
        for bad in ["m/84'/1776'/0'/0/5", "m/84'/0'/0'/0/5", "m/0/5", "m/5"] {
            let err = refuse_non_testnet_paths(&pset_asking("73c5da0a", bad), &ours)
                .expect_err(bad)
                .to_string();
            assert!(err.contains("mainnet"), "{bad}: {err}");
            assert!(err.contains("73c5da0a"), "{bad}: {err}");
        }
        // Somebody else's key on a mainnet path is not our call to make.
        refuse_non_testnet_paths(&pset_asking("deadbeef", "m/84'/1776'/0'/0/5"), &ours).unwrap();
    }

    // -- signing guard ------------------------------------------------------

    /// A taproot key-spend input naming `fp` in `tap_key_origins`.
    fn taproot_input(fp: Fingerprint, sighash: Option<u32>) -> Input {
        use lwk_wollet::elements::pset::PsbtSighashType;
        use lwk_wollet::elements::secp256k1_zkp::{Keypair, SecretKey};
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[5u8; 32]).unwrap());
        let (xonly, _) = keypair.x_only_public_key();
        let mut input = input_with(TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array([7u8; 32])),
            value: Value::Explicit(1_000),
            nonce: Nonce::Null,
            script_pubkey: Script::new_v1_p2tr(&secp, xonly, None),
            witness: Default::default(),
        });
        input.tap_internal_key = Some(xonly);
        input.tap_key_origins.insert(
            xonly,
            (
                vec![],
                (
                    fp,
                    lwk_wollet::bitcoin::bip32::DerivationPath::from_str("m/86'/1'/0'/0/0")
                        .unwrap(),
                ),
            ),
        );
        input.sighash_type = sighash.map(PsbtSighashType::from_u32);
        input
    }

    fn with_fee(input: Input) -> PartiallySignedTransaction {
        let mut pset = PartiallySignedTransaction::new_v2();
        pset.add_input(input);
        pset.add_output(Output::from_txout(TxOut::new_fee(
            100,
            AssetId::from_byte_array([7u8; 32]),
        )));
        pset
    }

    #[test]
    fn taproot_inputs_may_ask_for_default_or_all_only() {
        let ours = Fingerprint::from_str("73c5da0a").unwrap();
        for ok in [None, Some(0x00), Some(0x01)] {
            refuse_unsafe_signing(&with_fee(taproot_input(ours, ok)), &[ours])
                .unwrap_or_else(|e| panic!("{ok:?}: {e}"));
        }
        for bad in [0x02u32, 0x03, 0x81, 0x82, 0x83] {
            let err = refuse_unsafe_signing(&with_fee(taproot_input(ours, Some(bad))), &[ours])
                .expect_err("non-default taproot sighash")
                .to_string();
            assert!(err.contains("SIGHASH_ALL only"), "{err}");
        }
        // Someone else's taproot input is theirs to judge.
        let theirs = Fingerprint::from_str("deadbeef").unwrap();
        refuse_unsafe_signing(&with_fee(taproot_input(theirs, Some(0x83))), &[ours]).unwrap();
    }

    #[test]
    fn fee_outputs_are_counted_whoever_owns_the_inputs() {
        let ours = Fingerprint::from_str("73c5da0a").unwrap();
        let mut none = PartiallySignedTransaction::new_v2();
        none.add_input(taproot_input(ours, None));
        let err = refuse_bad_fee_outputs(&none).unwrap_err().to_string();
        assert_eq!(
            err,
            "PSET inspection failed: PSET doesn't contain a fee output"
        );
        assert!(refuse_unsafe_signing(&none, &[ours]).is_err());
        // Nobody here signs it: the signer has nothing to refuse.
        refuse_unsafe_signing(&none, &[Fingerprint::from_str("deadbeef").unwrap()]).unwrap();

        let mut two = with_fee(taproot_input(ours, None));
        two.add_output(Output::from_txout(TxOut::new_fee(
            100,
            AssetId::from_byte_array([7u8; 32]),
        )));
        let err = refuse_bad_fee_outputs(&two).unwrap_err().to_string();
        assert_eq!(err, "PSET inspection failed: Multiple fee outputs");
        refuse_bad_fee_outputs(&with_fee(taproot_input(ours, None))).unwrap();
    }

    // -- threshold parsing ---------------------------------------------------

    fn multisig_prefix(k: u8, n: u8) -> Vec<u8> {
        let mut script = vec![0x50 + k];
        for i in 0..n {
            script.push(0x21);
            script.push(0x02);
            script.extend(std::iter::repeat_n(i, 32));
        }
        script.push(0x50 + n);
        script.push(0xae);
        script
    }

    #[test]
    fn threshold_is_read_off_a_multisig_that_opens_the_script() {
        assert_eq!(multisig_threshold(&multisig_prefix(2, 3)), Some(2));
        assert_eq!(multisig_threshold(&multisig_prefix(1, 1)), Some(1));
        // The escrow shape: or_d(multi(2,…), and_v(v:pk, after)) keeps the
        // multisig up front and goes on with OP_IFDUP OP_NOTIF … OP_ENDIF.
        let mut escrow = multisig_prefix(2, 2);
        escrow.extend([0x73, 0x64, 0x21]);
        escrow.extend(std::iter::repeat_n(0x03, 33));
        escrow.extend([0xad, 0x03, 0x40, 0xf1, 0x19, 0xb1, 0x68]);
        assert_eq!(multisig_threshold(&escrow), Some(2));
        // The real thing, from the Templar Protocol fixture.
        #[cfg(feature = "protocol")]
        {
            let pset = crate::liquid::protocol::tests::escrow_spend_pset(
                &crate::liquid::network::LiquidNetwork::testnet(),
                crate::liquid::protocol::tests::dummy_payout_script(),
                1_000,
                500,
            );
            let script = pset.inputs()[0].witness_script.clone().unwrap();
            assert_eq!(multisig_threshold(script.as_bytes()), Some(2));
        }

        // Not judged: single key, k > n, wrong key count, truncated, and a
        // script that only *ends* in CHECKMULTISIG.
        let single = [0x21u8]
            .into_iter()
            .chain(std::iter::repeat_n(0x02, 33))
            .chain([0xac])
            .collect::<Vec<_>>();
        assert_eq!(multisig_threshold(&single), None);
        assert_eq!(multisig_threshold(&multisig_prefix(3, 2)), None);
        let mut short = multisig_prefix(2, 3);
        short[0] = 0x52;
        let n = short.len();
        short[n - 2] = 0x54;
        assert_eq!(multisig_threshold(&short), None);
        assert_eq!(multisig_threshold(&multisig_prefix(2, 3)[..40]), None);
        let mut tail = vec![0x63, 0x68];
        tail.extend(multisig_prefix(2, 2));
        assert_eq!(multisig_threshold(&tail), None);
        assert_eq!(multisig_threshold(&[]), None);
    }
}
