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

use lwk_wollet::bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint};
use lwk_wollet::elements::confidential::{Asset, Value};
use lwk_wollet::elements::pset::{Input, Output, PartiallySignedTransaction};
use lwk_wollet::elements::secp256k1_zkp::{All, Secp256k1};
use lwk_wollet::elements::{AssetId, Script};
use lwk_wollet::elements_miniscript::{
    DefiniteDescriptorKey, Descriptor, DescriptorPublicKey, ForEachKey, ToPublicKey,
};

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
/// `signers` as master fingerprint touches `pset`. `wallet` is the
/// descriptor (without its blinding key) of the wallet those keys sign
/// for, when the caller has one. It only refuses; when none of `signers`
/// would sign any input it lets the PSET through, since the signer then
/// adds nothing.
///
/// - No input such a key would sign is a taproot input or names the key in
///   `tap_key_origins`: this wallet does not sign taproot inputs on Liquid.
///   LWK 0.9 never signed through `tap_key_origins`; 0.20 does, with
///   whatever path the PSET names — a mainnet coin type included, which
///   [`refuse_non_testnet_paths`] (it reads `bip32_derivation`) does not
///   see.
/// - Every input such a key would sign declares no sighash type or
///   SIGHASH_ALL. LWK 0.9's signers always produced SIGHASH_ALL signatures;
///   0.20's sign whatever type the input declares, and a SIGHASH_NONE,
///   SINGLE or ANYONECANPAY signature lets whoever holds the PSET change
///   what it pays.
/// - Exactly one fee output ([`refuse_bad_fee_outputs`]).
/// - No input is a peg-in. The one peg-in this wallet signs is the claim of
///   its own peg-in order, through
///   [`LiquidWalletManager::sign_own_pegin_claim`](crate::LiquidWalletManager::sign_own_pegin_claim),
///   which is not this function.
/// - Every input such a key would sign says truthfully which coin it spends
///   ([`refuse_unowned_input`]): a key of `wallet` signs only the very
///   coin `wallet` derives at that key's path, and any other key of ours
///   only a coin whose declared script is the script the signature commits
///   to. Otherwise a PSET could name the wallet's own P2WPKH coin as
///   someone else's P2WSH contract — the review would show nothing of the
///   wallet's leaving, and the signature would spend it.
///
/// Inputs only other keys sign are not judged: they are their signer's call.
pub fn refuse_unsafe_signing(
    pset: &PartiallySignedTransaction,
    signers: &[Fingerprint],
    wallet: Option<&Descriptor<DescriptorPublicKey>>,
) -> Result<(), TemplarError> {
    refuse_unsafe_signing_except(pset, signers, wallet, None)
}

/// [`refuse_unsafe_signing`], letting input `own_pegin` be a peg-in. Only
/// [`LiquidWalletManager::sign_own_pegin_claim`](crate::LiquidWalletManager::sign_own_pegin_claim)
/// passes `Some`, after checking the claim against the wallet's own order.
pub(crate) fn refuse_unsafe_signing_except(
    pset: &PartiallySignedTransaction,
    signers: &[Fingerprint],
    wallet: Option<&Descriptor<DescriptorPublicKey>>,
    own_pegin: Option<usize>,
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
    for &(index, input) in &ours {
        let names_tap_key = input
            .tap_key_origins
            .values()
            .any(|(_, (fp, _))| signers.contains(fp));
        if names_tap_key || lwk_common::is_taproot_input(input) {
            return Err(refusal(
                index,
                "it is a taproot input, and this wallet does not sign taproot inputs on Liquid",
            ));
        }
        let Some(declared) = input.sighash_type else {
            continue;
        };
        let declared = declared.to_u32();
        if declared != SIGHASH_ALL {
            return Err(refusal(
                index,
                format!(
                    "it asks for sighash type 0x{declared:02x}, and this wallet signs \
                     SIGHASH_ALL only — any other type would let whoever holds the \
                     transaction change what it pays"
                ),
            ));
        }
    }
    for (index, input) in pset.inputs().iter().enumerate() {
        if input.is_pegin() && own_pegin != Some(index) {
            return Err(refusal(
                index,
                "it claims a peg-in, and this wallet signs a peg-in only as the claim of \
                 one of its own peg-in orders (peg_claim)",
            ));
        }
    }
    let singles = wallet
        .and_then(|d| d.clone().into_single_descriptors().ok())
        .unwrap_or_default();
    for (index, input) in ours {
        refuse_unowned_input(index, input, signers, &singles)?;
    }
    Ok(())
}

/// `Signing failed: refusing to sign input <index>: <why>`.
fn refusal(index: usize, why: impl std::fmt::Display) -> TemplarError {
    LiquidError::SigningFailed(format!("refusing to sign input {index}: {why}")).into()
}

/// Elements' flag on a peg-in input's outpoint index.
const PEGIN_FLAG: u32 = 1 << 30;

/// Refuses input `index` unless, for every key of `signers` it names, the
/// coin it declares is the coin that key's signature would spend:
///
/// - It carries a `witness_utxo` (the coin), and a `non_witness_utxo`, when
///   present, is the transaction of that outpoint and holds that very
///   output.
/// - A key at a path of the wallet's descriptor (`singles`: same master
///   fingerprint, the path the descriptor derives at that path's last
///   index) signs only the coin the descriptor derives there: the same
///   scriptPubKey, the same key, and exactly the witness / redeem scripts
///   the descriptor gives that coin. That is LWK's ownership rule, so an
///   input such a key signs is always one inspection counts as the
///   wallet's.
/// - Any other key of ours (a loan key, a cosigner key of another wallet,
///   or every key when no descriptor is known) signs a P2WPKH coin locked
///   to that key with no witness script, or a P2WSH coin whose witness
///   script hashes to it and is not a P2PKH script code. Nothing else: a
///   P2SH wrapper or a P2PKH script code in a P2WSH lets a signature over
///   one declared script spend a P2WPKH coin of the same key.
fn refuse_unowned_input(
    index: usize,
    input: &Input,
    signers: &[Fingerprint],
    singles: &[Descriptor<DescriptorPublicKey>],
) -> Result<(), TemplarError> {
    let Some(coin) = &input.witness_utxo else {
        return Err(refusal(
            index,
            "it does not say which coin it spends (no witness_utxo)",
        ));
    };
    if let Some(tx) = &input.non_witness_utxo {
        let vout = (input.previous_output_index & !PEGIN_FLAG) as usize;
        let agrees = tx.txid() == input.previous_txid
            && tx.output.get(vout).is_some_and(|o| {
                o.script_pubkey == coin.script_pubkey
                    && o.asset == coin.asset
                    && o.value == coin.value
                    && o.nonce == coin.nonce
            });
        if !agrees {
            return Err(refusal(
                index,
                "its non_witness_utxo and its witness_utxo describe different coins",
            ));
        }
    }
    let spk = &coin.script_pubkey;
    for (pk, (fp, path)) in &input.bip32_derivation {
        if !signers.contains(fp) {
            continue;
        }
        match descriptor_coin_at(singles, *fp, path) {
            Some((derived, key)) => {
                if derived.script_pubkey() != *spk {
                    return Err(refusal(
                        index,
                        format!(
                            "it asks this wallet's key {fp} at {path} to sign, but the coin it \
                             names is not the coin this wallet derives at that path"
                        ),
                    ));
                }
                if key.to_public_key() != *pk {
                    return Err(refusal(
                        index,
                        format!("it names {pk} at {path}, which is not the key this wallet derives there"),
                    ));
                }
                let Some((redeem, witness)) = descriptor_scripts(&derived) else {
                    return Err(refusal(
                        index,
                        format!("this wallet does not sign {} coins", derived.desc_type()),
                    ));
                };
                if input.redeem_script != redeem {
                    return Err(refusal(
                        index,
                        "its redeem_script is not the one this wallet's coin has",
                    ));
                }
                if input.witness_script != witness {
                    return Err(refusal(
                        index,
                        "its witness_script is not the one this wallet's coin has",
                    ));
                }
            }
            None => refuse_foreign_coin(index, input, spk, pk)?,
        }
    }
    Ok(())
}

/// The coin a key of ours outside the wallet's descriptor may sign: see
/// [`refuse_unowned_input`].
fn refuse_foreign_coin(
    index: usize,
    input: &Input,
    spk: &Script,
    pk: &lwk_wollet::bitcoin::PublicKey,
) -> Result<(), TemplarError> {
    if spk.is_p2sh() || input.redeem_script.is_some() {
        return Err(refusal(
            index,
            "it spends a P2SH-wrapped coin, which a key of this wallet never signs — the wrapper \
             would let the signature spend a coin other than the one it names",
        ));
    }
    if spk.is_v0_p2wpkh() {
        if input.witness_script.is_some() {
            return Err(refusal(
                index,
                "it names a P2WPKH coin together with a witness_script, which such a coin \
                 does not have",
            ));
        }
        let locked_to_key = pk
            .wpubkey_hash()
            .is_ok_and(|hash| *spk == Script::new_v0_wpkh(&hash));
        if !locked_to_key {
            return Err(refusal(
                index,
                format!(
                    "the P2WPKH coin it names is not the coin of {pk}, the key it asks to sign"
                ),
            ));
        }
        return Ok(());
    }
    if spk.is_v0_p2wsh() {
        let Some(witness_script) = &input.witness_script else {
            return Err(refusal(
                index,
                "it names a P2WSH coin without its witness_script",
            ));
        };
        if witness_script.to_v0_p2wsh() != *spk {
            return Err(refusal(
                index,
                "its witness_script is not the script of the coin it names",
            ));
        }
        if witness_script.is_p2pkh() {
            return Err(refusal(
                index,
                "its witness_script is a P2PKH script code — the script a P2WPKH coin is signed \
                 under — so the signature would spend a P2WPKH coin, not the P2WSH coin it names",
            ));
        }
        return Ok(());
    }
    Err(refusal(
        index,
        "it spends a coin that is neither P2WPKH nor P2WSH, and this wallet signs no other kind",
    ))
}

/// The coin `singles` derives at `path`'s last index whose key is `fp` at
/// exactly `path`, with that key. `None`: `path` is not a path of the
/// wallet's descriptor.
fn descriptor_coin_at(
    singles: &[Descriptor<DescriptorPublicKey>],
    fp: Fingerprint,
    path: &DerivationPath,
) -> Option<(Descriptor<DefiniteDescriptorKey>, DefiniteDescriptorKey)> {
    let ChildNumber::Normal { index } = *path.into_iter().last()? else {
        return None;
    };
    singles.iter().find_map(|single| {
        let derived = single.at_derivation_index(index).ok()?;
        let mut found = None;
        derived.for_each_key(|key| {
            if found.is_none()
                && key.master_fingerprint() == fp
                && key.full_derivation_path().as_ref() == Some(path)
            {
                found = Some(key.clone());
            }
            true
        });
        found.map(|key| (derived, key))
    })
}

/// `(redeem_script, witness_script)` a PSET input spending a coin of
/// `derived` carries — what `update_input_with_descriptor` writes. `None`
/// for a descriptor type without a script code (taproot).
fn descriptor_scripts(
    derived: &Descriptor<DefiniteDescriptorKey>,
) -> Option<(Option<Script>, Option<Script>)> {
    use lwk_wollet::elements_miniscript::descriptor::DescriptorType as T;
    let explicit = derived.explicit_script().ok()?;
    Some(match derived.desc_type() {
        T::Bare | T::Pkh | T::Wpkh => (None, None),
        T::Wsh | T::WshSortedMulti => (None, Some(explicit)),
        T::ShWsh | T::ShWshSortedMulti => (Some(explicit.to_v0_p2wsh()), Some(explicit)),
        T::Sh | T::ShWpkh | T::ShSortedMulti => (Some(explicit), None),
        _ => return None,
    })
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
    fn our_taproot_inputs_are_never_signed_whatever_their_sighash() {
        let ours = Fingerprint::from_str("73c5da0a").unwrap();
        for sighash in [
            None,
            Some(0x00),
            Some(0x01),
            Some(0x02),
            Some(0x81),
            Some(0x83),
        ] {
            let err = refuse_unsafe_signing(&with_fee(taproot_input(ours, sighash)), &[ours], None)
                .expect_err("our taproot input")
                .to_string();
            assert!(
                err.starts_with("Signing failed: refusing to sign input 0:")
                    && err.contains("does not sign taproot inputs"),
                "{sighash:?}: {err}"
            );
        }
        // A taproot output named only through `bip32_derivation` is refused
        // as well: what makes it taproot is the coin it spends.
        let mut by_bip32 = taproot_input(Fingerprint::from_str("deadbeef").unwrap(), None);
        let pk = lwk_wollet::bitcoin::PublicKey::new(
            lwk_wollet::elements::secp256k1_zkp::SecretKey::from_slice(&[6u8; 32])
                .unwrap()
                .public_key(&Secp256k1::new()),
        );
        by_bip32.bip32_derivation.insert(
            pk,
            (
                ours,
                lwk_wollet::bitcoin::bip32::DerivationPath::from_str("m/84'/1'/0'/0/0").unwrap(),
            ),
        );
        assert!(refuse_unsafe_signing(&with_fee(by_bip32), &[ours], None).is_err());
        // Someone else's taproot input is theirs to judge.
        let theirs = Fingerprint::from_str("deadbeef").unwrap();
        refuse_unsafe_signing(&with_fee(taproot_input(theirs, Some(0x83))), &[ours], None).unwrap();
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
        assert!(refuse_unsafe_signing(&none, &[ours], None).is_err());
        // Nobody here signs it: the signer has nothing to refuse.
        refuse_unsafe_signing(&none, &[Fingerprint::from_str("deadbeef").unwrap()], None).unwrap();

        let mut two = with_fee(taproot_input(ours, None));
        two.add_output(Output::from_txout(TxOut::new_fee(
            100,
            AssetId::from_byte_array([7u8; 32]),
        )));
        let err = refuse_bad_fee_outputs(&two).unwrap_err().to_string();
        assert_eq!(err, "PSET inspection failed: Multiple fee outputs");
        refuse_bad_fee_outputs(&with_fee(taproot_input(ours, None))).unwrap();
    }

    // -- ownership: keys outside a wallet descriptor --------------------------

    /// A key of ours at a loan path, and a stranger's key.
    fn loan_and_stranger() -> (
        lwk_wollet::bitcoin::PublicKey,
        Fingerprint,
        DerivationPath,
        lwk_wollet::bitcoin::PublicKey,
    ) {
        use lwk_wollet::elements::secp256k1_zkp::SecretKey;
        let secp = Secp256k1::new();
        let key = |b: u8| {
            lwk_wollet::bitcoin::PublicKey::new(
                SecretKey::from_slice(&[b; 32]).unwrap().public_key(&secp),
            )
        };
        (
            key(6),
            Fingerprint::from_str("73c5da0a").unwrap(),
            DerivationPath::from_str("m/2121'/1'/0'/0/7").unwrap(),
            key(9),
        )
    }

    /// An input naming `pk` at `path` of `fp`, spending `spk`.
    fn named(
        spk: Script,
        pk: lwk_wollet::bitcoin::PublicKey,
        fp: Fingerprint,
        path: &DerivationPath,
    ) -> Input {
        let mut input = input_with(TxOut {
            asset: Asset::Explicit(AssetId::from_byte_array([7u8; 32])),
            value: Value::Explicit(1_000),
            nonce: Nonce::Null,
            script_pubkey: spk,
            witness: Default::default(),
        });
        input.bip32_derivation.insert(pk, (fp, path.clone()));
        input
    }

    #[test]
    fn a_key_outside_the_descriptor_signs_only_a_coin_named_as_what_it_is() {
        use lwk_wollet::elements::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2};
        use lwk_wollet::elements::script::Builder;
        use lwk_wollet::elements::{Address, AddressParams};
        let (pk, ours, path, stranger) = loan_and_stranger();
        let p2wpkh = Address::p2wpkh(&pk, None, &AddressParams::LIQUID_TESTNET).script_pubkey();
        let escrow = Builder::new()
            .push_opcode(OP_PUSHNUM_2)
            .push_key(&pk)
            .push_key(&stranger)
            .push_opcode(OP_PUSHNUM_2)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script();
        let check = |input: Input| refuse_unsafe_signing(&with_fee(input), &[ours], None);

        // What the protocol signs: the check PSET's P2WPKH, an escrow P2WSH.
        check(named(p2wpkh.clone(), pk, ours, &path)).unwrap();
        let mut input = named(escrow.to_v0_p2wsh(), pk, ours, &path);
        input.witness_script = Some(escrow.clone());
        check(input).unwrap();

        let refused = |input: Input, words: &str| {
            let err = check(input).unwrap_err().to_string();
            assert!(
                err.starts_with("Signing failed: refusing to sign input 0:") && err.contains(words),
                "{words}: {err}"
            );
        };
        // The P2PKH script code of the key inside a P2WSH.
        let code = Address::p2pkh(&pk, None, &AddressParams::LIQUID_TESTNET).script_pubkey();
        let mut input = named(code.to_v0_p2wsh(), pk, ours, &path);
        input.witness_script = Some(code);
        refused(input, "P2PKH script code");
        // Nested in P2SH.
        let mut input = named(p2wpkh.to_p2sh(), pk, ours, &path);
        input.redeem_script = Some(p2wpkh.clone());
        refused(input, "P2SH-wrapped");
        // Another key's P2WPKH, or a P2WPKH with a witness script.
        let other =
            Address::p2wpkh(&stranger, None, &AddressParams::LIQUID_TESTNET).script_pubkey();
        refused(named(other, pk, ours, &path), "is not the coin of");
        let mut input = named(p2wpkh.clone(), pk, ours, &path);
        input.witness_script = Some(escrow.clone());
        refused(input, "together with a witness_script");
        // A P2WSH without its script, or with another script.
        refused(
            named(escrow.to_v0_p2wsh(), pk, ours, &path),
            "without its witness_script",
        );
        let mut input = named(escrow.to_v0_p2wsh(), pk, ours, &path);
        input.witness_script = Some(Script::from(vec![0x51]));
        refused(input, "not the script of the coin");
        // Neither P2WPKH nor P2WSH; no coin at all.
        let legacy = Address::p2pkh(&pk, None, &AddressParams::LIQUID_TESTNET).script_pubkey();
        refused(named(legacy, pk, ours, &path), "neither P2WPKH nor P2WSH");
        let mut input = named(p2wpkh, pk, ours, &path);
        input.witness_utxo = None;
        refused(input, "no witness_utxo");

        // A stranger's key on the same input is not judged.
        let mut input = named(
            Script::from(vec![0x51]),
            stranger,
            Fingerprint::from_str("deadbeef").unwrap(),
            &path,
        );
        input.witness_utxo = None;
        check(input).unwrap();
    }

    #[test]
    fn a_peg_in_anywhere_is_refused_once_a_key_of_ours_signs() {
        let (pk, ours, path, stranger) = loan_and_stranger();
        let p2wpkh = lwk_wollet::elements::Address::p2wpkh(
            &pk,
            None,
            &lwk_wollet::elements::AddressParams::LIQUID_TESTNET,
        )
        .script_pubkey();
        let mut pset = with_fee(named(p2wpkh.clone(), pk, ours, &path));
        refuse_unsafe_signing(&pset, &[ours], None).unwrap();
        // Someone else's peg-in beside our input.
        let mut theirs = named(
            p2wpkh,
            stranger,
            Fingerprint::from_str("deadbeef").unwrap(),
            &path,
        );
        theirs.previous_output_index |= PEGIN_FLAG;
        pset.add_input(theirs);
        let err = refuse_unsafe_signing(&pset, &[ours], None)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("Signing failed: refusing to sign input 1:") && err.contains("peg-in"),
            "{err}"
        );
        // The claim route's allowance covers exactly the input it names.
        refuse_unsafe_signing_except(&pset, &[ours], None, Some(1)).unwrap();
        assert!(refuse_unsafe_signing_except(&pset, &[ours], None, Some(0)).is_err());
        // Nobody of ours signs: nothing to refuse.
        refuse_unsafe_signing(&pset, &[Fingerprint::from_str("0badf00d").unwrap()], None).unwrap();
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
