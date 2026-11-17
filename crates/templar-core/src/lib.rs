//! Templar Wallet core library — Bitcoin + Liquid Network wallet engine.
//!
//! Provides wallet management, key derivation, Miniscript policy compilation,
//! Liquid multisig coordination, and PSET inspection. Zero GUI dependencies.

pub mod bitcoin;
pub mod config;
pub mod cross_chain;
pub mod derivation;
pub mod endpoints;
pub mod error;
pub mod frozen;
pub mod liquid;
pub(crate) mod net;
pub mod peg;
pub mod policy;
pub mod qr;
pub mod registry;
pub mod sideswap;
pub mod test_server;
pub mod types;
pub mod vault;

// Re-exports for convenience
pub use bdk::bitcoin::Txid as BitcoinTxid;
#[cfg(feature = "hardware")]
pub use bitcoin::device::{
    enumerate_native, hid_device_count, DeviceFamily, NativeDeviceInfo,
    Transport as DeviceTransport,
};
#[cfg(feature = "hardware")]
pub use bitcoin::hardware::{
    hwi_usable, hwi_version, native_family_names, resolve_hwi_bin, HwDeviceInfo, HwPairing,
    ERR_DEVICE_NOT_FOUND, ERR_DEVICE_NOT_READY, ERR_HWI_MISSING, ERR_HWI_PERMISSION, ERR_SIGNING,
};
pub use bitcoin::multisig::{
    normalize_cosigner_key, validate_descriptor_pair, CosignerKeyInfo, CosignerRole,
    MultisigSetupInfo,
};
pub use bitcoin::psbt::{
    check_input_utxos, inspect_psbt, PsbtInputInfo, PsbtInspectionResult, PsbtOutputInfo,
    PsbtSignerInfo, UtxoStatus,
};
pub use bitcoin::wallet::{
    BitcoinBackend, FeeBumpCapabilities, FeeBumpPlan, TxPreviewIo, WalletManager,
};
pub use bitcoin::watch_only::{liquid_descriptor_from_wpkh, normalize_watch_only_descriptors};
pub use config::AppConfig;
pub use cross_chain::{
    bitcoin_contract, bitcoin_tx_hex, derive_swap_secret_key, htlc_script, liquid_contract,
    new_swap_secret, payment_hash_hex, spend_bitcoin_htlc, swap_public_key, BitcoinSpendRequest,
    CrossChain, HtlcContract, HtlcTerms, SwapSecret, MAKER_TIMEOUT_SECS, MIN_CROSS_AMOUNT_SATS,
    TAKER_TIMEOUT_SECS,
};
pub use derivation::{
    account_xpub_bip84, derive_liquid_descriptor, generate_mnemonic_phrase, hwi_fingerprint_to_hex,
    keyorigin_xpub_bip48, master_xprv, public_descriptor, slip77_blinding_key, validate_mnemonic,
    xpub_to_vpub_testnet, LiquidDerivationInfo, WalletPubInfo,
};
pub use endpoints::{Endpoints, NativePegTerms, PegProvider, Resolved, Source};
pub use error::{
    BitcoinError, HardwareError, LiquidError, PegError, PolicyError, StorageError, TemplarError,
    TemplarResult, TestServerError, VaultError, ERR_PEG_EXPIRED, ERR_PEG_NOT_READY,
    ERR_PEG_PROOF_REJECTED, ERR_PEG_UNAVAILABLE,
};
pub use frozen::{canonical_outpoint, first_frozen, CoinChain, FrozenCoins};
pub use liquid::assets::{
    known_assets, AssetInfo, AssetMetadata, AssetRegistry, CachedAssets, IssuanceResult,
    IssuedAssetInfo, LBTC_ASSET_ID, LUSDT_ASSET_ID,
};
pub use liquid::chain::{
    liquid_electrum_endpoint, ElementsRpcBackend, LiquidBackend, LiquidChain,
    DEFAULT_ELEMENTS_RPC_PASS, DEFAULT_ELEMENTS_RPC_URL, DEFAULT_ELEMENTS_RPC_USER,
};
#[cfg(feature = "hardware")]
pub use liquid::hardware::JadeLiquidSigner;
pub use liquid::hardware::{
    is_jade_model, liquid_hw_unsupported_reason, ERR_LIQUID_HW_UNSUPPORTED,
    LIQUID_HW_SIGNING_SUPPORTED,
};
pub use liquid::liquidex::{
    broadcast_transaction, broadcast_transaction_with, build_cancel_tx, make_proposal,
    proposal_utxo_unspent, proposal_utxo_unspent_with, spend_liquid_htlc, take_preview,
    take_preview_excluding, take_proposal, take_proposal_excluding, verify_proposal,
    verify_proposal_with, LiquidHtlcSpendRequest, LiquidexLeg, LiquidexProposal, SwapLeg,
    SwapNetwork, TakePreview, TakeResult, VerifyCheck, VerifyResult, LBTC_MAINNET_ASSET_ID,
    LBTC_TESTNET_ASSET_ID,
};
pub use liquid::multisig::{BlindingKeySource, LiquidMultisigSetup};
pub use liquid::network::{LiquidNetwork, REGTEST_DEFAULT_POLICY_ASSET, TESTNET_POLICY_ASSET};
#[cfg(feature = "protocol")]
pub use liquid::protocol::{
    check_pset, check_pset_shape, escrow_account_xpub, escrow_xpub_from_mnemonic, is_check_pset,
    loan_key_at_zero, proof_fake_txid, verify_check_signature, ESCROW_KEY_PATH,
    LOAN_KEY_PATH_BIP87, PROOF_PREVOUT_TAG,
};
pub use liquid::pset::{
    refuse_bad_fee_outputs, refuse_unsafe_signing, PsetDetails, PsetInputInfo, PsetOutputInfo,
    PsetRecipient,
};
pub use liquid::wallet::{
    fetch_asset_metadata, fetch_asset_metadata_on, LiquidBalance, LiquidTx, LiquidWalletManager,
    Pset, LIQUID_ELECTRUM_URL,
};
pub use liquid::watch_only::{create_watch_only, validate_ct_descriptor};
pub use policy::engine::{PolicyCompiler, PolicyKeyResolver};
pub use policy::fragments::{blocks_to_human, HashType, PolicyFragment, PolicyKey};
pub use policy::templates::PolicyTemplate;
pub use policy::validator::{PolicyValidator, SpendingPath, ValidationResult};
pub use qr::{decode_ur_parts, psbt_to_ur_parts, pset_to_ur_parts, UrDecodeResult};
pub use registry::{
    is_ct_descriptor, LiquidWalletConfig, ProfileStore, WalletData, WalletEntry, WalletProfile,
    WalletRegistry,
};
pub use test_server::{RegtestProfile, TestServerProfile};
pub use types::{Network, SyncStatus, TxInfo};
pub use vault::{KdfParams, SealedSecret, Vault, VaultHeader};
