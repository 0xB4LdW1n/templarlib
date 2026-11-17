//! Typed error hierarchy for Templar Wallet.
//!
//! All public functions in templar-core return `Result<T, TemplarError>`.
//! The desktop frontend can convert these to `anyhow::Error` at the boundary.

use thiserror::Error;

/// Top-level error type for templar-core.
#[derive(Debug, Error)]
pub enum TemplarError {
    #[error(transparent)]
    Bitcoin(#[from] BitcoinError),

    #[error(transparent)]
    Liquid(#[from] LiquidError),

    #[error(transparent)]
    Storage(#[from] StorageError),

    #[error(transparent)]
    Hardware(#[from] HardwareError),

    #[error(transparent)]
    Policy(#[from] PolicyError),

    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error(transparent)]
    TestServer(#[from] TestServerError),

    #[error(transparent)]
    Peg(#[from] PegError),
}

/// Tag of [`PegError::Unavailable`]: no peg provider on the active network.
pub const ERR_PEG_UNAVAILABLE: &str = "PEG_UNAVAILABLE";
/// Tag of [`PegError::NotReady`]: the order is not in a state that allows the step.
pub const ERR_PEG_NOT_READY: &str = "PEG_NOT_READY";
/// Tag of [`PegError::Expired`]: the deposit address or order is no longer valid.
pub const ERR_PEG_EXPIRED: &str = "PEG_EXPIRED";
/// Tag of [`PegError::ProofRejected`]: the evidence for a peg-in claim did not verify.
pub const ERR_PEG_PROOF_REJECTED: &str = "PEG_PROOF_REJECTED";
/// Tag of [`PegError::InsufficientFunds`]: the wallet cannot pay a peg's own
/// transaction (the deposit or the peg-out) and its fee.
pub const ERR_PEG_INSUFFICIENT_FUNDS: &str = "PEG_INSUFFICIENT_FUNDS";

/// What a builder adds when frozen coins were left out of a payment that
/// came up short: the balance still counts them, the builder does not.
pub const FROZEN_LEFT_OUT_HINT: &str =
    " — frozen coins are left out; unfreeze some on the UTXOs screen to spend them";

fn frozen_hint(frozen_left_out: bool) -> &'static str {
    if frozen_left_out {
        FROZEN_LEFT_OUT_HINT
    } else {
        ""
    }
}

/// A peg-in / peg-out step that cannot go ahead. The first four variants
/// start with a stable tag hosts key on; the text after it may change.
#[derive(Debug, Error)]
pub enum PegError {
    /// No peg provider serves the active network, with the reason.
    #[error("PEG_UNAVAILABLE: {0}")]
    Unavailable(String),

    /// The order is not where the step needs it (not enough confirmations
    /// yet, already funded, …). Retrying later may help.
    #[error("PEG_NOT_READY: {0}")]
    NotReady(String),

    /// The deposit address (or the provider's order) is no longer valid;
    /// nothing may be paid to it.
    #[error("PEG_EXPIRED: {0}")]
    Expired(String),

    /// The Bitcoin transaction, merkle proof or block header behind a
    /// peg-in claim did not verify against the wallet's own chain view.
    #[error("PEG_PROOF_REJECTED: {0}")]
    ProofRejected(String),

    /// The wallet holds too little of the asset a peg's own transaction
    /// spends (BTC for a peg-in deposit, L-BTC for a peg-out); the text
    /// names the chain, the asset, what it has and what is needed.
    #[error("PEG_INSUFFICIENT_FUNDS: {0}")]
    InsufficientFunds(String),

    /// A chain server or the provider could not be read.
    #[error("Peg chain access failed: {0}")]
    Chain(String),

    /// The transaction could not be built or did not come out as intended.
    #[error("Peg transaction failed: {0}")]
    Build(String),
}

/// A Templar test server (`GET <url>/api/config`) that cannot be used. Every
/// variant is a refusal at a trust boundary: the profile decides which
/// servers the wallet talks to, so nothing of a refused answer is applied.
#[derive(Debug, Error)]
pub enum TestServerError {
    #[error("Invalid test server URL: {0}")]
    InvalidUrl(String),

    #[error("Cannot reach the test server: {0}")]
    Unreachable(String),

    #[error("The test server answered HTTP {0} for /api/config")]
    Http(u16),

    #[error("The test server's /api/config is larger than {0} bytes")]
    TooLarge(u64),

    #[error(
        "This test server needs a newer wallet (its config is version {found}; this wallet \
         reads version {supported})"
    )]
    UnsupportedVersion { found: u64, supported: u32 },

    #[error("The test server's config is invalid: {0}")]
    Invalid(String),

    #[error(
        "The test server's config names a mainnet ({0}); this wallet runs on test networks only"
    )]
    Mainnet(String),
}

/// At-rest encryption / vault errors (C1).
#[derive(Debug, Error)]
pub enum VaultError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivation(String),

    #[error("Wrong passphrase")]
    WrongPassphrase,

    #[error("Vault is locked — unlock with your passphrase first")]
    Locked,

    #[error("A vault already exists on this device")]
    AlreadyExists,

    #[error("Corrupt vault data: {0}")]
    Corrupt(String),
}

/// Bitcoin wallet errors (BDK 0.30).
#[derive(Debug, Error)]
pub enum BitcoinError {
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("Transaction build failed: {0}")]
    TxBuildFailed(String),

    /// The wallet's spendable coins do not cover the payment and its fee.
    /// The text is the one [`BitcoinError::TxBuildFailed`] carried for it;
    /// the amounts are there for a caller that explains it better.
    #[error(
        "Transaction build failed: Insufficient funds: {available} sat available of {needed} \
         sat needed{}",
        frozen_hint(*frozen_left_out)
    )]
    InsufficientFunds {
        /// What the builder could spend (frozen coins left out), in sat.
        available: u64,
        /// The payment and its fee, in sat.
        needed: u64,
        /// Frozen coins were left out of the selection.
        frozen_left_out: bool,
    },

    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(String),

    #[error("PSBT error: {0}")]
    PsbtError(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Wallet not available")]
    WalletNotAvailable,

    #[error("BDK panicked: {0}")]
    Panicked(String),

    #[error("Coin {0} is frozen. Unfreeze it on the UTXOs screen to spend it.")]
    FrozenCoin(String),
}

/// Liquid wallet errors (LWK 0.20).
#[derive(Debug, Error)]
pub enum LiquidError {
    #[error("Invalid descriptor: {0}")]
    InvalidDescriptor(String),

    #[error("Sync failed: {0}")]
    SyncFailed(String),

    #[error("PSET build failed: {0}")]
    PsetBuildFailed(String),

    /// The wallet's coins of `asset_id` do not cover a payment and its fee.
    /// The text is the one [`LiquidError::PsetBuildFailed`] carried for it.
    #[error(
        "PSET build failed: {context}: Insufficient funds: missing {missing_sats} units for \
         asset {asset_id}{}",
        frozen_hint(*frozen_left_out)
    )]
    InsufficientFunds {
        /// The builder step (`Build PSET`, `Build peg-out`).
        context: String,
        /// The asset that is short (hex).
        asset_id: String,
        /// How much more of it the payment and its fee need.
        missing_sats: u64,
        /// The wallet's coins of that asset the builder could spend
        /// (frozen coins left out).
        available_sats: u64,
        /// Frozen coins were left out of the selection.
        frozen_left_out: bool,
    },

    #[error("PSET inspection failed: {0}")]
    PsetInspectionFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),

    #[error("Finalization failed: {0}")]
    FinalizationFailed(String),

    #[error("Broadcast failed: {0}")]
    BroadcastFailed(String),

    #[error("Issuance failed: {0}")]
    IssuanceFailed(String),

    #[error("Reissuance failed: {0}")]
    ReissuanceFailed(String),

    #[error("Burn failed: {0}")]
    BurnFailed(String),

    /// The operation is not available in this build (e.g. Liquid signing on a
    /// hardware wallet). Distinct from a failure: retrying never helps.
    #[error("Unsupported: {0}")]
    Unsupported(String),

    /// A network name, policy asset or address that does not fit the
    /// selected Liquid network (testnet vs. regtest).
    #[error("Invalid Liquid network: {0}")]
    InvalidNetwork(String),

    /// Something that only exists on one network was asked for on another
    /// (the public asset registry or order book on a local regtest, a PSET
    /// carrying another chain's assets). Retrying never helps.
    #[error("Not available on {network}: {what}")]
    UnavailableOnNetwork { network: String, what: String },

    /// The wallet and the chain backend disagree on the network — the wallet
    /// has to be reopened after a network switch.
    #[error("Network mismatch: {0}")]
    NetworkMismatch(String),

    #[error("Coin {0} is frozen. Unfreeze it on the UTXOs screen to spend it.")]
    FrozenCoin(String),

    /// LWK picks the inputs itself whenever a payment moves an asset other
    /// than LBTC (the builders pass it a coin list only for LBTC-only
    /// payments), so there a frozen coin cannot be left out — only refused.
    #[error(
        "This transaction would spend frozen coin {0}. A Liquid transaction that moves \
         an asset other than LBTC cannot leave coins out yet: unfreeze it on the \
         UTXOs screen to send this."
    )]
    FrozenCoinUnavoidable(String),
}

/// Storage / persistence errors.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization failed: {0}")]
    SerializationFailed(String),

    #[error("Registry corrupted: {0}")]
    RegistryCorrupted(String),
}

/// Hardware wallet errors (HWI).
#[derive(Debug, Error)]
pub enum HardwareError {
    #[error("Device not found")]
    DeviceNotFound,

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Signing failed: {0}")]
    SigningFailed(String),
}

/// Miniscript policy errors.
#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Invalid policy: {0}")]
    InvalidPolicy(String),

    #[error("Unsupported: {0}")]
    Unsupported(String),

    #[error("Compilation failed: {0}")]
    CompilationFailed(String),
}

/// Convenience alias for templar-core results.
pub type TemplarResult<T> = std::result::Result<T, TemplarError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn templar_error_from_bitcoin_error() {
        let err: TemplarError = BitcoinError::WalletNotAvailable.into();
        assert!(matches!(err, TemplarError::Bitcoin(_)));
        assert!(err.to_string().contains("not available"));
    }

    #[test]
    fn templar_error_from_liquid_error() {
        let err: TemplarError = LiquidError::SyncFailed("timeout".into()).into();
        assert!(matches!(err, TemplarError::Liquid(_)));
        assert!(err.to_string().contains("timeout"));
    }

    #[test]
    fn templar_error_from_storage_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file gone");
        let err: TemplarError = StorageError::IoError(io_err).into();
        assert!(matches!(err, TemplarError::Storage(_)));
    }

    #[test]
    fn templar_error_from_hardware_error() {
        let err: TemplarError = HardwareError::DeviceNotFound.into();
        assert!(matches!(err, TemplarError::Hardware(_)));
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn templar_error_from_policy_error() {
        let err: TemplarError = PolicyError::CompilationFailed("bad script".into()).into();
        assert!(matches!(err, TemplarError::Policy(_)));
        assert!(err.to_string().contains("bad script"));
    }

    #[test]
    fn bitcoin_error_variants_display() {
        assert!(BitcoinError::InvalidMnemonic("bad".into())
            .to_string()
            .contains("bad"));
        assert!(BitcoinError::Panicked("RefCell".into())
            .to_string()
            .contains("RefCell"));
        assert!(BitcoinError::BroadcastFailed("net".into())
            .to_string()
            .contains("net"));
    }

    #[test]
    fn liquid_error_variants_display() {
        assert!(LiquidError::PsetBuildFailed("x".into())
            .to_string()
            .contains("x"));
        assert!(LiquidError::FinalizationFailed("y".into())
            .to_string()
            .contains("y"));
        assert!(LiquidError::PsetInspectionFailed("z".into())
            .to_string()
            .contains("z"));
    }

    #[test]
    fn storage_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let storage_err = StorageError::from(io_err);
        assert!(matches!(storage_err, StorageError::IoError(_)));
        assert!(storage_err.to_string().contains("denied"));
    }

    #[test]
    fn templar_result_alias_works() {
        let ok: TemplarResult<u32> = Ok(42);
        assert!(matches!(ok, Ok(42)));
        let err: TemplarResult<u32> = Err(TemplarError::from(BitcoinError::WalletNotAvailable));
        assert!(err.is_err());
    }
}
