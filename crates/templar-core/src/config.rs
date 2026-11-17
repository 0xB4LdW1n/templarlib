//! Application configuration — global settings stored in `~/.config/templar_wallet.json`.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::error::{StorageError, TemplarError};
use crate::liquid::network::LiquidNetwork;
use crate::test_server::TestServerProfile;

/// Global application config, stored separately from wallet data.
///
/// Contains the pointer to the data directory, the last opened wallet ID and
/// the selected Liquid network.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AppConfig {
    /// Base data directory (e.g. `~/.local/share/templar_wallet`).
    pub data_dir: PathBuf,
    /// ID of the last opened wallet (for auto-reopen).
    pub last_wallet_id: Option<String>,
    /// Liquid network the app runs on. `None` = testnet (the default, and
    /// what every config written before the setting existed means).
    /// `TEMPLAR_LIQUID_NETWORK` overrides it at runtime without touching it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub liquid_network: Option<LiquidNetwork>,
    /// The Templar test server the wallet joined (`set_test_server`), as
    /// last fetched and validated. Absent = none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub test_server: Option<TestServerProfile>,
}

impl AppConfig {
    /// Loads the config from `~/.config/templar_wallet.json`.
    pub fn load() -> Option<Self> {
        Self::load_from(&Self::config_path())
    }

    /// Loads the config at `path`. A stored test-server profile that no
    /// longer passes the rules a fetched one meets
    /// ([`TestServerProfile::revalidate`]: edited on disk, written by a
    /// build with other rules) is dropped with a log line, so the wallet
    /// starts on its defaults instead of applying it — or panicking on it.
    pub fn load_from(path: &std::path::Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        let mut cfg: Self = serde_json::from_str(&content).ok()?;
        if let Some(profile) = &cfg.test_server {
            if let Err(e) = profile.revalidate() {
                eprintln!("[config] the stored test server is not applied: {e}");
                cfg.test_server = None;
                // Its regtest went with it; a regtest setting without a lab
                // falls back to testnet rather than a guess.
                if cfg.liquid_network.as_ref().is_some_and(|n| n.is_regtest()) {
                    cfg.liquid_network = None;
                }
            }
        }
        Some(cfg)
    }

    /// Saves the config to `~/.config/templar_wallet.json`.
    pub fn save(&self) -> Result<(), TemplarError> {
        self.save_to(&Self::config_path())
    }

    /// Saves the config to `path` (directories created as needed).
    pub fn save_to(&self, path: &std::path::Path) -> Result<(), TemplarError> {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).map_err(StorageError::IoError)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| StorageError::SerializationFailed(e.to_string()))?;
        // Atomic: a crash mid-write must not truncate the file that points
        // at the wallet data folder.
        crate::registry::atomic_write(path, &json)
    }

    /// Returns the config file path: `~/.config/templar_wallet.json`.
    pub fn config_path() -> PathBuf {
        dirs_next::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("templar_wallet.json")
    }

    /// The persisted Liquid network, testnet when unset.
    pub fn liquid_network(&self) -> LiquidNetwork {
        self.liquid_network.clone().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn app_config_serialization_roundtrip() {
        let config = AppConfig {
            data_dir: PathBuf::from("/tmp/templar_test"),
            last_wallet_id: Some("wallet-123".into()),
            liquid_network: None,
            test_server: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.data_dir, PathBuf::from("/tmp/templar_test"));
        assert_eq!(parsed.last_wallet_id.as_deref(), Some("wallet-123"));
    }

    #[test]
    fn app_config_serialization_no_wallet_id() {
        let config = AppConfig {
            data_dir: PathBuf::from("/tmp/test"),
            last_wallet_id: None,
            liquid_network: None,
            test_server: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: AppConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.last_wallet_id.is_none());
    }

    #[test]
    fn liquid_network_defaults_to_testnet_and_round_trips() {
        // A config written before the setting existed.
        let old: AppConfig =
            serde_json::from_str(r#"{"data_dir":"/tmp/x","last_wallet_id":null}"#).unwrap();
        assert_eq!(old.liquid_network(), LiquidNetwork::testnet());
        // Unset stays absent on disk, so older builds keep parsing the file.
        assert!(!serde_json::to_string(&old)
            .unwrap()
            .contains("liquid_network"));

        let cfg = AppConfig {
            data_dir: PathBuf::from("/tmp/x"),
            last_wallet_id: None,
            liquid_network: Some(LiquidNetwork::regtest_default()),
            test_server: None,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("liquid-regtest"), "{json}");
        let back: AppConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.liquid_network(), LiquidNetwork::regtest_default());
    }

    #[test]
    fn a_bad_stored_test_server_is_dropped_on_load() {
        let dir = std::env::temp_dir().join(format!("templar_cfg_bad_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("templar_wallet.json");
        let mut profile = crate::test_server::parse_config(
            "http://127.0.0.1:8096",
            crate::test_server::tests_example(),
            1,
        )
        .unwrap();
        let cfg = AppConfig {
            data_dir: dir.clone(),
            last_wallet_id: None,
            liquid_network: Some(profile.regtest.liquid_network().unwrap()),
            test_server: Some(profile.clone()),
        };
        cfg.save_to(&path).unwrap();
        let back = AppConfig::load_from(&path).unwrap();
        assert_eq!(back.test_server.as_ref(), Some(&profile));
        assert!(back.liquid_network().is_regtest());
        // Edited on disk: a non-hex policy asset. Dropped, back to testnet.
        profile.regtest.policy_asset = "not-hex".into();
        let cfg = AppConfig {
            test_server: Some(profile),
            ..cfg
        };
        std::fs::write(&path, serde_json::to_string(&cfg).unwrap()).unwrap();
        let back = AppConfig::load_from(&path).unwrap();
        assert!(back.test_server.is_none());
        assert_eq!(back.liquid_network(), LiquidNetwork::testnet());
        assert_eq!(back.data_dir, dir);
        // Saved atomically: no temporary file left behind.
        back.save_to(&path).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() != "templar_wallet.json")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_path_is_not_empty() {
        let path = AppConfig::config_path();
        assert!(!path.as_os_str().is_empty());
        assert!(path.to_string_lossy().contains("templar_wallet"));
    }

    #[test]
    fn app_config_save_and_load_tempdir() {
        // Save to a temp dir and verify roundtrip
        let tmpdir =
            std::env::temp_dir().join(format!("templar_config_test_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&tmpdir);
        let config = AppConfig {
            data_dir: tmpdir.clone(),
            last_wallet_id: Some("test-id".into()),
            liquid_network: None,
            test_server: None,
        };
        // We can't override config_path easily, but we can test serialization
        let json = serde_json::to_string_pretty(&config).unwrap();
        let path = tmpdir.join("config_test.json");
        std::fs::write(&path, &json).unwrap();
        let loaded: AppConfig =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.data_dir, tmpdir);
        assert_eq!(loaded.last_wallet_id.as_deref(), Some("test-id"));
        let _ = std::fs::remove_dir_all(&tmpdir);
    }
}
