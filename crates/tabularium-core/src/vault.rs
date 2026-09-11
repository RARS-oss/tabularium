//! A vault: one directory holding config, keys and the ledger database.

use crate::error::{Error, Result};
use crate::keys::VaultKeys;
use crate::types::Trust;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

pub const CONFIG_FILE: &str = "vault.toml";
pub const DB_FILE: &str = "ledger.db";
pub const KEYS_DIR: &str = "keys";
pub const CONFIG_VERSION: u32 = 1;
pub const ENV_VAULT: &str = "TABULARIUM_VAULT";

/// Who may assert which trust level. Channels not listed fall back to `default_max_trust`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_max_trust")]
    pub default_max_trust: Trust,
    #[serde(default)]
    pub channels: BTreeMap<String, Trust>,
}

fn default_max_trust() -> Trust {
    Trust::User
}

impl Default for Policy {
    fn default() -> Self {
        Policy { default_max_trust: Trust::User, channels: BTreeMap::new() }
    }
}

impl Policy {
    pub fn max_trust_for(&self, channel: &str) -> Trust {
        self.channels.get(channel).copied().unwrap_or(self.default_max_trust)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultConfig {
    pub version: u32,
    pub name: String,
    /// Root for relative check paths. Absolute, or relative to the vault directory.
    /// When absent, the process working directory at open time is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(default)]
    pub policy: Policy,
}

pub struct Vault {
    pub(crate) dir: PathBuf,
    pub(crate) config: VaultConfig,
    pub(crate) keys: VaultKeys,
    pub(crate) conn: Connection,
    pub(crate) root: PathBuf,
}

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS events (
    seq          INTEGER PRIMARY KEY,
    id           TEXT NOT NULL UNIQUE,
    ts           TEXT NOT NULL,
    channel      TEXT NOT NULL,
    kind         TEXT NOT NULL,
    trust        INTEGER NOT NULL,
    payload      TEXT,
    payload_hash TEXT NOT NULL,
    prev_hash    TEXT NOT NULL,
    hash         TEXT NOT NULL,
    sig          TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS events_append_only_update BEFORE UPDATE ON events
BEGIN
    SELECT CASE WHEN NOT (
        NEW.payload IS NULL
        AND NEW.seq = OLD.seq AND NEW.id = OLD.id AND NEW.ts = OLD.ts
        AND NEW.channel = OLD.channel AND NEW.kind = OLD.kind AND NEW.trust = OLD.trust
        AND NEW.payload_hash = OLD.payload_hash AND NEW.prev_hash = OLD.prev_hash
        AND NEW.hash = OLD.hash AND NEW.sig = OLD.sig
    ) THEN RAISE(ABORT, 'events are append-only; only payload redaction is allowed') END;
END;
CREATE TRIGGER IF NOT EXISTS events_append_only_delete BEFORE DELETE ON events
BEGIN
    SELECT RAISE(ABORT, 'events are append-only');
END;
CREATE TABLE IF NOT EXISTS memories (
    id            TEXT PRIMARY KEY,
    seq           INTEGER NOT NULL,
    kind          TEXT NOT NULL,
    text          TEXT NOT NULL,
    subject       TEXT,
    trust         INTEGER NOT NULL,
    evidence      TEXT NOT NULL,
    checks        TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    superseded_by TEXT,
    tombstoned    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS memories_subject ON memories(subject);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS receipts (
    id   TEXT PRIMARY KEY,
    ts   TEXT NOT NULL,
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    sig  TEXT NOT NULL
);
"#;

impl Vault {
    /// Default vault location: `~/.tabularium/default`.
    pub fn default_dir() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".tabularium").join("default")
    }

    /// Explicit path, else `TABULARIUM_VAULT`, else the default location.
    pub fn resolve_dir(explicit: Option<&Path>) -> PathBuf {
        if let Some(p) = explicit {
            return p.to_path_buf();
        }
        if let Ok(v) = std::env::var(ENV_VAULT)
            && !v.trim().is_empty()
        {
            return PathBuf::from(v);
        }
        Vault::default_dir()
    }

    pub fn exists(dir: &Path) -> bool {
        dir.join(CONFIG_FILE).is_file()
    }

    /// Create a new vault. Fails if one already exists at `dir`.
    pub fn init(dir: &Path, name: &str, root: Option<&Path>) -> Result<Vault> {
        if Vault::exists(dir) {
            return Err(Error::Config(format!("vault already exists at {}", dir.display())));
        }
        fs::create_dir_all(dir)?;
        let keys = VaultKeys::generate()?;
        keys.save(&dir.join(KEYS_DIR))?;
        let config = VaultConfig {
            version: CONFIG_VERSION,
            name: name.to_string(),
            root: root.map(|p| p.to_string_lossy().to_string()),
            policy: Policy::default(),
        };
        let toml_text = toml::to_string_pretty(&config).map_err(|e| Error::Config(format!("serialize config: {e}")))?;
        fs::write(dir.join(CONFIG_FILE), toml_text)?;
        Vault::open(dir)
    }

    pub fn open(dir: &Path) -> Result<Vault> {
        if !Vault::exists(dir) {
            return Err(Error::Config(format!(
                "no vault at {} (run `tabularium init` first)",
                dir.display()
            )));
        }
        let raw = fs::read_to_string(dir.join(CONFIG_FILE))?;
        let config: VaultConfig = toml::from_str(&raw).map_err(|e| Error::Config(format!("parse vault.toml: {e}")))?;
        if config.version != CONFIG_VERSION {
            return Err(Error::Config(format!(
                "unsupported vault config version {} (expected {CONFIG_VERSION})",
                config.version
            )));
        }
        let keys = VaultKeys::load(&dir.join(KEYS_DIR))?;
        let conn = Connection::open(dir.join(DB_FILE))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "FULL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;
        conn.execute_batch(SCHEMA)?;
        let root = match &config.root {
            Some(r) => {
                let p = PathBuf::from(r);
                if p.is_absolute() { p } else { dir.join(p) }
            }
            None => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        };
        Ok(Vault { dir: dir.to_path_buf(), config, keys, conn, root })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Override the root for relative check paths (e.g. per MCP session).
    pub fn set_root(&mut self, root: PathBuf) {
        self.root = root;
    }

    pub fn public_key_hex(&self) -> String {
        self.keys.public_key_hex()
    }

    pub(crate) fn meta_get(&self, key: &str) -> Result<Option<String>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get::<_, String>(0))
            .optional()?)
    }
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}
