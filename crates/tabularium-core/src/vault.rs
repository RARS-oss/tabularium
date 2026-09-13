//! A vault: one directory holding config, keys and the ledger database.

use crate::embed::{Embedder, EmbeddingConfig, ENV_NO_EMBED};
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
pub const ENV_IDENTITY: &str = "TABULARIUM_IDENTITY";

/// A registered writer: a public key the vault owner has authorized, with a name for humans and a
/// trust ceiling for the engine. Mirrors an SSH `authorized_keys` entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WriterPolicy {
    pub name: String,
    pub max_trust: Trust,
}

/// Who may assert which trust level. Channels not listed fall back to `default_max_trust`; this is
/// a labeling convention, not a security boundary (`channel` is self-reported). `writers` is the
/// real boundary: a public key not listed here caps at `Trust::External` regardless of channel,
/// enforced by `Vault::check_writer_trust` against a signature only that key could have produced.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default = "default_max_trust")]
    pub default_max_trust: Trust,
    #[serde(default)]
    pub channels: BTreeMap<String, Trust>,
    #[serde(default)]
    pub writers: BTreeMap<String, WriterPolicy>,
}

fn default_max_trust() -> Trust {
    Trust::User
}

impl Default for Policy {
    fn default() -> Self {
        Policy { default_max_trust: Trust::User, channels: BTreeMap::new(), writers: BTreeMap::new() }
    }
}

impl Policy {
    pub fn max_trust_for(&self, channel: &str) -> Trust {
        self.channels.get(channel).copied().unwrap_or(self.default_max_trust)
    }

    /// Trust ceiling for a registered writer's public key, or `Trust::External` when the key is
    /// not (or no longer) registered -- the safe default for an unknown or revoked signer.
    pub fn max_trust_for_writer(&self, pubkey_hex: &str) -> Trust {
        self.writers.get(pubkey_hex).map(|w| w.max_trust).unwrap_or(Trust::External)
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
    #[serde(default)]
    pub embeddings: EmbeddingConfig,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EmbedderState {
    /// Not attempted yet; resolved lazily from config on first need.
    Unresolved,
    /// Disabled by config, environment, explicit call, or a failed load.
    Disabled,
    Ready,
}

pub struct Vault {
    pub(crate) dir: PathBuf,
    pub(crate) config: VaultConfig,
    pub(crate) keys: VaultKeys,
    pub(crate) conn: Connection,
    pub(crate) root: PathBuf,
    pub(crate) embedder: Option<Box<dyn Embedder>>,
    pub(crate) embedder_state: EmbedderState,
    /// This process's writer identity, if any. `None` means events are signed only by the vault's
    /// own custodial key (`keys`), exactly as before this feature existed.
    pub(crate) writer: Option<VaultKeys>,
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
CREATE TABLE IF NOT EXISTS embeddings (
    memory_id TEXT PRIMARY KEY,
    model     TEXT NOT NULL,
    dim       INTEGER NOT NULL,
    vector    BLOB NOT NULL
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
            embeddings: EmbeddingConfig::default(),
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
        Ok(Vault {
            dir: dir.to_path_buf(),
            config,
            keys,
            conn,
            root,
            embedder: None,
            embedder_state: EmbedderState::Unresolved,
            writer: None,
        })
    }

    /// Default model cache: `~/.tabularium/models`.
    pub fn models_dir() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".tabularium").join("models")
    }

    /// Default personal identity location: `~/.tabularium/identity`. A keypair here is reusable
    /// across any vault (like `~/.ssh/id_ed25519`), separate from any single vault's own key.
    pub fn identity_dir() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".tabularium").join("identity")
    }

    /// Explicit path, else `TABULARIUM_IDENTITY`, else the default location -- regardless of
    /// whether a keypair actually lives there yet. Used by `identity init`/`show`, which need to
    /// know *where* to create or read one.
    pub fn resolve_identity_path(explicit: Option<&Path>) -> PathBuf {
        if let Some(p) = explicit {
            return p.to_path_buf();
        }
        if let Ok(v) = std::env::var(ENV_IDENTITY)
            && !v.trim().is_empty()
        {
            return PathBuf::from(v);
        }
        Vault::identity_dir()
    }

    /// Same resolution as [`Vault::resolve_identity_path`], but `None` unless a keypair already
    /// exists there -- so opening a vault with no identity configured anywhere is a pure no-op and
    /// stays in today's single-custodian-key mode.
    pub fn resolve_identity_dir(explicit: Option<&Path>) -> Option<PathBuf> {
        let dir = Vault::resolve_identity_path(explicit);
        dir.join(crate::keys::SECRET_FILE).is_file().then_some(dir)
    }

    /// Install (or explicitly disable, with `None`) the embedder. Overrides config resolution.
    pub fn set_embedder(&mut self, embedder: Option<Box<dyn Embedder>>) {
        self.embedder_state = if embedder.is_some() { EmbedderState::Ready } else { EmbedderState::Disabled };
        self.embedder = embedder;
    }

    /// Install (or clear, with `None`) this process's writer identity. Events appended afterward
    /// are additionally signed by it and trust-capped by its registry entry (`Policy.writers`);
    /// `None` (the default) keeps today's behavior of signing only with the vault's own key.
    pub fn set_writer_identity(&mut self, writer: Option<VaultKeys>) {
        self.writer = writer;
    }

    /// This process's writer public key, if an identity is configured.
    pub fn writer_public_key_hex(&self) -> Option<String> {
        self.writer.as_ref().map(|k| k.public_key_hex())
    }

    /// Resolve the embedder from config on first use. Failures disable embeddings for this
    /// process and are reported once on stderr; the engine keeps working lexically.
    pub(crate) fn ensure_embedder(&mut self) {
        if self.embedder_state != EmbedderState::Unresolved {
            return;
        }
        self.embedder_state = EmbedderState::Disabled;
        if !self.config.embeddings.enabled {
            return;
        }
        if std::env::var(ENV_NO_EMBED).map(|v| v == "1").unwrap_or(false) {
            return;
        }
        #[cfg(feature = "fastembed")]
        {
            let cache = self
                .config
                .embeddings
                .cache_dir
                .as_ref()
                .map(PathBuf::from)
                .unwrap_or_else(Vault::models_dir);
            match crate::embed::onnx::OnnxEmbedder::new(&self.config.embeddings.model, &cache, true) {
                Ok(e) => {
                    self.embedder = Some(Box::new(e));
                    self.embedder_state = EmbedderState::Ready;
                }
                Err(e) => eprintln!("[tabularium] embeddings disabled: {e}"),
            }
        }
    }

    /// Whether semantic recall is available (resolving the embedder if needed).
    pub fn has_embedder(&mut self) -> bool {
        self.ensure_embedder();
        self.embedder.is_some()
    }

    /// Model id of the active embedder, if any.
    pub fn embedding_model_id(&mut self) -> Option<String> {
        self.ensure_embedder();
        self.embedder.as_ref().map(|e| e.model_id().to_string())
    }

    /// Embed one text with the active embedder. `None` when embeddings are unavailable.
    pub(crate) fn embed_texts(&mut self, texts: &[&str]) -> Option<(String, Vec<Vec<f32>>)> {
        self.ensure_embedder();
        let embedder = self.embedder.as_mut()?;
        match embedder.embed(texts) {
            Ok(vectors) => Some((embedder.model_id().to_string(), vectors)),
            Err(e) => {
                eprintln!("[tabularium] embedding failed, continuing lexically: {e}");
                None
            }
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    pub fn config_mut(&mut self) -> &mut VaultConfig {
        &mut self.config
    }

    /// Persist the current in-memory config back to `vault.toml` (e.g. after editing `writers`).
    pub fn save_config(&self) -> Result<()> {
        let toml_text = toml::to_string_pretty(&self.config).map_err(|e| Error::Config(format!("serialize config: {e}")))?;
        fs::write(self.dir.join(CONFIG_FILE), toml_text)?;
        Ok(())
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
