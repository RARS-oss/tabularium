//! tabularium-core: a verifiable memory engine for LLM agents.
//!
//! * An append-only, hash-chained, Ed25519-signed ledger is the only source of truth.
//! * Memories are a derived view, recompilable from the ledger byte-for-byte.
//! * Every memory carries provenance (evidence event ids) and declarative validity checks that
//!   are run against the real world at recall time.
//! * Trust levels are assigned at ingestion and never rise; behaviour-steering memories
//!   (preferences, instructions) cannot be derived from untrusted evidence.
//! * Recall packs memories under a token budget and signs a receipt of exactly what was returned.
//!
//! The core never calls a language model. The host agent does the thinking; the engine keeps it honest.

pub mod canon;
pub mod compile;
pub mod contradict;
pub mod dedup;
pub mod embed;
pub mod error;
pub mod keys;
pub mod ledger;
pub mod recall;
pub mod text;
pub mod timeline;
pub mod types;
pub mod vault;
pub mod verify;

pub use compile::CompileReport;
pub use contradict::{ContradictOptions, ContradictionPair, ContradictionReport, SimilarityMemberRef};
pub use dedup::{DuplicateOptions, DuplicatePair, DuplicateReport};
pub use embed::{Embedder, EmbeddingConfig, HashEmbedder};
pub use error::{Error, Result};
pub use ledger::{derive_trust, AuditReport, EmbedReport, ForgetReport, ObserveInput, RememberInput};
pub use recall::{HintItem, HintResult, RecallItem, RecallOptions, RecallResult, Skipped};
pub use types::*;
pub use vault::{now_rfc3339, Policy, Vault, VaultConfig, WriterPolicy};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
