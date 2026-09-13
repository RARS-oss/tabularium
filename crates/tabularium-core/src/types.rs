//! Core data model: trust levels, events, memories, checks.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Trust level attached to every event at ingestion time.
/// Ordered: External < Tool < Agent < User. Never upgraded automatically.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    /// Imported documents, web pages, anything from outside the session.
    External = 0,
    /// Tool output: file contents, command output, API responses.
    Tool = 1,
    /// The agent's own actions and conclusions.
    Agent = 2,
    /// What the user actually said.
    User = 3,
}

impl Trust {
    pub const ALL: [Trust; 4] = [Trust::External, Trust::Tool, Trust::Agent, Trust::User];

    pub fn as_str(self) -> &'static str {
        match self {
            Trust::External => "external",
            Trust::Tool => "tool",
            Trust::Agent => "agent",
            Trust::User => "user",
        }
    }

    pub fn parse(s: &str) -> Option<Trust> {
        match s.trim().to_ascii_lowercase().as_str() {
            "external" => Some(Trust::External),
            "tool" => Some(Trust::Tool),
            "agent" => Some(Trust::Agent),
            "user" => Some(Trust::User),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(n: u8) -> Option<Trust> {
        match n {
            0 => Some(Trust::External),
            1 => Some(Trust::Tool),
            2 => Some(Trust::Agent),
            3 => Some(Trust::User),
            _ => None,
        }
    }
}

impl std::fmt::Display for Trust {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Kind of ledger event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    /// Something the user said.
    Utterance,
    /// Something the agent did or concluded.
    Action,
    /// Tool output observed by the agent (file read, command output).
    Observation,
    /// External document imported into the ledger.
    External,
    /// A memory derivation ("remember"). Payload: [`DerivePayload`].
    Derive,
    /// A tombstone ("forget"). Payload: [`ForgetPayload`].
    Forget,
    /// A stored embedding vector for a memory. Payload: [`EmbedPayload`].
    Embed,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::Utterance => "utterance",
            EventKind::Action => "action",
            EventKind::Observation => "observation",
            EventKind::External => "external",
            EventKind::Derive => "derive",
            EventKind::Forget => "forget",
            EventKind::Embed => "embed",
        }
    }

    pub fn parse(s: &str) -> Option<EventKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "utterance" => Some(EventKind::Utterance),
            "action" => Some(EventKind::Action),
            "observation" => Some(EventKind::Observation),
            "external" => Some(EventKind::External),
            "derive" => Some(EventKind::Derive),
            "forget" => Some(EventKind::Forget),
            "embed" => Some(EventKind::Embed),
            _ => None,
        }
    }

    /// Default trust for an event when the caller does not specify one.
    pub fn default_trust(self) -> Trust {
        match self {
            EventKind::Utterance => Trust::User,
            EventKind::Action => Trust::Agent,
            EventKind::Observation => Trust::Tool,
            EventKind::External => Trust::External,
            EventKind::Derive | EventKind::Forget | EventKind::Embed => Trust::Agent,
        }
    }

    pub fn is_observation(self) -> bool {
        !matches!(self, EventKind::Derive | EventKind::Forget | EventKind::Embed)
    }
}

impl std::fmt::Display for EventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Kind of memory. Preference and Instruction require user-level trust by construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MemoryKind {
    /// A verifiable statement about the world or the project.
    Fact,
    /// How the user wants things done. Requires user trust.
    Preference,
    /// A standing instruction from the user. Requires user trust.
    Instruction,
    /// Pointer to an external resource (URL, ticket, dashboard).
    Reference,
    /// Free-form note without a validity claim.
    Note,
}

impl MemoryKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MemoryKind::Fact => "fact",
            MemoryKind::Preference => "preference",
            MemoryKind::Instruction => "instruction",
            MemoryKind::Reference => "reference",
            MemoryKind::Note => "note",
        }
    }

    pub fn parse(s: &str) -> Option<MemoryKind> {
        match s.trim().to_ascii_lowercase().as_str() {
            "fact" => Some(MemoryKind::Fact),
            "preference" => Some(MemoryKind::Preference),
            "instruction" => Some(MemoryKind::Instruction),
            "reference" => Some(MemoryKind::Reference),
            "note" => Some(MemoryKind::Note),
            _ => None,
        }
    }

    /// Kinds that can steer the agent's behaviour must come from the user.
    pub fn requires_user_trust(self) -> bool {
        matches!(self, MemoryKind::Preference | MemoryKind::Instruction)
    }
}

impl std::fmt::Display for MemoryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Declarative validity check attached to a memory. Run at recall time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Check {
    /// The file must exist.
    FileExists { path: String },
    /// The file's BLAKE3 hash must equal `blake3` (filled in at remember time when omitted).
    FileHash {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blake3: Option<String>,
    },
    /// The file must contain `symbol` as a substring.
    SymbolInFile { path: String, symbol: String },
    /// The memory expires at `expires` (RFC 3339).
    Ttl { expires: String },
}

/// One append-only ledger event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    /// Equal to `hash`. Stable identifier used as evidence and memory id.
    pub id: String,
    /// RFC 3339 UTC with millisecond precision.
    pub ts: String,
    /// Ingestion channel, e.g. "mcp", "cli", "hook:UserPromptSubmit".
    pub channel: String,
    pub kind: EventKind,
    pub trust: Trust,
    /// `None` once redacted by a forget. The hash chain commits to `payload_hash`, not the payload.
    pub payload: Option<Value>,
    pub payload_hash: String,
    pub prev_hash: String,
    pub hash: String,
    /// Ed25519 signature over the domain-tagged hash, hex encoded.
    pub sig: String,
}

/// Payload of a [`EventKind::Derive`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DerivePayload {
    pub kind: MemoryKind,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(default)]
    pub evidence: Vec<String>,
    #[serde(default)]
    pub checks: Vec<Check>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
    /// Ids of active memories this one consolidates. Each is superseded by this derive, exactly
    /// like subject supersession but keyed by explicit id instead of a shared subject. Always a
    /// subset of `evidence` by construction, so trust can never rise through a merge. Old ledger
    /// events predate this field and deserialize to an empty list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub merged_from: Vec<String>,
}

/// Payload of a [`EventKind::Forget`] event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgetPayload {
    pub memory_id: String,
    #[serde(default)]
    pub reason: String,
}

/// Payload of an [`EventKind::Embed`] event. The vector is hex of little-endian f32.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedPayload {
    pub memory_id: String,
    pub model: String,
    pub dim: usize,
    pub vector_hex: String,
}

/// Payload of an observation-type event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservePayload {
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta: Option<Value>,
}

/// A memory: a derived view row, recompilable from the ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Memory {
    /// Id of the derive event that produced it.
    pub id: String,
    pub seq: u64,
    pub kind: MemoryKind,
    /// Empty once tombstoned.
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// min(evidence trusts), or the deriving event's trust when there is no evidence.
    pub trust: Trust,
    pub evidence: Vec<String>,
    pub checks: Vec<Check>,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub superseded_by: Option<String>,
    pub tombstoned: bool,
}

impl Memory {
    pub fn is_active(&self) -> bool {
        !self.tombstoned && self.superseded_by.is_none()
    }
}

/// Verification status of a memory at recall time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// All checks passed.
    Fresh,
    /// The memory carries no checks at all: it never claimed to be verifiable.
    Unchecked,
    /// Verification was skipped this call, or a check exists but errored (couldn't run) rather
    /// than definitively passing or failing.
    Unverified,
    /// At least one check failed: the world changed since this was remembered.
    Stale,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Fresh => "fresh",
            Status::Unchecked => "unchecked",
            Status::Unverified => "unverified",
            Status::Stale => "stale",
        }
    }
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum CheckOutcome {
    Pass,
    Fail { reason: String },
    Error { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub check: Check,
    #[serde(flatten)]
    pub outcome: CheckOutcome,
}

/// A signed statement about an engine operation (currently: recalls).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// Hex BLAKE3 of the canonical body; also the receipt id.
    pub id: String,
    pub ts: String,
    pub kind: String,
    pub body: Value,
    pub sig: String,
}
