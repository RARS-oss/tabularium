//! The append-only, hash-chained, signed event ledger.

use crate::canon::{self, GENESIS_HASH, SIG_DOMAIN};
use crate::error::{Error, Result};
use crate::keys::verify_hex;
use crate::types::*;
use crate::vault::{now_rfc3339, Vault};
use rusqlite::{params, OptionalExtension, Row, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone)]
pub struct ObserveInput {
    pub kind: EventKind,
    pub content: String,
    /// Defaults to the kind's default trust. Clamped by channel policy (error if above).
    pub trust: Option<Trust>,
    pub channel: String,
    pub meta: Option<Value>,
}

#[derive(Debug, Clone)]
pub struct RememberInput {
    pub kind: MemoryKind,
    pub text: String,
    pub subject: Option<String>,
    pub evidence: Vec<String>,
    pub checks: Vec<Check>,
    pub channel: String,
    /// Trust of the remember act itself; only matters when there is no evidence. Defaults to Agent.
    pub trust: Option<Trust>,
    pub meta: Option<Value>,
}

/// Result of a backfill of missing vectors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedReport {
    /// `None` when embeddings are unavailable in this process.
    pub model: Option<String>,
    pub embedded: usize,
    pub covered: usize,
    pub active: usize,
}

/// Result of forgetting a memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForgetReport {
    pub tombstone_event: Event,
    /// Ids of evidence events whose payload was also redacted, because no other active memory
    /// still cites them. An evidence event still backing another live memory is left untouched.
    pub evidence_redacted: Vec<String>,
}

/// Ingestion channel used for embed events written by the engine itself.
pub const EMBED_CHANNEL: &str = "embedder";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditReport {
    pub ok: bool,
    pub events: u64,
    pub receipts: u64,
    pub head_seq: u64,
    pub head_hash: String,
    pub public_key: String,
    pub problems: Vec<String>,
}

pub(crate) fn row_to_event(row: &Row<'_>) -> rusqlite::Result<Event> {
    let seq: i64 = row.get(0)?;
    let kind_s: String = row.get(4)?;
    let trust_n: i64 = row.get(5)?;
    let payload_s: Option<String> = row.get(6)?;
    let kind = EventKind::parse(&kind_s).unwrap_or(EventKind::Observation);
    let trust = Trust::from_u8(trust_n as u8).unwrap_or(Trust::External);
    let payload = payload_s.map(|s| serde_json::from_str(&s).unwrap_or(Value::String(s)));
    Ok(Event {
        seq: seq as u64,
        id: row.get(1)?,
        ts: row.get(2)?,
        channel: row.get(3)?,
        kind,
        trust,
        payload,
        payload_hash: row.get(7)?,
        prev_hash: row.get(8)?,
        hash: row.get(9)?,
        sig: row.get(10)?,
    })
}

pub(crate) const EVENT_COLS: &str =
    "seq, id, ts, channel, kind, trust, payload, payload_hash, prev_hash, hash, sig";

/// Trust of a derived memory: the weakest link among its evidence, or the recorder's own trust
/// when it cites nothing.
pub fn derive_trust(recorder: Trust, evidence: &[Trust]) -> Trust {
    evidence.iter().copied().min().unwrap_or(recorder)
}

impl Vault {
    /// Current chain head: (seq, hash). (0, genesis) for an empty ledger.
    pub fn head(&self) -> Result<(u64, String)> {
        let head = self
            .conn
            .query_row("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })
            .optional()?;
        Ok(head.unwrap_or((0, GENESIS_HASH.to_string())))
    }

    fn append_event(&mut self, channel: &str, kind: EventKind, trust: Trust, payload: Value) -> Result<Event> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let (head_seq, prev_hash) = tx
            .query_row("SELECT seq, hash FROM events ORDER BY seq DESC LIMIT 1", [], |r| {
                Ok((r.get::<_, i64>(0)? as u64, r.get::<_, String>(1)?))
            })
            .optional()?
            .unwrap_or((0, GENESIS_HASH.to_string()));
        let seq = head_seq + 1;
        let ts = now_rfc3339();
        let payload_hash = canon::payload_hash(&payload);
        let hash = canon::event_hash(seq, &ts, channel, kind.as_str(), trust.as_u8(), &payload_hash, &prev_hash);
        let sig = self.keys.sign_hex(&canon::sig_message(SIG_DOMAIN, &hash))?;
        let payload_text = canon::canonical_json(&payload);
        tx.execute(
            "INSERT INTO events (seq, id, ts, channel, kind, trust, payload, payload_hash, prev_hash, hash, sig)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                seq as i64,
                hash,
                ts,
                channel,
                kind.as_str(),
                trust.as_u8() as i64,
                payload_text,
                payload_hash,
                prev_hash,
                hash,
                sig
            ],
        )?;
        tx.commit()?;
        Ok(Event {
            seq,
            id: hash.clone(),
            ts,
            channel: channel.to_string(),
            kind,
            trust,
            payload: Some(payload),
            payload_hash,
            prev_hash,
            hash,
            sig,
        })
    }

    fn check_channel_trust(&self, channel: &str, trust: Trust) -> Result<()> {
        let max = self.config.policy.max_trust_for(channel);
        if trust > max {
            return Err(Error::Policy(format!(
                "channel '{channel}' may assert at most trust '{max}', got '{trust}'"
            )));
        }
        Ok(())
    }

    /// Record an observation-type event.
    pub fn observe(&mut self, input: ObserveInput) -> Result<Event> {
        if !input.kind.is_observation() {
            return Err(Error::Invalid(format!("kind '{}' is not an observation kind", input.kind)));
        }
        if input.content.trim().is_empty() {
            return Err(Error::Invalid("content is empty".into()));
        }
        let channel = normalize_channel(&input.channel);
        let trust = input.trust.unwrap_or_else(|| input.kind.default_trust());
        self.check_channel_trust(&channel, trust)?;
        let payload = serde_json::to_value(ObservePayload { content: input.content, meta: input.meta })?;
        self.append_event(&channel, input.kind, trust, payload)
    }

    /// Derive a memory from evidence. Validates trust rules before anything touches the ledger,
    /// then appends a derive event and compiles it.
    pub fn remember(&mut self, input: RememberInput) -> Result<Memory> {
        if input.text.trim().is_empty() {
            return Err(Error::Invalid("memory text is empty".into()));
        }
        let channel = normalize_channel(&input.channel);
        let recorder = input.trust.unwrap_or(Trust::Agent);
        self.check_channel_trust(&channel, recorder)?;

        let mut evidence_trusts = Vec::with_capacity(input.evidence.len());
        let mut evidence_ids = Vec::with_capacity(input.evidence.len());
        for id in &input.evidence {
            let id = id.trim();
            if evidence_ids.iter().any(|x: &String| x == id) {
                continue;
            }
            let ev = self
                .get_event(id)?
                .ok_or_else(|| Error::NotFound(format!("evidence event '{id}' does not exist")))?;
            evidence_trusts.push(ev.trust);
            evidence_ids.push(id.to_string());
        }
        let trust = derive_trust(recorder, &evidence_trusts);
        if input.kind.requires_user_trust() && trust < Trust::User {
            return Err(Error::Policy(format!(
                "a '{}' memory needs user-level trust; derived trust is '{trust}' \
                 (cite user utterances as evidence, not tool output or external content)",
                input.kind
            )));
        }

        let mut checks = input.checks;
        crate::verify::bake_checks(&self.root, &mut checks)?;

        let payload = serde_json::to_value(DerivePayload {
            kind: input.kind,
            text: input.text,
            subject: input.subject.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
            evidence: evidence_ids,
            checks,
            meta: input.meta,
        })?;
        let text_for_embedding = payload["text"].as_str().unwrap_or_default().to_string();
        let ev = self.append_event(&channel, EventKind::Derive, recorder, payload)?;
        if let Some((model, mut vectors)) = self.embed_texts(&[text_for_embedding.as_str()])
            && let Some(vector) = vectors.pop()
        {
            self.append_embed_event(&ev.id, &model, &vector)?;
        }
        self.compile(false)?;
        self.get_memory(&ev.id)?
            .ok_or_else(|| Error::Integrity("derived memory missing after compile".into()))
    }

    fn append_embed_event(&mut self, memory_id: &str, model: &str, vector: &[f32]) -> Result<Event> {
        let payload = serde_json::to_value(EmbedPayload {
            memory_id: memory_id.to_string(),
            model: model.to_string(),
            dim: vector.len(),
            vector_hex: crate::embed::encode_vector(vector),
        })?;
        self.append_event(EMBED_CHANNEL, EventKind::Embed, Trust::Agent, payload)
    }

    /// Write vectors for active memories that lack one under the current model. Batches of 64.
    pub fn embed_missing(&mut self) -> Result<EmbedReport> {
        let Some(model) = self.embedding_model_id() else {
            let active = self.memories(false)?.len();
            return Ok(EmbedReport { model: None, embedded: 0, covered: 0, active });
        };
        let missing = self.memories_missing_embedding(&model)?;
        let mut embedded = 0;
        for chunk in missing.chunks(64) {
            let texts: Vec<&str> = chunk.iter().map(|m| m.text.as_str()).collect();
            let Some((model_id, vectors)) = self.embed_texts(&texts) else { break };
            for (m, v) in chunk.iter().zip(vectors.iter()) {
                self.append_embed_event(&m.id, &model_id, v)?;
                embedded += 1;
            }
        }
        if embedded > 0 {
            self.compile(false)?;
        }
        let (covered, active) = self.embedding_coverage(&model)?;
        Ok(EmbedReport { model: Some(model), embedded, covered, active })
    }

    /// Tombstone a memory: append a forget event, redact the derive payload, redact any evidence
    /// event no longer cited by another active memory, recompile.
    pub fn forget(&mut self, memory_id: &str, reason: &str, channel: &str) -> Result<ForgetReport> {
        let mem = self
            .get_memory(memory_id)?
            .ok_or_else(|| Error::NotFound(format!("memory '{memory_id}' does not exist")))?;
        if mem.tombstoned {
            return Err(Error::Invalid(format!("memory '{memory_id}' is already forgotten")));
        }
        let channel = normalize_channel(channel);
        let payload = serde_json::to_value(ForgetPayload { memory_id: memory_id.to_string(), reason: reason.to_string() })?;
        let ev = self.append_event(&channel, EventKind::Forget, Trust::Agent, payload)?;
        self.conn
            .execute("UPDATE events SET payload = NULL WHERE id = ?1", [memory_id])?;
        // A vector is a lossy copy of the text; redact it too.
        self.conn.execute(
            "UPDATE events SET payload = NULL
             WHERE kind = 'embed' AND payload IS NOT NULL AND json_extract(payload, '$.memory_id') = ?1",
            [memory_id],
        )?;
        let evidence_redacted = self.redact_orphaned_evidence(&mem.evidence, memory_id)?;
        self.compile(false)?;
        Ok(ForgetReport { tombstone_event: ev, evidence_redacted })
    }

    /// Redact the payload of each evidence event in `candidates` that no other *active* memory
    /// (besides `forgetting`, whose own view row is still active at this point) still cites. The
    /// memories view is read as-is: not yet updated for this forget, since `compile` hasn't run.
    fn redact_orphaned_evidence(&mut self, candidates: &[String], forgetting: &str) -> Result<Vec<String>> {
        if candidates.is_empty() {
            return Ok(Vec::new());
        }
        let active = self.memories(false)?;
        let mut redacted = Vec::new();
        for id in candidates {
            let still_cited = active.iter().any(|m| m.id != forgetting && m.evidence.iter().any(|e| e == id));
            if still_cited {
                continue;
            }
            let n = self.conn.execute("UPDATE events SET payload = NULL WHERE id = ?1 AND payload IS NOT NULL", [id])?;
            if n > 0 {
                redacted.push(id.clone());
            }
        }
        Ok(redacted)
    }

    pub fn get_event(&self, id: &str) -> Result<Option<Event>> {
        let sql = format!("SELECT {EVENT_COLS} FROM events WHERE id = ?1");
        Ok(self.conn.query_row(&sql, [id], row_to_event).optional()?)
    }

    /// Events with seq > `after`, in order, at most `limit`.
    pub fn events(&self, after: u64, limit: usize) -> Result<Vec<Event>> {
        let sql = format!("SELECT {EVENT_COLS} FROM events WHERE seq > ?1 ORDER BY seq ASC LIMIT ?2");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(params![after as i64, limit as i64], row_to_event)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn event_count(&self) -> Result<u64> {
        Ok(self.conn.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0))? as u64)
    }

    /// Walk the whole chain: contiguity, links, hashes, signatures, payload commitments.
    pub fn audit(&self) -> Result<AuditReport> {
        let pk = self.public_key_hex();
        let mut problems = Vec::new();
        let mut expected_seq: u64 = 1;
        let mut prev = GENESIS_HASH.to_string();
        let mut count: u64 = 0;
        let mut head_hash = GENESIS_HASH.to_string();
        let sql = format!("SELECT {EVENT_COLS} FROM events ORDER BY seq ASC");
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_event)?;
        for r in rows {
            let ev = r?;
            count += 1;
            if ev.seq != expected_seq {
                problems.push(format!("seq gap: expected {expected_seq}, found {}", ev.seq));
                expected_seq = ev.seq;
            }
            if ev.prev_hash != prev {
                problems.push(format!("event {}: prev_hash does not match previous event", ev.seq));
            }
            let recomputed = canon::event_hash(
                ev.seq,
                &ev.ts,
                &ev.channel,
                ev.kind.as_str(),
                ev.trust.as_u8(),
                &ev.payload_hash,
                &ev.prev_hash,
            );
            if recomputed != ev.hash {
                problems.push(format!("event {}: hash mismatch (content altered)", ev.seq));
            }
            if ev.id != ev.hash {
                problems.push(format!("event {}: id does not equal hash", ev.seq));
            }
            if let Some(p) = &ev.payload
                && canon::payload_hash(p) != ev.payload_hash
            {
                problems.push(format!("event {}: payload does not match its commitment", ev.seq));
            }
            if let Err(e) = verify_hex(&pk, &canon::sig_message(SIG_DOMAIN, &ev.hash), &ev.sig) {
                problems.push(format!("event {}: {e}", ev.seq));
            }
            prev = ev.hash.clone();
            head_hash = ev.hash.clone();
            expected_seq += 1;
        }
        let mut receipts: u64 = 0;
        let mut rstmt = self.conn.prepare("SELECT id, sig FROM receipts")?;
        let rrows = rstmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?;
        for r in rrows {
            let (id, sig) = r?;
            receipts += 1;
            if let Err(e) = verify_hex(&pk, &canon::sig_message(canon::RECEIPT_DOMAIN, &id), &sig) {
                problems.push(format!("receipt {id}: {e}"));
            }
        }
        Ok(AuditReport {
            ok: problems.is_empty(),
            events: count,
            receipts,
            head_seq: count,
            head_hash,
            public_key: pk,
            problems,
        })
    }
}

fn normalize_channel(s: &str) -> String {
    let t = s.trim();
    if t.is_empty() { "unknown".to_string() } else { t.to_string() }
}
