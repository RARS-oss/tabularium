//! Compile memories from the ledger. A pure, replayable function of the event sequence.

use crate::canon::{blake3_hex, canonical_json};
use crate::embed::{decode_vector, vector_from_bytes, vector_to_bytes};
use crate::error::{Error, Result};
use crate::ledger::{derive_trust, row_to_event, EVENT_COLS};
use crate::types::*;
use crate::vault::Vault;
use rusqlite::{params, OptionalExtension, Row, Transaction, TransactionBehavior};
use serde::{Deserialize, Serialize};

const META_COMPILED_UPTO: &str = "compiled_upto";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompileReport {
    pub rebuilt: bool,
    pub from_seq: u64,
    pub to_seq: u64,
    pub applied: u64,
    pub memories_active: u64,
    pub memories_total: u64,
}

const MEMORY_COLS: &str =
    "id, seq, kind, text, subject, trust, evidence, checks, created_at, superseded_by, tombstoned";

fn row_to_memory(row: &Row<'_>) -> rusqlite::Result<Memory> {
    let seq: i64 = row.get(1)?;
    let kind_s: String = row.get(2)?;
    let trust_n: i64 = row.get(5)?;
    let evidence_s: String = row.get(6)?;
    let checks_s: String = row.get(7)?;
    let tomb: i64 = row.get(10)?;
    Ok(Memory {
        id: row.get(0)?,
        seq: seq as u64,
        kind: MemoryKind::parse(&kind_s).unwrap_or(MemoryKind::Note),
        text: row.get(3)?,
        subject: row.get(4)?,
        trust: Trust::from_u8(trust_n as u8).unwrap_or(Trust::External),
        evidence: serde_json::from_str(&evidence_s).unwrap_or_default(),
        checks: serde_json::from_str(&checks_s).unwrap_or_default(),
        created_at: row.get(8)?,
        superseded_by: row.get(9)?,
        tombstoned: tomb != 0,
    })
}

fn apply_event(tx: &Transaction<'_>, ev: &Event) -> Result<()> {
    match ev.kind {
        EventKind::Derive => {
            let Some(payload) = &ev.payload else {
                // Redacted derive: keep an inactive stub so ids stay resolvable.
                tx.execute(
                    "INSERT OR REPLACE INTO memories
                     (id, seq, kind, text, subject, trust, evidence, checks, created_at, superseded_by, tombstoned)
                     VALUES (?1, ?2, 'note', '', NULL, ?3, '[]', '[]', ?4, NULL, 1)",
                    params![ev.id, ev.seq as i64, ev.trust.as_u8() as i64, ev.ts],
                )?;
                return Ok(());
            };
            let d: DerivePayload = serde_json::from_value(payload.clone())
                .map_err(|e| Error::Integrity(format!("event {}: bad derive payload: {e}", ev.seq)))?;
            let mut trusts = Vec::with_capacity(d.evidence.len());
            for id in &d.evidence {
                let t = tx
                    .query_row("SELECT trust FROM events WHERE id = ?1", [id], |r| r.get::<_, i64>(0))
                    .optional()?
                    .ok_or_else(|| Error::Integrity(format!("event {}: evidence '{id}' missing", ev.seq)))?;
                trusts.push(Trust::from_u8(t as u8).unwrap_or(Trust::External));
            }
            let trust = derive_trust(ev.trust, &trusts);
            if d.kind.requires_user_trust() && trust < Trust::User {
                return Err(Error::Integrity(format!(
                    "event {}: '{}' memory with trust '{trust}' in ledger (policy bypassed?)",
                    ev.seq, d.kind
                )));
            }
            tx.execute(
                "INSERT OR REPLACE INTO memories
                 (id, seq, kind, text, subject, trust, evidence, checks, created_at, superseded_by, tombstoned)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, NULL, 0)",
                params![
                    ev.id,
                    ev.seq as i64,
                    d.kind.as_str(),
                    d.text,
                    d.subject,
                    trust.as_u8() as i64,
                    canonical_json(&serde_json::to_value(&d.evidence)?),
                    canonical_json(&serde_json::to_value(&d.checks)?),
                    ev.ts
                ],
            )?;
            if let Some(subject) = &d.subject {
                tx.execute(
                    "UPDATE memories SET superseded_by = ?1
                     WHERE subject = ?2 AND seq < ?3 AND tombstoned = 0 AND superseded_by IS NULL",
                    params![ev.id, subject, ev.seq as i64],
                )?;
            }
        }
        EventKind::Forget => {
            let Some(payload) = &ev.payload else { return Ok(()) };
            let f: ForgetPayload = serde_json::from_value(payload.clone())
                .map_err(|e| Error::Integrity(format!("event {}: bad forget payload: {e}", ev.seq)))?;
            // Forget undoes the derive. On rebuild the redacted derive never carries a subject, so
            // it never superseded anything: re-point whatever this memory superseded to whatever
            // superseded it (or nothing), then collapse to exactly the stub a redacted derive
            // produces, so the incremental view and a full replay agree byte for byte.
            tx.execute(
                "UPDATE memories
                 SET superseded_by = (SELECT superseded_by FROM memories AS m2 WHERE m2.id = ?1)
                 WHERE superseded_by = ?1",
                [&f.memory_id],
            )?;
            tx.execute(
                "UPDATE memories SET
                     kind = 'note', text = '', subject = NULL,
                     trust = (SELECT trust FROM events WHERE events.id = memories.id),
                     evidence = '[]', checks = '[]', superseded_by = NULL, tombstoned = 1
                 WHERE id = ?1",
                [&f.memory_id],
            )?;
            tx.execute("DELETE FROM embeddings WHERE memory_id = ?1", [&f.memory_id])?;
        }
        EventKind::Embed => {
            let Some(payload) = &ev.payload else { return Ok(()) };
            let e: EmbedPayload = serde_json::from_value(payload.clone())
                .map_err(|err| Error::Integrity(format!("event {}: bad embed payload: {err}", ev.seq)))?;
            let vector = decode_vector(&e.vector_hex)
                .map_err(|err| Error::Integrity(format!("event {}: {err}", ev.seq)))?;
            if vector.len() != e.dim {
                return Err(Error::Integrity(format!(
                    "event {}: embed dim {} does not match vector length {}",
                    ev.seq,
                    e.dim,
                    vector.len()
                )));
            }
            // Only live memories carry vectors; a forgotten memory's vector would leak its content.
            let live: bool = tx
                .query_row(
                    "SELECT COUNT(*) FROM memories WHERE id = ?1 AND tombstoned = 0",
                    [&e.memory_id],
                    |r| r.get::<_, i64>(0),
                )
                .map(|n| n > 0)?;
            if live {
                tx.execute(
                    "INSERT OR REPLACE INTO embeddings (memory_id, model, dim, vector) VALUES (?1, ?2, ?3, ?4)",
                    params![e.memory_id, e.model, e.dim as i64, vector_to_bytes(&vector)],
                )?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl Vault {
    /// Apply ledger events not yet reflected in the memories view. With `rebuild`, drop the view
    /// and replay from the genesis; the result must be identical, and tests assert that.
    pub fn compile(&mut self, rebuild: bool) -> Result<CompileReport> {
        let tx = self.conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut from: u64 = tx
            .query_row("SELECT value FROM meta WHERE key = ?1", [META_COMPILED_UPTO], |r| r.get::<_, String>(0))
            .optional()?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if rebuild {
            tx.execute("DELETE FROM memories", [])?;
            tx.execute("DELETE FROM embeddings", [])?;
            from = 0;
        }
        let mut applied: u64 = 0;
        let mut to = from;
        {
            let sql = format!("SELECT {EVENT_COLS} FROM events WHERE seq > ?1 ORDER BY seq ASC");
            let mut stmt = tx.prepare(&sql)?;
            let rows = stmt.query_map([from as i64], row_to_event)?;
            let mut events = Vec::new();
            for r in rows {
                events.push(r?);
            }
            for ev in &events {
                apply_event(&tx, ev)?;
                applied += 1;
                to = ev.seq;
            }
        }
        tx.execute(
            "INSERT INTO meta (key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![META_COMPILED_UPTO, to.to_string()],
        )?;
        let total: i64 = tx.query_row("SELECT COUNT(*) FROM memories", [], |r| r.get(0))?;
        let active: i64 = tx.query_row(
            "SELECT COUNT(*) FROM memories WHERE tombstoned = 0 AND superseded_by IS NULL",
            [],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(CompileReport {
            rebuilt: rebuild,
            from_seq: from,
            to_seq: to,
            applied,
            memories_active: active as u64,
            memories_total: total as u64,
        })
    }

    pub fn compiled_upto(&self) -> Result<u64> {
        Ok(self.meta_get(META_COMPILED_UPTO)?.and_then(|s| s.parse().ok()).unwrap_or(0))
    }

    pub fn get_memory(&self, id: &str) -> Result<Option<Memory>> {
        let sql = format!("SELECT {MEMORY_COLS} FROM memories WHERE id = ?1");
        Ok(self.conn.query_row(&sql, [id], row_to_memory).optional()?)
    }

    /// All memories in ledger order. Active only unless `include_inactive`.
    pub fn memories(&self, include_inactive: bool) -> Result<Vec<Memory>> {
        let sql = if include_inactive {
            format!("SELECT {MEMORY_COLS} FROM memories ORDER BY seq ASC")
        } else {
            format!("SELECT {MEMORY_COLS} FROM memories WHERE tombstoned = 0 AND superseded_by IS NULL ORDER BY seq ASC")
        };
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([], row_to_memory)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Canonical JSON of the full derived view (memories and embeddings). Two vaults with the same
    /// ledger must produce the same snapshot; incremental and rebuilt compiles must too.
    pub fn snapshot(&self) -> Result<String> {
        let memories = self.memories(true)?;
        let mut stmt = self.conn.prepare("SELECT memory_id, model, dim, vector FROM embeddings ORDER BY memory_id")?;
        let rows = stmt.query_map([], |r| {
            Ok(serde_json::json!({
                "memory_id": r.get::<_, String>(0)?,
                "model": r.get::<_, String>(1)?,
                "dim": r.get::<_, i64>(2)?,
                "vector_blake3": blake3_hex(&r.get::<_, Vec<u8>>(3)?),
            }))
        })?;
        let mut embeddings = Vec::new();
        for r in rows {
            embeddings.push(r?);
        }
        Ok(canonical_json(&serde_json::json!({"memories": memories, "embeddings": embeddings})))
    }

    /// Stored vectors for active memories under `model`, keyed by memory id.
    pub fn embeddings_for_active(&self, model: &str) -> Result<Vec<(String, Vec<f32>)>> {
        let mut stmt = self.conn.prepare(
            "SELECT e.memory_id, e.vector FROM embeddings e
             JOIN memories m ON m.id = e.memory_id
             WHERE e.model = ?1 AND m.tombstoned = 0 AND m.superseded_by IS NULL
             ORDER BY m.seq ASC",
        )?;
        let rows = stmt.query_map([model], |r| Ok((r.get::<_, String>(0)?, vector_from_bytes(&r.get::<_, Vec<u8>>(1)?))))?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Active memories that have no stored vector under `model`.
    pub fn memories_missing_embedding(&self, model: &str) -> Result<Vec<Memory>> {
        let sql = format!(
            "SELECT {MEMORY_COLS} FROM memories m
             WHERE m.tombstoned = 0 AND m.superseded_by IS NULL
               AND NOT EXISTS (SELECT 1 FROM embeddings e WHERE e.memory_id = m.id AND e.model = ?1)
             ORDER BY m.seq ASC"
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map([model], row_to_memory)?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// (memories with a vector under `model`, active memories).
    pub fn embedding_coverage(&self, model: &str) -> Result<(usize, usize)> {
        let covered: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM embeddings e JOIN memories m ON m.id = e.memory_id
             WHERE e.model = ?1 AND m.tombstoned = 0 AND m.superseded_by IS NULL",
            [model],
            |r| r.get(0),
        )?;
        let active: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM memories WHERE tombstoned = 0 AND superseded_by IS NULL",
            [],
            |r| r.get(0),
        )?;
        Ok((covered as usize, active as usize))
    }
}
