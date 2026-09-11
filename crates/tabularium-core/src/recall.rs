//! Recall: rank active memories, verify them against the world, pack them under a token budget,
//! and sign a receipt saying exactly what was handed to the agent.

use crate::canon::{blake3_hex, canonical_json, RECEIPT_DOMAIN};
use crate::error::Result;
use crate::text::{estimate_tokens, tokenize, Bm25, Doc, BM25_B, BM25_K1};
use crate::types::*;
use crate::vault::{now_rfc3339, Vault};
use crate::verify::run_checks;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const POLICY_VERSION: u32 = 1;
/// Tokens charged per item on top of its text, for the kind/status framing the host adds.
pub const ITEM_OVERHEAD_TOKENS: u32 = 8;
/// Upper bound on how many candidates get verified per recall, to bound recall latency.
pub const MAX_VERIFY_CANDIDATES: usize = 200;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallOptions {
    pub budget_tokens: u32,
    pub limit: usize,
    /// Run validity checks. When false every item is `unverified`.
    pub verify: bool,
    /// Keep stale items (demoted) instead of dropping them.
    pub include_stale: bool,
}

impl Default for RecallOptions {
    fn default() -> Self {
        RecallOptions { budget_tokens: 800, limit: 20, verify: true, include_stale: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallItem {
    pub id: String,
    pub kind: MemoryKind,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub trust: Trust,
    pub status: Status,
    pub score: f64,
    pub bm25: f64,
    pub tokens: u32,
    pub created_at: String,
    pub evidence: Vec<String>,
    pub checks: Vec<CheckResult>,
    pub why: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skipped {
    pub id: String,
    pub tokens: u32,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecallResult {
    pub query: String,
    pub budget_tokens: u32,
    pub used_tokens: u32,
    /// Active memories considered.
    pub considered: usize,
    /// Memories with a non-zero lexical match (all of them for an empty query).
    pub matched: usize,
    pub items: Vec<RecallItem>,
    pub skipped_for_budget: Vec<Skipped>,
    pub receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintItem {
    pub id: String,
    pub kind: MemoryKind,
    pub title: String,
    pub score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HintResult {
    pub matched: usize,
    pub items: Vec<HintItem>,
}

pub fn status_factor(s: Status) -> f64 {
    match s {
        Status::Fresh => 1.0,
        Status::Unverified => 0.9,
        Status::Stale => 0.5,
    }
}

pub fn trust_factor(t: Trust) -> f64 {
    match t {
        Trust::User => 1.0,
        Trust::Agent => 0.95,
        Trust::Tool => 0.9,
        Trust::External => 0.8,
    }
}

fn title_of(text: &str, max_chars: usize) -> String {
    let first_line = text.lines().next().unwrap_or("").trim();
    let mut out: String = first_line.chars().take(max_chars).collect();
    if first_line.chars().count() > max_chars {
        out.push('…');
    }
    out
}

fn fmt_score(x: f64) -> String {
    format!("{x:.3}")
}

/// Active memories, their (index, bm25) ranking, and whether the query had lexical content.
struct Ranking {
    memories: Vec<Memory>,
    scored: Vec<(usize, f64)>,
    lexical: bool,
}

impl Vault {
    fn ranked_candidates(&self, query: &str) -> Result<Ranking> {
        let memories = self.memories(false)?;
        let q = tokenize(query);
        let lexical = !q.is_empty();
        let docs: Vec<Doc<usize>> = memories
            .iter()
            .enumerate()
            .map(|(i, m)| {
                let mut text = m.text.clone();
                if let Some(s) = &m.subject {
                    text.push(' ');
                    text.push_str(s);
                }
                Doc { key: i, tokens: tokenize(&text) }
            })
            .collect();
        let mut scored: Vec<(usize, f64)> = if lexical {
            Bm25::build(docs).score_all(&q).into_iter().filter(|(_, s)| *s > 0.0).collect()
        } else {
            (0..memories.len()).map(|i| (i, 0.0)).collect()
        };
        // Deterministic order: score desc, then most recent first.
        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| memories[b.0].seq.cmp(&memories[a.0].seq))
        });
        Ok(Ranking { memories, scored, lexical })
    }

    /// Rank, verify, pack under budget, sign a receipt.
    pub fn recall(&self, query: &str, opts: &RecallOptions) -> Result<RecallResult> {
        let Ranking { memories, scored, lexical } = self.ranked_candidates(query)?;
        let now = chrono::Utc::now();
        let considered = memories.len();
        let matched = scored.len();

        // Verify and compute final scores for a bounded prefix of the ranking.
        let mut candidates: Vec<RecallItem> = Vec::new();
        for (i, bm25) in scored.iter().take(MAX_VERIFY_CANDIDATES) {
            let m = &memories[*i];
            let (status, checks) = if opts.verify {
                run_checks(&self.root, &m.checks, &now)
            } else {
                (Status::Unverified, Vec::new())
            };
            if status == Status::Stale && !opts.include_stale {
                continue;
            }
            let base = if lexical { *bm25 } else { 1.0 };
            let score = base * status_factor(status) * trust_factor(m.trust);
            let tokens = estimate_tokens(&m.text) + ITEM_OVERHEAD_TOKENS;
            let mut why = if lexical {
                format!("bm25 {}", fmt_score(*bm25))
            } else {
                "no query: recency order".to_string()
            };
            why.push_str(&format!(
                " × status {} ({}) × trust {} ({}) = {}",
                status,
                fmt_score(status_factor(status)),
                m.trust,
                fmt_score(trust_factor(m.trust)),
                fmt_score(score)
            ));
            if let Some(fail) = checks.iter().find_map(|c| match &c.outcome {
                CheckOutcome::Fail { reason } => Some(reason.clone()),
                _ => None,
            }) {
                why.push_str(&format!("; stale because: {fail}"));
            }
            candidates.push(RecallItem {
                id: m.id.clone(),
                kind: m.kind,
                text: m.text.clone(),
                subject: m.subject.clone(),
                trust: m.trust,
                status,
                score,
                bm25: *bm25,
                tokens,
                created_at: m.created_at.clone(),
                evidence: m.evidence.clone(),
                checks,
                why,
            });
        }
        // Re-rank by final score; ties by recency (seq desc == created order desc).
        let seq_of = |id: &str| memories.iter().find(|m| m.id == id).map(|m| m.seq).unwrap_or(0);
        candidates.sort_by(|a, b| {
            b.score
                .partial_cmp(&a.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| seq_of(&b.id).cmp(&seq_of(&a.id)))
        });

        // Greedy knapsack under the budget.
        let mut items = Vec::new();
        let mut skipped = Vec::new();
        let mut used: u32 = 0;
        for c in candidates {
            if items.len() >= opts.limit {
                break;
            }
            if used + c.tokens <= opts.budget_tokens {
                used += c.tokens;
                items.push(c);
            } else {
                skipped.push(Skipped { id: c.id, tokens: c.tokens, score: c.score });
            }
        }

        let (head_seq, head_hash) = self.head()?;
        let receipt_items: Vec<serde_json::Value> = items
            .iter()
            .map(|it| json!({"id": it.id, "status": it.status, "tokens": it.tokens, "score": it.score}))
            .collect();
        let result_hash = blake3_hex(canonical_json(&serde_json::Value::Array(receipt_items.clone())).as_bytes());
        let ts = now_rfc3339();
        let body = json!({
            "kind": "recall",
            "ts": ts,
            "ledger_head": {"seq": head_seq, "hash": head_hash},
            "query_hash": blake3_hex(query.as_bytes()),
            "budget_tokens": opts.budget_tokens,
            "used_tokens": used,
            "considered": considered,
            "matched": matched,
            "policy": {
                "version": POLICY_VERSION,
                "bm25": {"k1": BM25_K1, "b": BM25_B},
                "status_factor": {"fresh": 1.0, "unverified": 0.9, "stale": 0.5},
                "trust_factor": {"user": 1.0, "agent": 0.95, "tool": 0.9, "external": 0.8},
                "item_overhead_tokens": ITEM_OVERHEAD_TOKENS,
                "verify": opts.verify,
                "include_stale": opts.include_stale
            },
            "items": receipt_items,
            "result_hash": result_hash,
        });
        let receipt = self.sign_receipt("recall", body, &ts)?;
        Ok(RecallResult {
            query: query.to_string(),
            budget_tokens: opts.budget_tokens,
            used_tokens: used,
            considered,
            matched,
            items,
            skipped_for_budget: skipped,
            receipt,
        })
    }

    /// Cheap "you have memories about this" probe. No verification, no receipt.
    pub fn hint(&self, text: &str, n: usize) -> Result<HintResult> {
        let Ranking { memories, scored, lexical } = self.ranked_candidates(text)?;
        if !lexical {
            return Ok(HintResult { matched: 0, items: Vec::new() });
        }
        let items = scored
            .iter()
            .take(n)
            .map(|(i, s)| {
                let m = &memories[*i];
                HintItem { id: m.id.clone(), kind: m.kind, title: title_of(&m.text, 80), score: *s }
            })
            .collect();
        Ok(HintResult { matched: scored.len(), items })
    }

    fn sign_receipt(&self, kind: &str, body: serde_json::Value, ts: &str) -> Result<Receipt> {
        let id = blake3_hex(canonical_json(&body).as_bytes());
        let sig = self.keys.sign_hex(&crate::canon::sig_message(RECEIPT_DOMAIN, &id))?;
        self.conn.execute(
            "INSERT OR IGNORE INTO receipts (id, ts, kind, body, sig) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, ts, kind, canonical_json(&body), sig],
        )?;
        Ok(Receipt { id, ts: ts.to_string(), kind: kind.to_string(), body, sig })
    }

    pub fn get_receipt(&self, id: &str) -> Result<Option<Receipt>> {
        use rusqlite::OptionalExtension;
        let row = self
            .conn
            .query_row("SELECT id, ts, kind, body, sig FROM receipts WHERE id = ?1", [id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })
            .optional()?;
        Ok(match row {
            Some((id, ts, kind, body, sig)) => Some(Receipt { id, ts, kind, body: serde_json::from_str(&body)?, sig }),
            None => None,
        })
    }

    /// Verify a memory (or all active ones) right now, without recall or receipt.
    pub fn verify(&self, memory_id: Option<&str>) -> Result<Vec<(Memory, Status, Vec<CheckResult>)>> {
        let now = chrono::Utc::now();
        let targets = match memory_id {
            Some(id) => match self.get_memory(id)? {
                Some(m) => vec![m],
                None => return Err(crate::error::Error::NotFound(format!("memory '{id}' does not exist"))),
            },
            None => self.memories(false)?,
        };
        Ok(targets
            .into_iter()
            .map(|m| {
                let (s, r) = run_checks(&self.root, &m.checks, &now);
                (m, s, r)
            })
            .collect())
    }
}
