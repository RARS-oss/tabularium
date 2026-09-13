//! Recall: rank active memories lexically and semantically, verify them against the world, pack
//! them under a token budget, and sign a receipt saying exactly what was handed to the agent.
//!
//! Ranking is deterministic: exact BM25, exact cosine over vectors stored in the ledger
//! (quantized to four decimals), reciprocal-rank fusion with fixed tie-breaks.

use crate::canon::{blake3_hex, canonical_json, RECEIPT_DOMAIN};
use crate::embed::{cosine, quantize};
use crate::error::Result;
use crate::text::{estimate_tokens, tokenize, Bm25, Doc, BM25_B, BM25_K1};
use crate::types::*;
use crate::vault::{now_rfc3339, Vault};
use crate::verify::run_checks;
use rusqlite::params;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;

pub const POLICY_VERSION: u32 = 2;
/// Tokens charged per item on top of its text, for the kind/status framing the host adds.
pub const ITEM_OVERHEAD_TOKENS: u32 = 8;
/// Upper bound on how many candidates get verified per recall, to bound recall latency.
pub const MAX_VERIFY_CANDIDATES: usize = 200;
/// Reciprocal-rank-fusion constant. Contribution of rank r is (K+1)/(K+r): rank 1 gives 1.0.
pub const RRF_K: f64 = 60.0;

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
    /// Final score after fusion and status/trust factors.
    pub score: f64,
    pub bm25: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cosine: Option<f32>,
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
    /// Memories matched lexically or semantically (all of them for an empty query).
    pub matched: usize,
    /// Model used for semantic matching, when it was.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_model: Option<String>,
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
        // Same weight for now: splitting the taxonomy is about telling these two situations
        // apart for a reader (never claimed to be verifiable vs. verification was inconclusive
        // or skipped), not yet a calibrated claim that one deserves more trust than the other.
        Status::Unchecked => 0.9,
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

fn rrf(rank: usize) -> f64 {
    (RRF_K + 1.0) / (RRF_K + rank as f64)
}

fn title_of(text: &str, max_chars: usize) -> String {
    let first_line = text.lines().next().unwrap_or("").trim();
    let mut out: String = first_line.chars().take(max_chars).collect();
    if first_line.chars().count() > max_chars {
        out.push('…');
    }
    out
}

fn f3(x: f64) -> String {
    format!("{x:.3}")
}

/// Exact BM25 over active memories. Returns (index, score) for score > 0, best first, ties by
/// recency. `lexical` is false when the query has no tokens.
fn lexical_ranking(memories: &[Memory], query: &str) -> (Vec<(usize, f64)>, bool) {
    let q = tokenize(query);
    if q.is_empty() {
        return (Vec::new(), false);
    }
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
    let mut scored: Vec<(usize, f64)> =
        Bm25::build(docs).score_all(&q).into_iter().filter(|(_, s)| *s > 0.0).collect();
    scored.sort_by(|a, b| {
        b.1.partial_cmp(&a.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| memories[b.0].seq.cmp(&memories[a.0].seq))
    });
    (scored, true)
}

struct Semantic {
    model: String,
    query_hash: String,
    /// (index, quantized cosine) at or above the threshold, best first, ties by recency.
    ranking: Vec<(usize, f32)>,
}

/// One fused candidate before verification.
struct Candidate {
    idx: usize,
    base: f64,
    bm25: f64,
    lex_rank: Option<usize>,
    cosine: Option<f32>,
    sem_rank: Option<usize>,
}

impl Vault {
    fn semantic_ranking(&mut self, memories: &[Memory], query: &str) -> Option<Semantic> {
        if query.trim().is_empty() {
            return None;
        }
        let (model, mut vectors) = self.embed_texts(&[query])?;
        let qvec = vectors.pop()?;
        let stored = self.embeddings_for_active(&model).ok()?;
        if stored.is_empty() {
            return None;
        }
        let index_of: HashMap<&str, usize> = memories.iter().enumerate().map(|(i, m)| (m.id.as_str(), i)).collect();
        let threshold = self.config.embeddings.threshold;
        let mut ranking: Vec<(usize, f32)> = stored
            .iter()
            .filter_map(|(id, v)| {
                let i = *index_of.get(id.as_str())?;
                let c = quantize(cosine(&qvec, v));
                (c >= threshold).then_some((i, c))
            })
            .collect();
        ranking.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| memories[b.0].seq.cmp(&memories[a.0].seq))
        });
        Some(Semantic { model, query_hash: blake3_hex(&crate::embed::vector_to_bytes(&qvec)), ranking })
    }

    /// Lexical and semantic rankings fused with RRF. Without an embedder (or an empty query) this
    /// degrades to plain BM25 (or recency order).
    fn fused_candidates(&mut self, memories: &[Memory], query: &str) -> (Vec<Candidate>, bool, Option<Semantic>) {
        let (lex, lexical) = lexical_ranking(memories, query);
        let sem = self.semantic_ranking(memories, query);
        let mut by_idx: HashMap<usize, Candidate> = HashMap::new();
        if !lexical {
            // Empty query: everything, recency order, base 1.0.
            let mut all: Vec<Candidate> = memories
                .iter()
                .enumerate()
                .map(|(i, _)| Candidate { idx: i, base: 1.0, bm25: 0.0, lex_rank: None, cosine: None, sem_rank: None })
                .collect();
            all.sort_by(|a, b| memories[b.idx].seq.cmp(&memories[a.idx].seq));
            return (all, false, None);
        }
        for (rank, (i, s)) in lex.iter().enumerate() {
            by_idx.insert(*i, Candidate { idx: *i, base: 0.0, bm25: *s, lex_rank: Some(rank + 1), cosine: None, sem_rank: None });
        }
        if let Some(sem) = &sem {
            for (rank, (i, c)) in sem.ranking.iter().enumerate() {
                let e = by_idx.entry(*i).or_insert(Candidate {
                    idx: *i,
                    base: 0.0,
                    bm25: 0.0,
                    lex_rank: None,
                    cosine: None,
                    sem_rank: None,
                });
                e.cosine = Some(*c);
                e.sem_rank = Some(rank + 1);
            }
            for c in by_idx.values_mut() {
                c.base = c.lex_rank.map(rrf).unwrap_or(0.0) + c.sem_rank.map(rrf).unwrap_or(0.0);
            }
        } else {
            for c in by_idx.values_mut() {
                c.base = c.bm25;
            }
        }
        let mut cands: Vec<Candidate> = by_idx.into_values().collect();
        cands.sort_by(|a, b| {
            b.base
                .partial_cmp(&a.base)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.bm25.partial_cmp(&a.bm25).unwrap_or(std::cmp::Ordering::Equal))
                .then_with(|| memories[b.idx].seq.cmp(&memories[a.idx].seq))
        });
        (cands, true, sem)
    }

    /// Rank, verify, pack under budget, sign a receipt.
    pub fn recall(&mut self, query: &str, opts: &RecallOptions) -> Result<RecallResult> {
        let memories = self.memories(false)?;
        let (cands, lexical, sem) = self.fused_candidates(&memories, query);
        let now = chrono::Utc::now();
        let considered = memories.len();
        let matched = cands.len();

        // Verify and compute final scores for a bounded prefix of the ranking.
        let mut items: Vec<(RecallItem, u64)> = Vec::new();
        for c in cands.iter().take(MAX_VERIFY_CANDIDATES) {
            let m = &memories[c.idx];
            let (status, checks) = if opts.verify {
                run_checks(&self.root, &m.checks, &now)
            } else {
                (Status::Unverified, Vec::new())
            };
            if status == Status::Stale && !opts.include_stale {
                continue;
            }
            let score = c.base * status_factor(status) * trust_factor(m.trust);
            let tokens = estimate_tokens(&m.text) + ITEM_OVERHEAD_TOKENS;
            let mut why = String::new();
            if !lexical {
                why.push_str("no query: recency order");
            } else if sem.is_some() {
                let mut parts = Vec::new();
                if let Some(r) = c.lex_rank {
                    parts.push(format!("bm25 {} (#{r})", f3(c.bm25)));
                }
                if let (Some(cs), Some(r)) = (c.cosine, c.sem_rank) {
                    parts.push(format!("cos {cs:.3} (#{r})"));
                }
                why.push_str(&format!("{} → rrf {}", parts.join(" + "), f3(c.base)));
            } else {
                why.push_str(&format!("bm25 {}", f3(c.bm25)));
            }
            why.push_str(&format!(
                " × status {} ({}) × trust {} ({}) = {}",
                status,
                f3(status_factor(status)),
                m.trust,
                f3(trust_factor(m.trust)),
                f3(score)
            ));
            if let Some(fail) = checks.iter().find_map(|r| match &r.outcome {
                CheckOutcome::Fail { reason } => Some(reason.clone()),
                _ => None,
            }) {
                why.push_str(&format!("; stale because: {fail}"));
            }
            items.push((
                RecallItem {
                    id: m.id.clone(),
                    kind: m.kind,
                    text: m.text.clone(),
                    subject: m.subject.clone(),
                    trust: m.trust,
                    status,
                    score,
                    bm25: c.bm25,
                    cosine: c.cosine,
                    tokens,
                    created_at: m.created_at.clone(),
                    evidence: m.evidence.clone(),
                    checks,
                    why,
                },
                m.seq,
            ));
        }
        // Re-rank by final score; ties by recency.
        items.sort_by(|a, b| {
            b.0.score
                .partial_cmp(&a.0.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.1.cmp(&a.1))
        });

        // Greedy knapsack under the budget.
        let mut chosen = Vec::new();
        let mut skipped = Vec::new();
        let mut used: u32 = 0;
        for (it, _) in items {
            if chosen.len() >= opts.limit {
                break;
            }
            if used + it.tokens <= opts.budget_tokens {
                used += it.tokens;
                chosen.push(it);
            } else {
                skipped.push(Skipped { id: it.id, tokens: it.tokens, score: it.score });
            }
        }

        let (head_seq, head_hash) = self.head()?;
        let receipt_items: Vec<serde_json::Value> = chosen
            .iter()
            .map(|it| json!({"id": it.id, "status": it.status, "tokens": it.tokens, "score": it.score}))
            .collect();
        let result_hash = blake3_hex(canonical_json(&serde_json::Value::Array(receipt_items.clone())).as_bytes());
        let ts = now_rfc3339();
        let semantic_policy = sem.as_ref().map(|s| {
            json!({"model": s.model, "threshold": self.config.embeddings.threshold, "fusion": "rrf", "k": RRF_K,
                   "query_vector_hash": s.query_hash})
        });
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
                "semantic": semantic_policy,
                "status_factor": {"fresh": 1.0, "unchecked": 0.9, "unverified": 0.9, "stale": 0.5},
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
            semantic_model: sem.map(|s| s.model),
            items: chosen,
            skipped_for_budget: skipped,
            receipt,
        })
    }

    /// Cheap "you have memories about this" probe: lexical only, no verification, no receipt,
    /// no model load. Meant for per-prompt hooks.
    pub fn hint(&self, text: &str, n: usize) -> Result<HintResult> {
        let memories = self.memories(false)?;
        let (scored, lexical) = lexical_ranking(&memories, text);
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

    pub(crate) fn sign_receipt(&self, kind: &str, body: serde_json::Value, ts: &str) -> Result<Receipt> {
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
