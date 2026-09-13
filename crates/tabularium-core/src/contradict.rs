//! Contradiction detection on `subject`: two differently-labeled active memories whose stored
//! embeddings look like they're about the same specific claim. Same-subject drift is already
//! resolved by supersession in `compile.rs`; this catches the case supersession cannot see —
//! two distinct subjects that quietly drifted into overlap (or outright conflict) because whoever
//! updated one never touched the other.
//!
//! No LLM runs here: a high cosine similarity is a *possible* conflict, not a proven one. The core
//! never claims to know that two texts disagree — only that they now look like the same claim.

use crate::canon::blake3_hex;
use crate::embed::{cosine, quantize};
use crate::error::Result;
use crate::types::{Memory, MemoryKind, Receipt, Trust};
use crate::vault::{now_rfc3339, Vault};
use serde::{Deserialize, Serialize};
use serde_json::json;

/// Bound on how many subject-bearing active memories are compared pairwise, newest first. Keeps
/// the O(n^2) scan cheap regardless of vault size, mirroring `recall::MAX_VERIFY_CANDIDATES`.
pub const MAX_CONTRADICTION_CANDIDATES: usize = 500;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContradictOptions {
    /// Overrides `vault.toml`'s `embeddings.contradiction_threshold` for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContradictionMemberRef {
    pub id: String,
    pub subject: String,
    pub kind: MemoryKind,
    pub trust: Trust,
    pub text: String,
    pub created_at: String,
}

impl ContradictionMemberRef {
    fn from(m: &Memory) -> ContradictionMemberRef {
        ContradictionMemberRef {
            id: m.id.clone(),
            subject: m.subject.clone().unwrap_or_default(),
            kind: m.kind,
            trust: m.trust,
            text: m.text.clone(),
            created_at: m.created_at.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContradictionPair {
    pub a: ContradictionMemberRef,
    pub b: ContradictionMemberRef,
    pub cosine: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContradictionReport {
    /// `None` when no embedder is available; the scan then finds nothing rather than erroring.
    pub model: Option<String>,
    pub threshold: f32,
    /// Subject-bearing active memories considered (before the candidate cap).
    pub considered: usize,
    pub pairs: Vec<ContradictionPair>,
    pub receipt: Receipt,
}

impl Vault {
    /// Find active memories with different `subject`s whose stored embeddings are similar enough
    /// to be about the same specific claim. Read-only: nothing is written to the ledger.
    pub fn contradictions(&mut self, opts: &ContradictOptions) -> Result<ContradictionReport> {
        let threshold = opts.threshold.unwrap_or(self.config.embeddings.contradiction_threshold);
        let mut candidates: Vec<Memory> =
            self.memories(false)?.into_iter().filter(|m| m.subject.is_some()).collect();
        let considered = candidates.len();
        // Newest first, then cap: recent subjects are the ones most likely to still be live drift.
        candidates.sort_by(|a, b| b.seq.cmp(&a.seq));
        candidates.truncate(MAX_CONTRADICTION_CANDIDATES);

        let model = self.embedding_model_id();
        let mut pairs = Vec::new();
        if let Some(model) = &model {
            let vectors = self.embeddings_for_active(model)?;
            let by_id: std::collections::HashMap<&str, &Vec<f32>> =
                vectors.iter().map(|(id, v)| (id.as_str(), v)).collect();
            let with_vectors: Vec<(&Memory, &Vec<f32>)> =
                candidates.iter().filter_map(|m| by_id.get(m.id.as_str()).map(|v| (m, *v))).collect();
            for i in 0..with_vectors.len() {
                let (a, va) = with_vectors[i];
                for (b, vb) in with_vectors.iter().skip(i + 1) {
                    if a.subject == b.subject {
                        continue;
                    }
                    let c = quantize(cosine(va, vb));
                    if c >= threshold {
                        pairs.push(ContradictionPair {
                            a: ContradictionMemberRef::from(a),
                            b: ContradictionMemberRef::from(b),
                            cosine: c,
                        });
                    }
                }
            }
            pairs.sort_by(|p, q| {
                q.cosine
                    .partial_cmp(&p.cosine)
                    .unwrap_or(std::cmp::Ordering::Equal)
                    .then_with(|| p.a.id.cmp(&q.a.id))
                    .then_with(|| p.b.id.cmp(&q.b.id))
            });
        }

        let (head_seq, head_hash) = self.head()?;
        let pair_bodies: Vec<serde_json::Value> = pairs
            .iter()
            .map(|p| json!({"a": p.a.id, "b": p.b.id, "cosine": p.cosine}))
            .collect();
        let result_hash = blake3_hex(crate::canon::canonical_json(&serde_json::Value::Array(pair_bodies.clone())).as_bytes());
        let ts = now_rfc3339();
        let body = json!({
            "kind": "contradictions",
            "ts": ts,
            "ledger_head": {"seq": head_seq, "hash": head_hash},
            "model": model,
            "threshold": threshold,
            "considered": considered,
            "pairs": pair_bodies,
            "result_hash": result_hash,
        });
        let receipt = self.sign_receipt("contradictions", body, &ts)?;
        Ok(ContradictionReport { model, threshold, considered, pairs, receipt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::HashEmbedder;
    use crate::ledger::{ObserveInput, RememberInput};
    use crate::types::EventKind;
    use std::fs;

    fn new_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        fs::create_dir_all(&root).unwrap();
        let v = Vault::init(&dir.path().join("vault"), "test", Some(&root)).unwrap();
        (dir, v)
    }

    fn remember(v: &mut Vault, subject: &str, text: &str) -> Memory {
        let ev = v
            .observe(ObserveInput { kind: EventKind::Utterance, content: text.into(), trust: None, channel: "test".into(), meta: None })
            .unwrap();
        v.remember(RememberInput {
            kind: MemoryKind::Fact,
            text: text.into(),
            subject: Some(subject.into()),
            evidence: vec![ev.id],
            checks: vec![],
            channel: "test".into(),
            trust: None,
            merged_from: vec![],
            meta: None,
        })
        .unwrap()
    }

    #[test]
    fn flags_same_text_under_different_subjects() {
        let (_d, mut v) = new_vault();
        v.set_embedder(Some(Box::new(HashEmbedder::new(64))));
        remember(&mut v, "plan.a", "ship vigil then arbiter then fons");
        remember(&mut v, "plan.b", "ship vigil then arbiter then fons");
        let r = v.contradictions(&ContradictOptions::default()).unwrap();
        assert_eq!(r.model.as_deref(), Some("hash:64"));
        assert_eq!(r.pairs.len(), 1);
        assert!((r.pairs[0].cosine - 1.0).abs() < 1e-6, "{}", r.pairs[0].cosine);
    }

    #[test]
    fn unrelated_subjects_are_not_flagged() {
        let (_d, mut v) = new_vault();
        v.set_embedder(Some(Box::new(HashEmbedder::new(64))));
        remember(&mut v, "plan.a", "ship vigil then arbiter then fons");
        remember(&mut v, "env.cargo-path", "added cargo bin to PATH on windows");
        let r = v.contradictions(&ContradictOptions::default()).unwrap();
        assert!(r.pairs.is_empty(), "{:?}", r.pairs);
    }

    #[test]
    fn superseded_memory_is_not_a_candidate() {
        let (_d, mut v) = new_vault();
        v.set_embedder(Some(Box::new(HashEmbedder::new(64))));
        remember(&mut v, "plan.a", "old plan text");
        remember(&mut v, "plan.a", "new plan text, unrelated words entirely");
        remember(&mut v, "plan.b", "old plan text");
        // "plan.a" was superseded by its own second remember, so only one "plan.a" is active;
        // it must never appear paired with itself, and the stale text should not match "plan.b".
        let r = v.contradictions(&ContradictOptions::default()).unwrap();
        assert!(r.pairs.is_empty(), "{:?}", r.pairs);
    }

    #[test]
    fn no_embedder_returns_empty_not_error() {
        let (_d, mut v) = new_vault();
        v.set_embedder(None);
        remember(&mut v, "plan.a", "ship vigil then arbiter then fons");
        remember(&mut v, "plan.b", "ship vigil then arbiter then fons");
        let r = v.contradictions(&ContradictOptions::default()).unwrap();
        assert_eq!(r.model, None);
        assert!(r.pairs.is_empty());
        assert_eq!(r.considered, 2);
    }

    #[test]
    fn threshold_override_is_respected() {
        let (_d, mut v) = new_vault();
        v.set_embedder(Some(Box::new(HashEmbedder::new(64))));
        remember(&mut v, "plan.a", "ship vigil then arbiter");
        remember(&mut v, "plan.b", "ship vigil then something else entirely different");
        let strict = v.contradictions(&ContradictOptions { threshold: Some(0.999) }).unwrap();
        let loose = v.contradictions(&ContradictOptions { threshold: Some(-1.0) }).unwrap();
        assert!(loose.pairs.len() >= strict.pairs.len());
        assert_eq!(loose.pairs.len(), 1);
    }
}
