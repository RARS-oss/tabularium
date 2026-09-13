//! Duplicate detection: active memories whose stored embeddings are near-identical, regardless of
//! subject (unlike `contradict.rs`, which requires two *different* subjects). Real duplicates are
//! often both subject-less -- an accidental re-recording of the same fact, not a labeled claim
//! drifting against another label.
//!
//! Detection only, exactly like `contradict.rs`: text synthesis is the host's job, not the core's.
//! To actually consolidate a flagged pair, call `Vault::remember` with `merged_from` set to their
//! ids -- the merge result then supersedes both, and they drop out of this scan on the next call
//! since it only ever looks at active memories.

use crate::contradict::{pairwise_similarity, SimilarityMemberRef};
use crate::error::Result;
use crate::types::{Memory, Receipt};
use crate::vault::Vault;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Bound on how many active memories are compared pairwise, newest first. Mirrors
/// `contradict::MAX_CONTRADICTION_CANDIDATES`; duplicates has no subject filter so the candidate
/// set is usually larger for the same vault.
pub const MAX_DUPLICATE_CANDIDATES: usize = 500;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DuplicateOptions {
    /// Overrides `vault.toml`'s `embeddings.duplicate_threshold` for this call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicatePair {
    pub a: SimilarityMemberRef,
    pub b: SimilarityMemberRef,
    pub cosine: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DuplicateReport {
    /// `None` when no embedder is available; the scan then finds nothing rather than erroring.
    pub model: Option<String>,
    pub threshold: f32,
    /// Active memories considered (before the candidate cap).
    pub considered: usize,
    pub pairs: Vec<DuplicatePair>,
    pub receipt: Receipt,
}

impl Vault {
    /// Find active memories, any subjects, whose stored embeddings are near-identical enough to
    /// be the same claim recorded twice. Read-only: nothing is written to the ledger.
    pub fn duplicates(&mut self, opts: &DuplicateOptions) -> Result<DuplicateReport> {
        let threshold = opts.threshold.unwrap_or(self.config.embeddings.duplicate_threshold);
        let mut candidates: Vec<Memory> = self.memories(false)?;
        let considered = candidates.len();
        candidates.sort_by(|a, b| b.seq.cmp(&a.seq));
        candidates.truncate(MAX_DUPLICATE_CANDIDATES);

        let model = self.embedding_model_id();
        let mut pairs = Vec::new();
        if let Some(model) = &model {
            let vectors: HashMap<String, Vec<f32>> = self.embeddings_for_active(model)?.into_iter().collect();
            let by_id: HashMap<&str, &Memory> = candidates.iter().map(|m| (m.id.as_str(), m)).collect();
            let raw = pairwise_similarity(&candidates, &vectors, threshold, |_a, _b| true);
            pairs = raw
                .into_iter()
                .map(|p| DuplicatePair {
                    a: SimilarityMemberRef::from(by_id[p.a_id.as_str()]),
                    b: SimilarityMemberRef::from(by_id[p.b_id.as_str()]),
                    cosine: p.cosine,
                })
                .collect();
        }

        let receipt = self.sign_similarity_receipt("duplicates", &model, threshold, considered, &pairs, |p| (p.a.id.clone(), p.b.id.clone(), p.cosine))?;
        Ok(DuplicateReport { model, threshold, considered, pairs, receipt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::embed::HashEmbedder;
    use crate::ledger::{ObserveInput, RememberInput};
    use crate::types::{EventKind, MemoryKind};
    use std::fs;

    fn new_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("proj");
        fs::create_dir_all(&root).unwrap();
        let v = Vault::init(&dir.path().join("vault"), "test", Some(&root)).unwrap();
        (dir, v)
    }

    fn remember(v: &mut Vault, subject: Option<&str>, text: &str) -> Memory {
        let ev = v
            .observe(ObserveInput { kind: EventKind::Utterance, content: text.into(), trust: None, channel: "test".into(), meta: None })
            .unwrap();
        v.remember(RememberInput {
            kind: MemoryKind::Note,
            text: text.into(),
            subject: subject.map(|s| s.into()),
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
    fn flags_near_identical_text_with_no_subject_at_all() {
        let (_d, mut v) = new_vault();
        v.set_embedder(Some(Box::new(HashEmbedder::new(64))));
        remember(&mut v, None, "the deploy branch is release");
        remember(&mut v, None, "the deploy branch is release");
        let r = v.duplicates(&DuplicateOptions::default()).unwrap();
        assert_eq!(r.model.as_deref(), Some("hash:64"));
        assert_eq!(r.pairs.len(), 1);
        assert!((r.pairs[0].cosine - 1.0).abs() < 1e-6, "{}", r.pairs[0].cosine);
    }

    #[test]
    fn a_contradiction_shaped_pair_is_not_flagged_at_the_higher_threshold() {
        // Different subjects, real but partial overlap -- exactly what contradict.rs's default
        // threshold (0.50) would catch, but duplicates' much stricter default should not.
        let (_d, mut v) = new_vault();
        v.set_embedder(Some(Box::new(HashEmbedder::new(64))));
        remember(&mut v, Some("plan.a"), "ship vigil then oculus then fons");
        remember(&mut v, Some("plan.b"), "ship vigil then arbiter then fons then auctor");
        let r = v.duplicates(&DuplicateOptions::default()).unwrap();
        assert!(r.pairs.is_empty(), "{:?}", r.pairs);
    }

    #[test]
    fn no_embedder_returns_empty_not_error() {
        let (_d, mut v) = new_vault();
        v.set_embedder(None);
        remember(&mut v, None, "same text");
        remember(&mut v, None, "same text");
        let r = v.duplicates(&DuplicateOptions::default()).unwrap();
        assert_eq!(r.model, None);
        assert!(r.pairs.is_empty());
        assert_eq!(r.considered, 2);
    }

    #[test]
    fn merged_sources_drop_out_of_the_next_scan() {
        let (_d, mut v) = new_vault();
        v.set_embedder(Some(Box::new(HashEmbedder::new(64))));
        let a = remember(&mut v, None, "identical note text");
        let b = remember(&mut v, None, "identical note text");
        assert_eq!(v.duplicates(&DuplicateOptions::default()).unwrap().pairs.len(), 1);

        v.remember(RememberInput {
            kind: MemoryKind::Note,
            text: "identical note text (consolidated)".into(),
            subject: None,
            evidence: vec![],
            checks: vec![],
            channel: "test".into(),
            trust: None,
            merged_from: vec![a.id, b.id],
            meta: None,
        })
        .unwrap();

        assert!(v.duplicates(&DuplicateOptions::default()).unwrap().pairs.is_empty(), "merged-away sources must not reappear");
    }
}
