//! Property tests: the invariants the paper will claim.
//!
//! 1. Trust monotonicity: no sequence of operations yields a behaviour-steering memory
//!    (preference/instruction) unless every piece of its evidence is user-trusted, and every
//!    memory's trust equals the weakest trust among its evidence.
//! 2. Determinism: incremental compilation equals a full rebuild, byte for byte, and audit passes.
//! 3. Budget: recall never exceeds its token budget, and reports exactly what it used.

use proptest::prelude::*;
use std::collections::HashMap;
use tabularium_core::*;

#[derive(Debug, Clone)]
enum Op {
    Observe { kind: u8, trust: u8, content: String },
    Remember { kind: u8, evidence: Vec<usize>, subject: Option<u8>, text: String },
    Forget { idx: usize },
}

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (0..4u8, 0..4u8, "[a-z]{1,8}( [a-z]{1,8}){0,6}")
            .prop_map(|(kind, trust, content)| Op::Observe { kind, trust, content }),
        4 => (
            0..5u8,
            prop::collection::vec(0..32usize, 0..4),
            prop::option::of(0..3u8),
            "[a-z]{1,8}( [a-z]{1,8}){0,10}"
        )
            .prop_map(|(kind, evidence, subject, text)| Op::Remember { kind, evidence, subject, text }),
        1 => (0..32usize).prop_map(|idx| Op::Forget { idx }),
    ]
}

fn kind_of(n: u8) -> EventKind {
    [EventKind::Utterance, EventKind::Action, EventKind::Observation, EventKind::External][n as usize % 4]
}

fn mkind_of(n: u8) -> MemoryKind {
    [MemoryKind::Fact, MemoryKind::Preference, MemoryKind::Instruction, MemoryKind::Reference, MemoryKind::Note]
        [n as usize % 5]
}

fn run_ops(v: &mut Vault, ops: &[Op]) -> (Vec<Event>, Vec<String>) {
    let mut events: Vec<Event> = Vec::new();
    let mut memory_ids: Vec<String> = Vec::new();
    for op in ops {
        match op {
            Op::Observe { kind, trust, content } => {
                let r = v.observe(ObserveInput {
                    kind: kind_of(*kind),
                    content: content.clone(),
                    trust: Trust::from_u8(*trust),
                    channel: "prop".into(),
                    meta: None,
                });
                if let Ok(e) = r {
                    events.push(e);
                }
            }
            Op::Remember { kind, evidence, subject, text } => {
                let evidence: Vec<String> = if events.is_empty() {
                    vec![]
                } else {
                    evidence.iter().map(|i| events[*i % events.len()].id.clone()).collect()
                };
                let r = v.remember(RememberInput {
                    kind: mkind_of(*kind),
                    text: text.clone(),
                    subject: subject.map(|s| format!("subj{s}")),
                    evidence,
                    checks: vec![],
                    channel: "prop".into(),
                    trust: None,
                    meta: None,
                });
                if let Ok(m) = r {
                    memory_ids.push(m.id);
                }
            }
            Op::Forget { idx } => {
                if !memory_ids.is_empty() {
                    let id = memory_ids[*idx % memory_ids.len()].clone();
                    let _ = v.forget(&id, "prop", "prop");
                }
            }
        }
    }
    (events, memory_ids)
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 24, .. ProptestConfig::default() })]

    #[test]
    fn trust_monotonicity_and_determinism(ops in prop::collection::vec(op_strategy(), 1..40)) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::init(&dir.path().join("v"), "prop", Some(dir.path())).unwrap();
        let (events, _) = run_ops(&mut v, &ops);
        let trust_by_id: HashMap<&str, Trust> = events.iter().map(|e| (e.id.as_str(), e.trust)).collect();

        for m in v.memories(true).unwrap() {
            if m.tombstoned {
                continue;
            }
            let evidence_trusts: Vec<Trust> = m.evidence.iter().map(|id| trust_by_id[id.as_str()]).collect();
            let expected = evidence_trusts.iter().copied().min().unwrap_or(Trust::Agent);
            prop_assert_eq!(m.trust, expected, "memory trust must be the weakest evidence");
            if m.kind.requires_user_trust() {
                prop_assert_eq!(m.trust, Trust::User);
                prop_assert!(!m.evidence.is_empty(), "steering memories need evidence");
                prop_assert!(evidence_trusts.iter().all(|t| *t == Trust::User));
            }
        }

        let incremental = v.snapshot().unwrap();
        v.compile(true).unwrap();
        prop_assert_eq!(incremental, v.snapshot().unwrap());
        let audit = v.audit().unwrap();
        prop_assert!(audit.ok, "{:?}", audit.problems);
    }

    #[test]
    fn recall_never_exceeds_budget(
        texts in prop::collection::vec("[a-zA-Zа-я]{1,12}( [a-zA-Zа-я]{1,12}){0,40}", 1..25),
        budget in 0u32..600,
        limit in 1usize..30,
        query in "[a-z]{1,8}( [a-z]{1,8}){0,3}",
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut v = Vault::init(&dir.path().join("v"), "prop", Some(dir.path())).unwrap();
        for t in &texts {
            let _ = v.remember(RememberInput {
                kind: MemoryKind::Fact, text: t.clone(), subject: None, evidence: vec![], checks: vec![],
                channel: "prop".into(), trust: None, meta: None,
            });
        }
        let opts = RecallOptions { budget_tokens: budget, limit, ..Default::default() };
        for q in [query.as_str(), ""] {
            let r = v.recall(q, &opts).unwrap();
            prop_assert!(r.used_tokens <= budget, "used {} > budget {}", r.used_tokens, budget);
            prop_assert_eq!(r.used_tokens, r.items.iter().map(|i| i.tokens).sum::<u32>());
            prop_assert!(r.items.len() <= limit);
            for w in r.items.windows(2) {
                prop_assert!(w[0].score >= w[1].score);
            }
            let again = v.recall(q, &opts).unwrap();
            prop_assert_eq!(&r.receipt.body["result_hash"], &again.receipt.body["result_hash"], "recall is deterministic");
        }
    }
}
