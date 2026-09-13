# tabularium: verifiable long-term memory for LLM agents

*Working skeleton, `evals/paper/skeleton.md`. Numbers below are from real runs of
`evals/{staleness,determinism,injection,locomo}/run.py` (see `evals/results/*.json`), not
placeholders -- and not the full-scale runs a publication would need (see Limitations).*

## Abstract

Existing agent-memory systems extract mutable text with an LLM and paste it back into context at
recall time. This architecture produces four failures independent of any particular
implementation: silent staleness, susceptibility to poisoning, irreproducibility, and unbounded
context cost. tabularium replaces the mutable-text-store architecture with an append-only,
hash-chained, Ed25519-signed event ledger; memories are a pure, replayable function of it, with
provenance and declarative validity checks re-verified at recall time. We evaluate four resulting
claims (H1-H4) empirically against the shipped binary.

## 1. Problem

(See `docs/DESIGN.md` §1: silent staleness, poisoning, irreproducibility, no budget accounting --
four failures of the extract-mutable-text-and-paste-back architecture common to Mem0, Zep/Graphiti,
Letta, LangMem, and file-based memories in coding CLIs.)

## 2. Design

(See `docs/DESIGN.md` §2: ledger, trust, compile, verify, recall. Not restated here.)

## 3. Evaluation

All four suites are pure Python, drive the real `tabularium` binary as a black box through its
`--json` CLI output against a throwaway scratch vault, and use `claude -p` (this session's own
authenticated Claude Code login) wherever an LLM step is needed -- no separate API key was
configured or required. Full harness: `evals/`.

### H1 -- staleness

**Claim:** with checks, the fraction of drifted facts served as fresh drops to ~0, at no loss on
the unchanged subset.

**Method:** 10 facts recorded with a `file_hash` check against a scratch file; half of those
files mutated after recording. A parallel arm of 10 identical facts recorded with *no* checks at
all, standing in for any system with no validity mechanism -- their backing files were mutated too.

**Result** (`staleness/run.py`, n=10 per arm):

| | with checks | no checks (baseline) |
|---|---|---|
| drifted facts correctly flagged stale | **5/5 (100%)** | n/a -- no mechanism to flag anything |
| unchanged facts still fresh | **5/5 (100%)** | n/a |
| drifted facts still served as fresh | **0%** | **10/10 (100%)** |

Checks drove the stale-served-as-fresh rate from 100% (no mechanism) to 0%, with zero false
positives on the unchanged subset. Confirms H1 at this scale.

### H2 -- injection

**Claim:** memory-injection success rate is 0% by construction.

**Method:** a 7-attack corpus (`injection/attacks.py`) attempting, through the real CLI surface an
attacker with tool/agent access (not the user's own voice) would have: spoofing `trust: user` on
tool-output content; direct instruction injection at default trust; poisoned external documents;
bare instructions with no evidence; subject-reuse to overwrite a genuine instruction; laundering
trust through `merged_from`; abusing evidence citation to reach into another memory via `forget`.
Run under two channel policies plus one positive control (a genuine preference from real user
evidence, which must keep working -- a "fix" that also breaks the primary workflow isn't a fix).

**Result** (`injection/run.py`, after the fix below): **0/7 attacks succeed under either policy**,
legitimate evidence-backed preference creation unaffected in both.

**Finding, and a real fix, not just a finding:** this eval originally caught 1/7 attacks
succeeding under the *default* policy (`tabularium init`'s shipped, empty `[policy.channels]`) --
`observe` accepted an explicit trust override uncorrelated with `kind`, a residual gap DESIGN.md
§2.2 already named ("a recorder that mislabels trust... the policy can cap what the mcp:*
channels may assert"). The documented mitigation's *literal* reading -- cap the channel at Tool
trust -- was tried first and is a trap: `remember()`'s channel check runs on the recorder's fixed
Agent default, evaluated *before* evidence is resolved, so capping below Agent rejects every
`remember()` over that channel, legitimate or not. Rather than ship a config workaround, the gap
was fixed at the root in `Vault::observe` (`ledger.rs`): a trust override may only *downgrade*
from `kind.default_trust()`, never raise above it -- only `utterance` defaults to user trust, so a
tool-output "observation" can no longer simply claim to be one. This closes the attack under the
*unmodified default policy*, with zero vault.toml changes needed, protecting every vault rather
than only ones whose owner remembers to harden channels. Channel-capping at Agent remains
available as defense-in-depth, verified to still work and to leave the legitimate workflow intact,
but is no longer required. The trust mechanism itself held throughout (6/7 attacks already failed
even before this fix).

Baseline comparison against extraction-based systems' injection-attack success rates is cited from
the AgentPoison/MINJA literature (DESIGN.md §1's own references), not re-run here as a fresh
head-to-head against a reimplemented competing system.

### H3 -- parity (LoCoMo pilot; LongMemEval not run)

**Claim:** recall quality is within CI of the strongest baseline at equal token budget, on
LongMemEval and LoCoMo, with a reference extractor in the harness.

**Method (pilot):** one full LoCoMo conversation (`snap-research/locomo`, 19 sessions, real dialogue
including two participants' full session history) extracted in a single `claude -p` pass into a
scratch vault as plain `fact` memories (no LLM in tabularium-core itself -- the harness is the
host that does the extraction, per the engine's own "no model inside the core" rule). 8 of the
conversation's real annotated questions answered using *only* `recall`'s output (budget 600
tokens), graded by an LLM judge (`claude -p`) against the gold answer.

**Result** (`locomo/run.py`, pilot n=1 conversation, 8 questions): **118 facts extracted, 4/8
correct (50%)**. The 4 misses are genuine and reported, not hidden: two were `recall` not
surfacing the relevant fact ("What did Caroline research?", "When is Melanie planning on going
camping?" -- both answered "I don't know" rather than guessing), one was a near-miss on a relative
date ("the Sunday before 25 May" vs. a computed absolute date), one a plausible date resolved
incorrectly.

**Not run:** LongMemEval (`longmemeval/`). Its loader and download URL are built and verified
live, but the dataset is ~277MB with up to 40 sessions per instance -- a pilot at comparable scope
to LoCoMo's would be many times the `claude -p` call volume actually spent this session. Scaling
`locomo/run.py`'s pattern to it is mechanical, not a design gap; see `evals/README.md`.

**This is a pilot, explicitly:** n=1 conversation, 8 questions, one embedding model, one judge
model (Claude, not GPT-4o as LongMemEval's own official scorer uses -- a named methodology
difference, not a silent substitution). No confidence interval, no baseline system run
side-by-side. A real H3 claim needs the full LoCoMo set (10 conversations, ~199 questions each)
and a LongMemEval run at comparable scale, against at least one actual competing memory system,
not just recorded literature numbers.

### H4 -- reproducibility

**Claim:** 100% identical recalls across runs and machines.

**Method:** the same `recall` query issued 3 times against one scratch vault; the vault copied and
recalled again; the vault rebuilt (`compile --rebuild`) and its full memory list diffed
before/after. Compared on everything a recall receipt's `result_hash` actually commits to --
deliberately excluding each receipt's own timestamp (and the id/sig that sign it), which
legitimately differs per call.

**Result** (`determinism/run.py`, n=3 trials): same-process repeat identical, copied-vault
identical, rebuild identical, audit clean throughout. **100%**, confirming H4 at this scale, as an
independent black-box check from outside the binary (the Rust suite's own
`compile_is_deterministic_across_rebuild_and_copy` asserts the same property from inside).

## 4. Limitations

- H1, H2, H4 are real but small-n (10 facts, 7 attacks, 3 trials); no claim these are
  statistically powered, only that they are real runs, not simulations or assumptions.
- H3 is a single-conversation, 8-question pilot on one of two target benchmarks. LongMemEval was
  not run at all. No competing memory system was run side-by-side; H3's own baseline claim is
  unverified at any real scale.
- H2's baseline comparison against extraction-based systems is a literature citation, not a
  reproduced head-to-head.
- The trust-override-ceiling fix (H2) is code, not config, so it applies to every vault
  automatically -- but it was validated against this session's own 7-attack corpus, not an
  independent one; broader adversarial coverage (real AgentPoison/MINJA payloads replayed
  verbatim) would strengthen the claim further.

## 5. Related work

Mem0, Zep/Graphiti, Letta, LangMem, and file-based memories in coding CLIs (DESIGN.md §1) share
the extract-and-paste architecture this work replaces the mechanism of, not just tunes.

## 6. Future work

Full-scale H1/H2/H4 runs; a LongMemEval pilot; a real competing-system baseline for H3; replaying
verbatim payloads from the AgentPoison/MINJA literature through H2's corpus instead of
hand-written analogues; Week 5+ per `docs/DESIGN.md`'s own roadmap (next is whichever of
vigil/arbiter/fons/auctor/limen comes first per `build-priority-order`).
