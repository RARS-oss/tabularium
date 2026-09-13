# tabularium — design

## 1. Problem

Agent memory systems (Mem0, Zep/Graphiti, Letta, LangMem, file-based memories in coding CLIs) share one
architecture: an LLM extracts "facts" into a mutable store, and retrieval pastes them back into context.
Four failures follow from that architecture, not from any particular implementation:

1. **Silent staleness.** A memory has no notion of what would make it false. Renamed function, moved
   file, changed config: the memory is still confidently served.
2. **Poisoning.** Everything in the store is treated as equally trustworthy. Content the agent merely
   *read* (a README, a web page, a tool output) becomes indistinguishable from what the *user said*.
   Memory-injection attacks (AgentPoison, MINJA) exploit exactly this.
3. **Irreproducibility.** Extraction and retrieval are non-deterministic LLM calls. Nobody can replay
   why the agent knew X at time T.
4. **No budget.** Memory competes with the task for context tokens with no accounting and no
   explanation of what was dropped.

## 2. Model

### 2.1 Ledger
An append-only log of **events**. Each event has `seq`, `ts`, `channel`, `kind`, `trust`,
`payload_hash`, `prev_hash`, `hash = BLAKE3(domain || fields)`, `sig = Ed25519(hash)`. The chain
commits to `payload_hash`, not the payload, so a payload can later be **redacted** (forget) without
breaking the chain. SQLite triggers make the table append-only; only `payload := NULL` is permitted.

Event kinds: `utterance` (user), `action` (agent), `observation` (tool output), `external` (imported),
`derive` (remember), `forget` (tombstone).

### 2.2 Trust
`external < tool < agent < user`, assigned at ingestion by the channel that ingested it, capped per
channel by vault policy, never raised. A derived memory's trust is `min(trust of evidence)`, or the
recorder's own trust when it cites nothing. Memory kinds `preference` and `instruction` (the ones that
can steer behaviour) require trust `user`, i.e. *all* evidence must be user utterances. The rule is
enforced before anything touches the ledger and re-checked on replay.

This is a structural claim, not a prompt: no sequence of untrusted inputs can produce an instruction.
The residual risk is a recorder that mislabels trust (an agent claiming a tool output was a user
utterance). That is why events carry a `channel`, why hooks that observe the real user prompt run
outside the model, and why the policy can cap what the `mcp:*` channels may assert.

### 2.3 Compile
`memories = compile(ledger)`. A pure, order-dependent fold over events: `derive` inserts a memory
(superseding an older one with the same `subject`), `forget` collapses it to a canonical tombstone
stub. The view is persisted and advanced incrementally; `compile --rebuild` replays from genesis and
must yield the same bytes. This is asserted by property tests on random operation sequences.

The LLM never runs inside compile. Whatever an LLM concluded is itself an event (`derive` carries the
text), so non-determinism is quarantined in the log.

### 2.4 Verify
Memories carry declarative **checks**: `file_exists`, `file_hash` (BLAKE3 baked at remember time),
`symbol_in_file`, `ttl`. At recall, checks run against the real filesystem/clock and fold into a status:
`fresh` (all pass), `unchecked` (the memory carries no checks at all — it never claimed to be
verifiable), `unverified` (checks exist but errored rather than passing or failing, or verification
was skipped for this call), `stale` (any check failed). Stale memories are demoted and annotated
with the reason, not hidden: the agent learns *that* the world changed. `unchecked` and `unverified`
carry the same score weight today (0.9) — the split is about telling a reader the two situations
apart, not yet a calibrated claim that one deserves more trust than the other.

### 2.5 Recall
Two exact rankings over active memories, no approximate index:

- **lexical**: BM25 with English and Russian stopwords removed;
- **semantic**: cosine between the query vector and vectors **stored in the ledger**. Each `remember`
  appends an `embed` event `{memory_id, model, dim, vector_hex}`; compile materializes it into an
  `embeddings` table. A rebuilt vault therefore carries bit-identical vectors, and only the *query* is
  embedded live. Similarities are quantized to four decimals before ranking so low-bit differences
  between CPUs cannot reorder ties. Forgetting a memory redacts its `embed` events too: a vector is a
  lossy copy of the text.

The rankings are fused by reciprocal rank, `Σ (K+1)/(K+rank)` with `K = 60` (rank 1 contributes 1.0),
then `score = fused × status_factor × trust_factor`, ties by recency, then a greedy knapsack under a
token budget using a conservative token estimator. Each item carries a `why` string showing both ranks.
The receipt pins the ledger head, the query hash, the query vector hash, the model and the fusion policy.

The embedder is a trait. The default backend is a multilingual MiniLM through ONNX Runtime, statically
linked, model downloaded once. A deterministic hashing embedder drives the tests. Without any embedder
the engine is pure BM25 and the receipt says so. The per-prompt `hint` is always lexical so hooks never
pay for a model load.

## 3. Claims for the paper

- **H1 (staleness).** On a benchmark where the world drifts (files renamed, configs changed) the
  fraction of stale facts served as fresh drops from baseline levels to ~0 with checks, at no loss on
  the unchanged subset.
- **H2 (injection).** On an adversarial suite of memory-injection attacks, success rate is 0% by
  construction, versus non-trivial rates for extraction-based systems.
- **H3 (parity).** On LongMemEval and LoCoMo, with a reference extractor in the harness, recall quality
  is within CI of the strongest baseline at equal token budget.
- **H4 (reproducibility).** 100% identical recalls across runs and machines; baselines measured.

## 4. Roadmap

1. **Week 1 (done):** ledger, keys, compile, verify, recall, receipts, MCP stdio server, CLI, property tests.
2. **Week 2 (done):** stored embeddings + hybrid ranking; contradiction detection on `subject`
   (`Vault::contradictions` pairs active memories with *different* subjects whose stored embeddings
   exceed a separate, stricter threshold than recall's, since supersession already resolves same-subject
   drift; no LLM judges the pair, so it's reported as a possible conflict, not a proven one); hooks that
   record file reads as evidence (the existing `PostToolUse` hook already keyed off
   `tool_input.file_path`, generic across tools; the gap was the shipped matcher excluding `Read`,
   now `Read|Edit|Write|MultiEdit`); `roots` support in MCP (on `notifications/initialized` and
   `notifications/roots/list_changed`, a roots-capable client gets asked `roots/list` — a server-
   initiated request correlated by a fixed id on the same synchronous stdio channel, no async
   runtime needed — and the first root becomes the vault's root for resolving relative check paths);
   a status for memories that carry no checks ("unchecked", see §2.4) distinct from checks that
   could not run.
3. **Week 3 (done):** `redact` of source events (`forget` now also redacts any
   evidence event that no other *active* memory still cites; an evidence event backing another
   live memory survives, checked directly against the memories view rather than assumed);
   consolidation (done -- detection and merge are separate, composable operations, both explicit
   and logged, no LLM in either: `Vault::duplicates` is `contradictions`'s pairwise-cosine scan
   shared via `pairwise_similarity`, but with no subject filter and a far stricter threshold since
   a duplicate should be near-identical text, not just "same specific claim" -- calibrated against
   the real vault to 0.90, the gap between the most topically-related distinct memories observed
   (<= 0.771) and near-verbatim text (0.98+). `Vault::remember` gained `merged_from: Vec<String>`:
   each id must be an active memory, is auto-folded into `evidence` so trust cannot rise through a
   merge, and is superseded by the new memory exactly like subject supersession, just keyed by id;
   `forget`'s existing undo logic already operates on sets, so undoing a merge reactivates every
   source with no extra code); shared vaults with per-key trust (an `identity` is just a `VaultKeys`
   keypair stored outside any one vault, at `~/.tabularium/identity`, reusable across vaults like an
   SSH key; a vault's `Policy.writers` is an `authorized_keys`-style registry mapping a public key to
   a name and a trust ceiling. `append_event` additionally signs the same hash the vault's own key
   signs — no change to what's hashed, so no chain-format versioning issue — with the active writer
   identity, and trust is capped at `min(channel cap, writer's registry cap)`; an unregistered writer
   key caps at `external` rather than failing outright, so onboarding a new writer never requires
   touching the vault first. `writer_pubkey`/`writer_sig` are nullable columns, added via `ALTER
   TABLE` for vaults that predate this feature since `CREATE TABLE IF NOT EXISTS` is a no-op on an
   existing table; the append-only trigger's column list is rebuilt on every `open()` rather than
   guarded by `IF NOT EXISTS`, since that would have silently kept the old trigger — missing the new
   columns' equality check — on any vault migrated this way. `audit` verifies writer signatures
   cryptographically; deliberately out of scope for now: revocation does not retroactively lower
   trust already recorded under a since-removed key, and there is no remote sync between separate
   copies of a vault).
4. **Week 4 (done, pilot scale):** Python eval harness (`evals/`), driving the real binary as a
   black box via its `--json` CLI output, LLM steps via headless `claude -p` (no separate API key
   needed or configured). H1 staleness: checks drive stale-served-as-fresh from 100% (no-check
   baseline) to 0%, no false positives (n=10/arm). H2 injection: found and fixed a real gap in the
   *shipped default* policy (an empty `[policy.channels]` lets `observe --trust user` spoof its
   way into an instruction; capping the channel at Tool trust "fixes" it by breaking the system's
   own primary workflow too, capping at Agent instead closes it for free, confirmed by a positive
   control) -- 1/7 attacks succeed under default, 0/7 once hardened, legitimate preference
   creation unaffected either way. H3 parity: one real LoCoMo conversation piloted end to end
   (118 facts extracted, 4/8 questions answered correctly using only `recall`'s output, judged by
   Claude); LongMemEval's loader is built and its download verified live but not run at pilot
   scale this session (~277MB, far more `claude -p` volume per instance). H4 reproducibility:
   100% identical recalls across repeats, a copied vault, and a rebuild (n=3), independently of
   the Rust-internal property test asserting the same thing. Paper skeleton at
   `evals/paper/skeleton.md` with these real numbers, explicit about pilot scope throughout.
5. **Later:** GUI timeline ("what did the agent know at T"), HTTP transport, sampling-based
   extraction through the host.
