# evals

Python black-box harness for the H1-H4 claims in `docs/DESIGN.md` §3, plus follow-up suites for
specific risks and questions raised in review. Every suite drives the real `tabularium` binary
through its `--json` CLI output (`common/tabularium_client.py`) or a raw JSON-RPC session over
`tabularium serve` (`common/mcp_stdio_client.py`, for measuring warm-process latency the CLI path
can't) against a throwaway scratch vault (`common/scratch_vault.py`) -- never
`~/.tabularium/default`.

## Setup

```sh
export TABULARIUM_BIN=/path/to/target/release/tabularium.exe   # or rely on PATH
```

No API key needed for the LLM-shaped steps (`common/claude_headless.py`): they shell out to
`claude -p`, reusing whatever Claude Code login is already active in this environment, instead
of a separate OpenAI/Anthropic key (none is configured here). `pip install` is not required --
everything uses the Python 3.12 standard library only.

## Suites

| Suite | Needs network / claude -p? | Status |
|---|---|---|
| `staleness/` (H1) | no | built and run |
| `determinism/` (H4) | no | built and run |
| `injection/` (H2) | no | built and run |
| `locomo/` (H3, LoCoMo half) | claude -p only (dataset is bundled in-repo upstream) | built and run, pilot scale |
| `longmemeval/` (H3, LongMemEval half) | dataset download (~277MB) + claude -p | loader built, **not run** this session |
| `staleness/refactor_robustness.py` (H1 follow-up) | no | built and run |
| `scale/` (risk-review follow-up) | no | built and run |
| `language/` (risk-review follow-up) | no | built and run |

Run any suite directly, e.g.:

```sh
python staleness/run.py
python staleness/refactor_robustness.py
python determinism/run.py
python injection/run.py
python locomo/run.py [n_conversations] [n_questions_per_conversation]   # defaults 1, 10
python scale/run.py
python language/ru_en_rrf.py
```

Each writes its result to `results/<suite>.json` (gitignored) and exits nonzero if its `all_pass`
(or equivalent) check fails.

## Why LongMemEval wasn't run at pilot scale

`longmemeval/longmemeval_dataset.py`'s download URL and redirect chain were verified live
(`curl`) before writing it, but the file itself is ~277MB and a single instance's haystack spans
up to ~40 chat sessions -- extracting all of them, then answering and judging, is many times the
`claude -p` call volume `locomo/run.py`'s single-conversation pilot used. Scaling `locomo/run.py`'s
pattern to LongMemEval is a mechanical follow-up (swap `locomo_dataset.py` for
`longmemeval_dataset.py`, swap the transcript builder for `session_transcript`, iterate
`haystack_sessions` instead of LoCoMo's `session_N` keys), not a design change -- just more
wall-clock time than this session spent on it.

## Injection eval's own finding (fixed)

`injection/run.py` originally found that a fresh `tabularium init`'s empty channel policy let one
attack in the corpus succeed (`observe --trust user` on tool-output content, then cited into an
instruction). The obvious fix -- capping the channel at Tool trust -- turned out to break the
system's own primary workflow (turning a real user utterance into a preference) along with the
attack, since `remember()`'s channel check runs on the recorder's fixed Agent default before
evidence is even resolved. The actual fix landed in `Vault::observe` (`ledger.rs`), not config: a
trust override may only downgrade from `kind.default_trust()`, never raise above it, so the attack
now fails under the *unmodified* default policy -- every vault is protected, not just ones an
owner remembers to harden. See `injection/run.py`'s `finding` field, or the paper skeleton, for
the full writeup; the corpus keeps this attack as a permanent regression check.

## Risk-review follow-ups (see `evals/paper/skeleton.md` §3.5 for the full writeup)

Three specific questions from an external review, checked rather than argued:

- **Mass-refactor false positives** (`staleness/refactor_robustness.py`): `file_hash` flags 100%
  of purely-cosmetic reformats as stale (byte-exact by design); `symbol_in_file` flags 0% of the
  same reformats while still catching 100% of genuine renames. Prefer `symbol_in_file` unless the
  claim really is about exact bytes.
- **Latency at scale** (`scale/run.py`): a cold CLI call pays the ONNX model's load cost every
  time (1.34s mean); a long-lived MCP session pays it once at startup (1.20s) and every call after
  is warm (16-22ms). Recall latency at 3200 active memories is still 48ms (sub-linear growth from
  50 memories' 13.6ms) -- the real cost the review named is specifically CLI-per-call usage, not
  recall's own scan.
- **Cross-language recall quality** (`language/ru_en_rrf.py`): real, with a narrowed but not closed
  gap. The root cause turned out to be `embeddings.threshold` (calibrated for same-language
  recall) rejecting genuinely-correct cross-script matches before they could become ranking
  candidates at all -- not BM25 interference, which the raw cosine dump ruled out directly. Fixed
  with a script-aware threshold (`text::dominant_script`, `EmbeddingConfig::cross_script_threshold`
  in `tabularium-core`): found-within-budget rose from 65% to 90% and MRR from 0.325 to 0.41 on the
  same mixed 20-memory RU/EN vault with the real ONNX embedder, same-language MRR unchanged at
  0.95. Top-1 accuracy stayed at 5% -- the fix restores candidacy, not ranking parity. See
  `evals/paper/skeleton.md` §3.5 for the full before/after writeup.

## Layout

```
common/
  tabularium_client.py   subprocess wrapper over the tabularium CLI's --json output
  scratch_vault.py        throwaway vault + pinned check-path root, guaranteed cleanup
  claude_headless.py       subprocess wrapper over `claude -p`, UTF-8 explicit, stdin not argv
  llm_pipeline.py           extract / answer / judge prompts, shared by locomo/ and (eventually) longmemeval/
  mcp_stdio_client.py       raw JSON-RPC over `tabularium serve`, for warm-process latency measurements
staleness/, determinism/, injection/, locomo/, longmemeval/, scale/, language/    one suite each
data/       downloaded datasets (gitignored)
results/    run outputs (gitignored)
paper/      skeleton.md -- the H1-H4 write-up (plus §3.5 follow-ups) with real numbers from the runs above
```
