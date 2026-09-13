# evals

Python black-box harness for the H1-H4 claims in `docs/DESIGN.md` §3. Every suite drives the
real `tabularium` binary through its `--json` CLI output (`common/tabularium_client.py`) against
a throwaway scratch vault (`common/scratch_vault.py`) -- never `~/.tabularium/default`.

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

Run any suite directly, e.g.:

```sh
python staleness/run.py
python determinism/run.py
python injection/run.py
python locomo/run.py [n_conversations] [n_questions_per_conversation]   # defaults 1, 10
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

## Layout

```
common/
  tabularium_client.py   subprocess wrapper over the tabularium CLI's --json output
  scratch_vault.py        throwaway vault + pinned check-path root, guaranteed cleanup
  claude_headless.py       subprocess wrapper over `claude -p`, UTF-8 explicit, stdin not argv
  llm_pipeline.py           extract / answer / judge prompts, shared by locomo/ and (eventually) longmemeval/
staleness/, determinism/, injection/, locomo/, longmemeval/    one suite each
data/       downloaded datasets (gitignored)
results/    run outputs (gitignored)
paper/      skeleton.md -- the H1-H4 write-up with real numbers from the runs above
```
