# tabularium

**Verifiable, auditable long-term memory for LLM agents.** One binary, no API keys, works offline,
plugs into Claude Code, Cursor, Codex or anything that speaks MCP.

Existing agent memories are mutable text that the model trusts blindly. They go stale without
noticing, they can be poisoned by anything the agent reads, and nobody can reproduce why an agent
"remembered" what it did. tabularium fixes that at the engine level, not by asking the model to be careful.

| Property | How |
|---|---|
| **Never lies silently** | Every memory carries evidence ids and validity checks (file hash, symbol present, TTL). Checks are re-run at recall time; a memory whose world has changed comes back marked `stale`, with the reason. |
| **Cannot be poisoned into instructions** | Trust is attached at ingestion (`external < tool < agent < user`) and never rises. A memory's trust is the weakest of its evidence. `preference` and `instruction` memories are rejected unless every piece of evidence is a user utterance. Enforced by construction, tested by fuzzing. |
| **Shared vaults, per-key trust** | A vault isn't limited to one writer. Each writer signs events with its own identity key (`tabularium identity`); the vault owner registers which keys may write and at what trust ceiling (`tabularium writer`) — an unregistered key caps at `external`, verified by `audit`, not just trusted by convention. |
| **Reproducible** | The only source of truth is an append-only, hash-chained, Ed25519-signed event ledger. The memory view is a pure function of it: incremental compilation and a full rebuild are byte-identical, and tests assert it. Recall uses exact BM25 plus exact cosine over vectors that are computed once and stored in the ledger, fused by reciprocal rank with fixed tie-breaks. |
| **Cross-language** | A multilingual embedding model runs locally through ONNX (statically linked, downloaded once to `~/.tabularium/models`), with a script-aware recall threshold so a genuine Russian-English match isn't rejected just for scoring lower than same-language pairs typically do. Ask in Russian, find what was saved in English -- real, and it finds the right memory within budget 9 times in 10 (up from 6.5, measured), but it still ranks behind same-language recall, not parity (`evals/paper/skeleton.md` §3.5). Without the model the engine degrades to lexical recall and says so. |
| **Budgeted and explainable** | Recall packs memories under a token budget and tells you why each item ranked where it did. |
| **Auditable** | Every recall yields a signed receipt: ledger head, query hash, policy, exactly which items were handed over. `tabularium audit` verifies the whole chain. |
| **LLM-free core** | The host agent does the thinking. The engine keeps it honest. No keys, no network. |

## Install

```sh
cargo install --path crates/tabularium
tabularium init            # creates ~/.tabularium/default with a fresh Ed25519 key
```

## Use from Claude Code

Add to `.mcp.json` in your project (or `~/.claude.json` for all projects):

```json
{ "mcpServers": { "tabularium": { "command": "tabularium", "args": ["serve"] } } }
```

Optional but recommended, in `.claude/settings.json`: a hook that whispers "you have memories about this"
on every prompt, and one that records file reads and edits as evidence automatically.

```json
{
  "hooks": {
    "UserPromptSubmit": [{ "hooks": [{ "type": "command", "command": "tabularium hook user-prompt" }] }],
    "PostToolUse": [{ "matcher": "Read|Edit|Write|MultiEdit", "hooks": [{ "type": "command", "command": "tabularium hook post-tool" }] }]
  }
}
```

The server exposes: `memory_observe`, `memory_remember`, `memory_recall`, `memory_hint`, `memory_verify`,
`memory_contradictions`, `memory_duplicates`, `memory_forget`, `memory_list`, `memory_audit`,
`memory_receipt`, `memory_info`.

## Use from the shell

```sh
tabularium observe --kind utterance "we deploy from the release branch only"
#   event 3f9c…  seq 1  kind utterance  trust user
tabularium remember --kind instruction -e 3f9c… "Deploy only from the release branch."
tabularium remember --kind fact --check-symbol src/lib.rs::compile_ledger "compile_ledger lives in src/lib.rs"
tabularium recall "how do we deploy" --budget 400
tabularium verify              # which memories went stale?
tabularium contradictions      # which differently-labeled memories now look like the same claim?
tabularium duplicates          # which memories, any subject, are near-identical text?
tabularium remember --kind fact --merge 3f9c… --merge a01e… "consolidated wording"  # retires both
tabularium audit               # chain, signatures, commitments, receipts
tabularium compile --rebuild   # replay the ledger from genesis; must equal the incremental view
tabularium embed               # write vectors for memories that have none (first run downloads the model)
```

Embeddings are on by default (`[embeddings]` in `vault.toml`: `enabled`, `model`, `threshold`, `cache_dir`).
Set `TABULARIUM_NO_EMBED=1` to force lexical-only for a process; hooks always run lexical-only.

### Sharing a vault between writers

```sh
tabularium identity init                          # ~/.tabularium/identity, reusable across vaults
tabularium identity show                           # hand this public key to the vault owner
tabularium writer add <pubkey> --name alice --max-trust user   # vault owner registers it
tabularium writer list
tabularium --identity ~/.tabularium/identity observe --kind utterance "..."  # now signs as that writer
```

An unregistered writer key can still write, capped at `external` trust, so onboarding a new writer
never requires touching the vault first. `tabularium audit` verifies every writer signature.

## Guarantees under test

- `cargo test` runs unit, integration and property tests (proptest):
  - **trust monotonicity**: random operation sequences never yield a steering memory with non-user evidence;
  - **determinism**: incremental view == rebuilt view, vectors included; a copied vault recalls identically;
  - **redaction**: forgetting a memory redacts its text, its vector, and any evidence event no
    longer cited by another active memory, and the chain still audits;
  - **integrity**: any altered byte in the ledger fails `audit`; the SQLite triggers make the table append-only;
  - **per-key trust**: a registered writer's trust ceiling is enforced regardless of channel; an
    unregistered key caps at `external`; a tampered writer signature fails `audit`;
  - **budget**: recall never exceeds its token budget.

## Layout

```
crates/tabularium-core   ledger, keys, compile, verify, recall
crates/tabularium-mcp    JSON-RPC/stdio MCP server, no async runtime
crates/tabularium        CLI + `serve`
integrations/claude-code example .mcp.json and hooks
docs/DESIGN.md           the design and the research claims
evals/                   Python benchmark harness: H1-H4 against DESIGN.md's claims
```

## Status

v0.2: core, stored embeddings and hybrid recall, contradiction and duplicate detection, explicit merge,
evidence redaction, shared vaults with per-key trust, and a Python eval harness against DESIGN.md's
H1-H4 claims (`evals/`, real pilot-scale numbers in `evals/paper/skeleton.md`). See `docs/DESIGN.md`
for what's next: a GUI timeline, HTTP transport, and the portfolio projects this one unblocks.

License: MIT OR Apache-2.0.
