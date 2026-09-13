# Dogfooding notes — first real agent session (2026-09-12/13)

Context: used the `tabularium` CLI live, from inside a Claude Code session, to record ~15
memories about the vault owner's real job-search decisions (applications sent, project roadmap
pivots, build priority). First use outside the test suite / synthetic examples — real evidence, real
`--check-file` links to real files that kept changing under it.

## What held up

- The `observe` → `remember` split never felt like friction — recording the raw utterance, then
  deriving a memory from it by evidence id, is a clean mental model even under real-time use.
- `--check-file` tied to files that were *actually edited during the session*
  (`PLAN.md`, `DESIGN.md`, `JOB-SEARCH-PLAN.md`) worked exactly as designed — this is the first
  time the staleness mechanic was exercised against a moving target, not a static test fixture.
- Cross-language recall worked on a real query, not a crafted one: a Russian-language recall
  found English-language memories via the multilingual embedder, unprompted.
- `subject` supersession was used twice on `planned-projects-list` as the roadmap changed
  (oculus → arbiter swap) — worked as "this plan replaced that plan," not as a duplicate.

## Friction — concrete improvement candidates

1. **`--json` is expensive for an agent caller, and there's no cheaper structured option.**
   Every `observe`/`remember --json` call returns the full event: `payload_hash`, `prev_hash`,
   `hash`, and a 128-hex-char Ed25519 `sig` inline. An LLM agent chaining `observe` → `remember`
   almost never needs to *see* the signature bytes — it only needs `id` to pass to
   `remember -e <id>`. Every one of those fields still costs the agent real context tokens on
   every call. Suggestion: a `--terse` mode (or CLI-default without `--json`) that prints just
   `id` (and `seq`) on one line; keep full `--json` for scripts that actually verify signatures.

2. **No single-shot "just record this" command.** Recording N related facts today is N
   `observe` calls + N `remember` calls, each with its own boilerplate. A convenience
   `tabularium note --kind fact "text"` (auto-generates the evidence event, then derives the
   memory from it) would halve the agent-side call count for the common case — plain
   `observe`/`remember` stays for the cases that genuinely need multi-evidence or explicit
   `--check-*` flags.

3. **No cheap "what changed since I last looked" recall.** Mid-session, `planned-projects-list`
   changed twice. An agent resuming a long task has no cheap way to ask "what's different since
   event X / since timestamp T" — it has to re-`recall` and diff mentally. A
   `tabularium recall --since <event-id|timestamp>` mode would make session-resumption cheap
   instead of re-reading everything.

4. **MCP path unexercised.** Every call this session went through the CLI as a subprocess from
   Claude Code's Bash tool, not the documented MCP stdio server (`tabularium serve`). The
   README's primary integration surface (Claude Code / Cursor / Codex via MCP) was not actually
   tested end-to-end here — worth a dedicated session doing that, since token/ergonomics
   characteristics of the MCP tool-call surface may differ from raw CLI JSON.

## Live findings (2026-09-13, follow-on session)

A second Claude Code session working directly on this repo picked up the friction points above
and produced a genuinely new result — not a synthetic test, a live incident:

- **The trust policy held against a cooperative, correct agent, not just an adversarial one.**
  The agent tried to overwrite `build-priority-order` (an `instruction` memory, `trust: user`)
  using its own reasoning as evidence (`trust: agent`) — and was rejected:
  `policy violation: instruction memory needs user-level trust; derived trust is 'agent'`.
  It did not attempt to fake a user utterance to route around the check; it recorded the
  underlying fact separately (`fact`, agent trust) and left the instruction memory correctly
  `stale`, waiting on the real user. This is the H2 claim exercised live, in the agent-overreach
  direction rather than the external-injection direction — worth citing as a real case study,
  not just a proptest, in `vigil`'s README when that project starts.
- **Threshold recalibration (0.72 → 0.50) needed real drift data.** A synthetic test never
  produced the 0.544 score a real, honest drift case did — confirms H1 can't be validated on
  synthetic fixtures alone; the Week 4 eval harness needs real corpora, not just generated ones.
- **`unchecked` vs `unverified` were deliberately left at the same score (0.9/0.9) for now** —
  no principled number existed yet to separate them; flagged as an open Week 4 question rather
  than a fabricated distinction. Correct call: don't invent precision you don't have.
- **Windows file-lock on the MCP server binary during iterative reinstall** — the running
  `tabularium serve` process holds the binary, so `cargo install --path` fails mid-development
  until the server is stopped first. Minor, but worth a note in the install docs for anyone
  iterating on the tool while an MCP client has it open.

## Recommended agent-usage pattern (for next time, mine or anyone's)

- Skip `--json` on `observe` when only the event id is needed — the human-readable line is far
  shorter than the JSON payload and contains the same id.
- Reserve `remember` for genuinely durable pivots, not every conversational aside. Recall quality
  degrades the same way any memory system's does if every utterance becomes a memory — this
  session stayed selective on purpose (~15 memories across a long conversation, not hundreds).
- Reach for `--check-file` whenever a memory is directly downstream of a real file's content.
  It's the single feature that made this feel like more than "notes with extra steps" — under-use
  it and tabularium is just a diary; use it whenever there's a real file to pin to, and it starts
  actually catching drift.
