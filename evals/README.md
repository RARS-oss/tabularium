# evals

Benchmark harness (Python) for the research claims in `docs/DESIGN.md`.

Planned suites:

- `staleness/` — synthetic repositories that drift (renames, config changes); measures stale facts served as fresh.
- `injection/` — memory-injection attacks (AgentPoison / MINJA style) through tool outputs and documents; measures how many become preferences/instructions.
- `longmemeval/`, `locomo/` — parity on public conversational-memory benchmarks with a reference extractor.
- `determinism/` — identical recalls across runs and machines.

The harness drives the `tabularium` binary through the CLI (`--json`) and the MCP stdio server.
