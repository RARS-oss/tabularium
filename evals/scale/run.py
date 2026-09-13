"""Latency at scale -- the risk this eval was asked to check: "pure BM25 + local ONNX embedding
on every call are fine for local dev, but real-time multi-agent swarms need careful caching and
indexing." Three real measurements instead of a guess:

A. Cold CLI cost: every `tabularium remember` invocation is a fresh process, so the ONNX embedder
   is lazily loaded from scratch every single time -- there is no warm cache across CLI calls,
   structurally.
B. Warm MCP-session cost: `tabularium serve` loads the model once and keeps the process alive
   (`main.rs`'s own comment: "long-lived process: load the model once..."). Driving raw JSON-RPC
   over one long-lived `serve` process (common/mcp_stdio_client.py) shows what a real MCP host
   actually pays per call once warm.
C. Recall latency vs. vault size: DESIGN.md is explicit that recall uses "two exact rankings...
   no approximate index" -- a deliberate reproducibility trade-off (an ANN index's build order or
   floating-point path could break "identical recall across runs and machines"). That means
   recall is O(n) in the number of active memories by construction. Measuring how it actually
   scales (not assuming) is the point.
"""

from __future__ import annotations

import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from scratch_vault import scratch_vault  # noqa: E402
from mcp_stdio_client import McpStdioSession  # noqa: E402


def cold_cli_remember_cost(n: int = 5) -> dict:
    times = []
    with scratch_vault("scale-cold") as v:
        for i in range(n):
            start = time.perf_counter()
            v.remember("fact", f"cold-call fact number {i}, with enough words to actually embed something real")
            times.append(time.perf_counter() - start)
    return {"n_calls": n, "times_sec": times, "mean_sec": statistics.mean(times), "note": "each call is a fresh process -- no warm state possible via the CLI"}


def warm_mcp_remember_cost(n: int = 20) -> dict:
    with scratch_vault("scale-warm") as v:
        session = McpStdioSession(v.path)
        try:
            times = [session.timed_call("memory_remember", {"kind": "fact", "text": f"warm-call fact number {i}, enough words to embed"})[0] for i in range(n)]
            return {
                "n_calls": n,
                "startup_sec": session.startup_sec,
                "first_call_sec": times[0],
                "mean_after_first_sec": statistics.mean(times[1:]) if len(times) > 1 else None,
                "note": "startup_sec (spawn -> initialize handshake) is where the model load actually happens for a server; the tool calls that follow, including the first, are already warm.",
            }
        finally:
            session.close()


def recall_latency_vs_size(sizes: list[int] = [50, 200, 800, 3200]) -> dict:
    results = []
    with scratch_vault("scale-recall") as v:
        session = McpStdioSession(v.path)
        try:
            written = 0
            for target in sizes:
                while written < target:
                    session.call_tool("memory_remember", {"kind": "fact", "text": f"scale fact {written}: the deploy branch for service {written % 37} is release, revision {written}"})
                    written += 1
                times = [session.timed_call("memory_recall", {"query": "deploy branch service revision", "budget_tokens": 800})[0] for _ in range(5)]
                results.append({"vault_size": target, "mean_recall_sec": statistics.mean(times), "min_sec": min(times), "max_sec": max(times)})
        finally:
            session.close()
    if len(results) >= 2:
        first, last = results[0], results[-1]
        size_ratio = last["vault_size"] / first["vault_size"]
        time_ratio = last["mean_recall_sec"] / first["mean_recall_sec"] if first["mean_recall_sec"] > 0 else None
    else:
        size_ratio = time_ratio = None
    return {"sizes": results, "size_ratio_largest_over_smallest": size_ratio, "time_ratio_largest_over_smallest": time_ratio}


def run() -> dict:
    return {
        "hypothesis": "scale (risk-point follow-up, not one of H1-H4)",
        "cold_cli": cold_cli_remember_cost(),
        "warm_mcp": warm_mcp_remember_cost(),
        "recall_vs_size": recall_latency_vs_size(),
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    out = Path(__file__).resolve().parent.parent / "results" / "scale.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
