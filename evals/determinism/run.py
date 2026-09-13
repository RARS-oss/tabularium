"""H4 -- reproducibility: identical recalls across repeated calls, a copied vault, and a
rebuild. Black-box confirmation from outside the binary of what
`compile_is_deterministic_across_rebuild_and_copy` already asserts inside the Rust test suite.

A recall receipt's `ts` (and therefore its `id`/`sig`, which sign a body containing `ts`) is
*expected* to differ between calls -- each is a fresh attestation of "this happened now".
What must be identical is everything the receipt actually attests to: the item list, scores,
and `result_hash` (a hash of just the items, computed without `ts`). Comparing raw JSON
blobs including receipts would make every trial "fail" for the wrong reason.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from scratch_vault import scratch_vault  # noqa: E402
from tabularium_client import Vault  # noqa: E402

FACTS = [
    ("the database is postgres", None),
    ("we deploy from the release branch only", None),
    ("Claude Code hooks run on every prompt", "project.hooks"),
    ("the deploy branch is release, not main", None),
    ("compile_ledger lives in src/lib.rs", None),
]


def populate(v: Vault) -> None:
    for text, subject in FACTS:
        v.remember("fact", text, subject=subject)


def stable_view(recall_result: dict) -> dict:
    """The part of a recall result that must be byte-identical across runs: everything the
    receipt's result_hash actually commits to, not the receipt's own per-call timestamp."""
    body = recall_result.get("receipt", {}).get("body", {})
    return {
        "items": recall_result.get("items"),
        "used_tokens": recall_result.get("used_tokens"),
        "considered": recall_result.get("considered"),
        "matched": recall_result.get("matched"),
        "semantic_model": recall_result.get("semantic_model"),
        "skipped_for_budget": recall_result.get("skipped_for_budget"),
        "result_hash": body.get("result_hash"),
    }


def canon(view: dict) -> str:
    return json.dumps(view, sort_keys=True)


def run(query: str = "deploy branch", trials: int = 3) -> dict:
    with scratch_vault("determinism") as v:
        populate(v)

        views = [canon(stable_view(v.recall(query))) for _ in range(trials)]
        same_process_identical = len(set(views)) == 1

        copy_dir = v.path.parent / "vault-copy"
        shutil.copytree(v.path, copy_dir)
        copy_view = canon(stable_view(Vault(copy_dir).recall(query)))
        copied_vault_identical = copy_view == views[0]

        before = canon({"memories": v.memories(all_=True)})
        v.compile(rebuild=True)
        after = canon({"memories": v.memories(all_=True)})
        rebuild_identical = before == after

        audit_ok = v.audit()["ok"]

        return {
            "hypothesis": "H4",
            "query": query,
            "trials": trials,
            "same_process_identical": same_process_identical,
            "copied_vault_identical": copied_vault_identical,
            "rebuild_identical": rebuild_identical,
            "audit_ok": audit_ok,
            "all_pass": same_process_identical and copied_vault_identical and rebuild_identical and audit_ok,
        }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    out = Path(__file__).resolve().parent.parent / "results" / "determinism.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    sys.exit(0 if result["all_pass"] else 1)
