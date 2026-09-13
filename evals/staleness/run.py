"""H1 -- staleness: with tabularium's checks, facts whose backing file drifted are correctly
flagged stale, and untouched facts stay fresh. Without checks (the naive baseline every
extraction-based memory system effectively runs), drift is invisible by construction --
those facts keep reporting as though nothing happened, no matter what changed underneath.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from scratch_vault import scratch_vault  # noqa: E402

N = 10  # facts per arm; half of the checked arm gets its file mutated after recording


def run(n: int = N) -> dict:
    with scratch_vault("staleness") as v:
        checked_ids: list[str] = []
        checked_mutated: list[bool] = []
        baseline_ids: list[str] = []

        for i in range(n):
            f = v.root / f"fact_{i}.txt"
            f.write_text(f"fact {i} original content")
            mem = v.remember(
                "fact",
                f"fact {i} says the original thing",
                checks=[{"type": "file_hash", "path": f"fact_{i}.txt"}],
            )
            checked_ids.append(mem["id"])
            checked_mutated.append(i % 2 == 0)

            base_f = v.root / f"baseline_{i}.txt"
            base_f.write_text(f"baseline {i} original content")
            base_mem = v.remember("fact", f"baseline {i} says the original thing")  # no checks
            baseline_ids.append(base_mem["id"])

        # Drift the world after the fact: mutate the marked half of the checked arm, and every
        # baseline file (baseline has no per-item "mutated or not" distinction to make -- the
        # point is it can't tell either way).
        for i in range(n):
            if checked_mutated[i]:
                (v.root / f"fact_{i}.txt").write_text(f"fact {i} DRIFTED content")
            (v.root / f"baseline_{i}.txt").write_text(f"baseline {i} DRIFTED content")

        reports = {r["memory_id"]: r["status"] for r in v.verify()}

        mutated_total = sum(checked_mutated)
        unchanged_total = n - mutated_total
        mutated_flagged_stale = sum(
            1 for i, mid in enumerate(checked_ids) if checked_mutated[i] and reports[mid] == "stale"
        )
        unchanged_stayed_fresh = sum(
            1 for i, mid in enumerate(checked_ids) if not checked_mutated[i] and reports[mid] == "fresh"
        )
        # Every baseline file actually drifted; with no checks, tabularium (like any system with
        # no validity mechanism) has nothing to flag, so it keeps reporting them as before.
        baseline_served_as_fresh = sum(1 for mid in baseline_ids if reports[mid] == "unchecked")

        result = {
            "hypothesis": "H1",
            "n_per_arm": n,
            "with_checks": {
                "mutated_total": mutated_total,
                "mutated_correctly_flagged_stale": mutated_flagged_stale,
                "mutated_detection_rate": mutated_flagged_stale / mutated_total if mutated_total else None,
                "unchanged_total": unchanged_total,
                "unchanged_correctly_fresh": unchanged_stayed_fresh,
                "unchanged_false_stale_rate": (
                    1 - unchanged_stayed_fresh / unchanged_total if unchanged_total else None
                ),
            },
            "baseline_no_checks": {
                "all_drifted": n,
                "served_as_fresh_anyway": baseline_served_as_fresh,
                "stale_served_as_fresh_rate": baseline_served_as_fresh / n,
            },
        }
        result["all_pass"] = (
            result["with_checks"]["mutated_detection_rate"] == 1.0
            and result["with_checks"]["unchanged_false_stale_rate"] == 0.0
        )
        return result


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    out = Path(__file__).resolve().parent.parent / "results" / "staleness.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    sys.exit(0 if result["all_pass"] else 1)
