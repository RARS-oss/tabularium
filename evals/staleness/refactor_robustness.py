"""Follow-up to H1, asked directly: how does `verify` behave during mass refactoring -- does it
throw a wave of *false*-positive staleness (the underlying fact is still true, but the check
trips anyway) on symbol/hash checks? Split by check type, because `file_hash` and
`symbol_in_file` have structurally different sensitivity:

- `file_hash` is byte-exact: ANY change to the file -- including a pure reformat that touches
  nothing the memory is actually about -- flips it stale. That's a real false positive.
- `symbol_in_file` is a substring test: a reformat that leaves the symbol's spelling untouched
  should NOT trip it, while an actual rename (the symbol's text genuinely disappearing) should
  correctly trip it -- a true positive, not a false one.

This is not "does staleness detection work" (staleness/run.py already covers that) -- it's "what's
the false-positive rate specifically under the kind of change (a mass reformat) `verify` has to
tolerate to be usable day to day."
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from scratch_vault import scratch_vault  # noqa: E402

N = 10  # files per check type


def original_source(i: int) -> str:
    return f"pub fn compute_value_{i}(x: i32) -> i32 {{\n    x * 2 + {i}\n}}\n"


def reformatted_source(i: int) -> str:
    # Cosmetic only: reindented, extra blank lines, a comment added. The function name and body
    # logic are byte-identical apart from whitespace/comments -- nothing a reader would call a
    # "change" to the fact "compute_value_i lives in this file."
    return f"pub fn compute_value_{i}(x: i32) -> i32\n{{\n\n    // reformatted by the mass pass\n    x * 2 + {i}\n\n}}\n"


def renamed_source(i: int) -> str:
    # A genuine rename: the old symbol text is gone. This should trip *both* check types.
    return f"pub fn compute_total_{i}(x: i32) -> i32 {{\n    x * 2 + {i}\n}}\n"


def run(n: int = N) -> dict:
    with scratch_vault("refactor-robustness") as v:
        hash_ids, symbol_ids = [], []
        for i in range(n):
            f = v.root / f"hash_checked_{i}.rs"
            f.write_text(original_source(i))
            m = v.remember("fact", f"compute_value_{i} lives in hash_checked_{i}.rs", checks=[{"type": "file_hash", "path": f"hash_checked_{i}.rs"}])
            hash_ids.append(m["id"])

            f2 = v.root / f"symbol_checked_{i}.rs"
            f2.write_text(original_source(i))
            m2 = v.remember(
                "fact",
                f"compute_value_{i} lives in symbol_checked_{i}.rs",
                checks=[{"type": "symbol_in_file", "path": f"symbol_checked_{i}.rs", "symbol": f"compute_value_{i}"}],
            )
            symbol_ids.append(m2["id"])

        # Half of each arm gets a pure cosmetic reformat; the other half gets a genuine rename.
        half = n // 2
        for i in range(n):
            source = reformatted_source(i) if i < half else renamed_source(i)
            (v.root / f"hash_checked_{i}.rs").write_text(source)
            (v.root / f"symbol_checked_{i}.rs").write_text(source)

        reports = {r["memory_id"]: r["status"] for r in v.verify()}

        def rate(ids: list[str], indices: range) -> float:
            flagged = sum(1 for i in indices for mid in [ids[i]] if reports[mid] == "stale")
            return flagged / len(list(indices)) if indices else 0.0

        reformatted_idx = range(0, half)
        renamed_idx = range(half, n)
        result = {
            "hypothesis": "H1 follow-up: refactor false-positive rate",
            "n_per_check_type": n,
            "file_hash": {
                "false_positive_rate_on_pure_reformat": rate(hash_ids, reformatted_idx),
                "true_positive_rate_on_genuine_rename": rate(hash_ids, renamed_idx),
            },
            "symbol_in_file": {
                "false_positive_rate_on_pure_reformat": rate(symbol_ids, reformatted_idx),
                "true_positive_rate_on_genuine_rename": rate(symbol_ids, renamed_idx),
            },
            "recommendation": (
                "file_hash flags every cosmetic change as stale by design (byte-exact) -- expect "
                "a false-positive wave on any mass reformat pass (gofmt/rustfmt/prettier-style). "
                "symbol_in_file is robust to reformatting (substring survives) while still "
                "catching genuine renames. Prefer symbol_in_file for 'this identifier exists "
                "somewhere in this file' claims; reserve file_hash for claims that really are "
                "about the file's exact bytes."
            ),
        }
        result["all_pass"] = (
            result["file_hash"]["false_positive_rate_on_pure_reformat"] == 1.0
            and result["file_hash"]["true_positive_rate_on_genuine_rename"] == 1.0
            and result["symbol_in_file"]["false_positive_rate_on_pure_reformat"] == 0.0
            and result["symbol_in_file"]["true_positive_rate_on_genuine_rename"] == 1.0
        )
        return result


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    out = Path(__file__).resolve().parent.parent / "results" / "refactor_robustness.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    sys.exit(0 if result["all_pass"] else 1)
