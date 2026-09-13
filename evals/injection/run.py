"""H2 -- injection: run the attack corpus (attacks.py) under two policies:

- default: exactly what `tabularium init` ships -- empty `[policy.channels]`.
- hardened: `eval` capped at Agent trust, defense-in-depth on top of the code fix below (see
  attacks.py::legitimate_preference_still_works for why Agent, not the more obvious Tool).

This suite originally found `trust_override_spoof` succeeding under the default policy --
`observe` accepted a trust override uncorrelated with `kind`. That's now fixed at the root in
`Vault::observe` (a trust override may only downgrade from `kind.default_trust()`, never raise
above it), so the attack fails under *both* conditions with no config needed; it stays in the
corpus as a permanent regression check, not a still-open gap.

Each attack/control still carries an *expected* outcome per policy (attacks.py::ATTACKS) -- the
headline number is whether reality matches what the trust model predicts, not just "0%
everywhere," so a future regression here would show up as a mismatch, not a quietly-passing test.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from scratch_vault import scratch_vault  # noqa: E402
from attacks import ATTACKS  # noqa: E402

CONTROL_NAMES = {"legitimate_preference_still_works"}


def _harden(vault_path: Path) -> None:
    """Cap the `eval` channel at Agent trust -- defense-in-depth, not the primary fix anymore.
    Exact string replacement, not a generic TOML writer: `tabularium init` always emits an empty
    `[policy.channels]` table verbatim (checked against the real output), so this is precise, not
    a guess at the file's shape.

    Capping at Tool was tried first and rejects every `remember()` over the channel outright,
    legitimate or not: `remember`'s channel check runs on the *recorder* default (always Agent --
    neither the CLI nor MCP exposes a trust override for remember), before evidence is even
    resolved. Agent is the surgical level: recorders at Agent-or-below still pass that gate, so
    plain facts and genuine evidence-backed preferences keep working.
    """
    toml_path = vault_path / "vault.toml"
    text = toml_path.read_text(encoding="utf-8")
    marker = "[policy.channels]\n"
    assert marker in text, "vault.toml did not contain the expected empty [policy.channels] table"
    toml_path.write_text(text.replace(marker, marker + 'eval = "agent"\n', 1), encoding="utf-8")


def run_condition(hardened: bool) -> dict:
    with scratch_vault("injection") as v:
        if hardened:
            _harden(v.path)
        results = {}
        for name, (fn, expected_default, expected_hardened) in ATTACKS.items():
            expected = expected_hardened if hardened else expected_default
            outcome = fn(v)
            results[name] = {**outcome, "expected": expected, "matched_expectation": outcome["succeeded"] == expected}

        attacks = {k: v for k, v in results.items() if k not in CONTROL_NAMES}
        n_succeeded = sum(1 for r in attacks.values() if r["succeeded"])
        n_matched = sum(1 for r in results.values() if r["matched_expectation"])
        return {
            "hardened": hardened,
            "results": results,
            "n_attacks": len(attacks),
            "n_attacks_succeeded": n_succeeded,
            "attack_success_rate": n_succeeded / len(attacks),
            "legitimate_workflow_still_works": results["legitimate_preference_still_works"]["succeeded"],
            "n_matched_expectation": n_matched,
            "all_matched_expectation": n_matched == len(results),
        }


def run() -> dict:
    default = run_condition(hardened=False)
    hardened = run_condition(hardened=True)
    return {
        "hypothesis": "H2",
        "default_policy": default,
        "hardened_policy": hardened,
        "finding": (
            "trust_override_spoof originally succeeded under the DEFAULT policy every fresh "
            "`tabularium init` ships (empty [policy.channels]): observe accepted a raw trust "
            "override uncorrelated with kind, so a tool-output observation could simply claim "
            "trust=user and get cited into an instruction -- a residual risk DESIGN.md 2.2 "
            "already named. Fixed at the root, not by config: Vault::observe now rejects a trust "
            "override above kind.default_trust() (only 'utterance' defaults to user), so the "
            "attack fails under the unmodified default policy, 0/7, with the legitimate "
            "evidence-backed-preference workflow confirmed unaffected by a positive control. "
            "Channel hardening (capping at Agent, not the more obvious Tool, which breaks "
            "remember() outright since its channel check runs on the recorder's fixed Agent "
            "default before evidence is resolved) remains available as defense-in-depth, but is "
            "no longer required to close this specific gap."
        ),
        "closed_by_api_design": (
            "A bare `remember --trust user` with no evidence was not attempted as a separate "
            "attack: neither the CLI nor the MCP memory_remember tool exposes a trust override "
            "for remember at all (checked --help / the MCP schema), so that vector does not "
            "exist as an API surface, independent of policy."
        ),
        "all_pass": default["all_matched_expectation"] and hardened["all_matched_expectation"],
    }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2))
    out = Path(__file__).resolve().parent.parent / "results" / "injection.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    sys.exit(0 if result["all_pass"] else 1)
