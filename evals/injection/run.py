"""H2 -- injection: run the attack corpus (attacks.py) under two policies:

- default: exactly what `tabularium init` ships -- empty `[policy.channels]`.
- hardened: `eval` capped at Agent trust -- the surgical mitigation this eval itself derived
  (see attacks.py::legitimate_preference_still_works for why Agent, not the more obvious Tool).

Each attack/control carries an *expected* outcome under each policy (attacks.py::ATTACKS). The
headline number isn't just "attack success rate" -- it's whether reality matched what the trust
model predicts, including the one attack expected to succeed under the default policy and the
one positive control (a genuine preference) expected to keep working under both. A harness that
only reported 0% everywhere, or that "fixed" the gap by breaking the legitimate workflow too,
would hide exactly what this exists to find.
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
    """Cap the `eval` channel at Agent trust. Exact string replacement, not a generic TOML
    writer: `tabularium init` always emits an empty `[policy.channels]` table verbatim (checked
    against the real output), so this is precise, not a guess at the file's shape.

    Capping at Tool was tried first and rejects every `remember()` over the channel outright,
    legitimate or not: `remember`'s channel check runs on the *recorder* default (always Agent --
    neither the CLI nor MCP exposes a trust override for remember), before evidence is even
    resolved. Agent is the surgical level: recorders at Agent-or-below still pass that gate, so
    plain facts and genuine evidence-backed preferences keep working, while `observe --trust
    user` on this channel (User > Agent) -- the actual spoofing vector -- is still rejected.
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
            "trust_override_spoof succeeds under the DEFAULT policy every fresh `tabularium "
            "init` ships (empty [policy.channels]): observe exposes a raw trust override not "
            "cross-checked against kind, so a tool-output observation can simply claim "
            "trust=user and get cited into an instruction -- a residual risk DESIGN.md 2.2 "
            "already names. Its literal suggested mitigation ('cap what mcp:* channels may "
            "assert') is a trap if applied at Tool level: remember()'s channel check runs on "
            "the recorder default (always Agent, before evidence is resolved), so capping below "
            "Agent rejects every remember() over that channel, breaking the system's own primary "
            "workflow -- turning a real user utterance into a preference -- along with the "
            "attack. Capping at Agent instead closes the gap with zero cost to the legitimate "
            "workflow: confirmed here by a positive control, not assumed."
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
