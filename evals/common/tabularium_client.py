"""Thin subprocess wrapper over the `tabularium` CLI's --json output.

Every eval suite drives the real binary as a black box -- no direct SQLite access, no
knowledge of tabularium-core internals. If the CLI's JSON shape changes, this is the one
place that needs updating.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any, Optional


def binary() -> str:
    """Path to the `tabularium` binary. Override with TABULARIUM_BIN, e.g. to point at
    target/release/tabularium.exe instead of whatever is (or isn't) on PATH."""
    return os.environ.get("TABULARIUM_BIN", "tabularium")


class TabulariumError(RuntimeError):
    def __init__(self, args: list[str], returncode: int, stdout: str, stderr: str):
        self.args_ = args
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        message = (stderr or stdout).strip() or f"exit {returncode}"
        super().__init__(f"tabularium {' '.join(args)}: {message}")


def _check(proc: subprocess.CompletedProcess, cmd: list[str]) -> Any:
    if proc.returncode != 0:
        raise TabulariumError(cmd, proc.returncode, proc.stdout, proc.stderr)
    out = proc.stdout.strip()
    return json.loads(out) if out else None


class Vault:
    """One vault directory, driven entirely through the CLI's --json output."""

    def __init__(self, path: Path):
        self.path = Path(path)

    @classmethod
    def init(cls, path: Path, name: str = "eval", root: Optional[Path] = None) -> "Vault":
        """`root` fixes what relative check paths (file_hash/file_exists/symbol_in_file) resolve
        against -- without it, tabularium defaults to the CWD *at init time*, which for a script
        invoked from anywhere but that exact directory is not what you want. Must already exist."""
        path = Path(path)
        cmd = [binary(), "--vault", str(path), "--json", "init", "--name", name]
        if root is not None:
            cmd += ["--root", str(root)]
        proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=60)
        _check(proc, cmd)
        return cls(path)

    def _run(self, *args: str, timeout: int = 60) -> Any:
        cmd = [binary(), "--vault", str(self.path), "--json", *args]
        # encoding="utf-8", not text=True (which defaults to the system codepage, cp1251 on
        # this machine): tabularium's own JSON output, and any fact text an eval remembers,
        # can contain arbitrary Unicode the platform codepage can't represent.
        proc = subprocess.run(cmd, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout)
        return _check(proc, cmd)

    def observe(self, kind: str, content: str, trust: Optional[str] = None, channel: str = "eval") -> dict:
        args = ["observe", "--kind", kind, "--channel", channel]
        if trust:
            args += ["--trust", trust]
        return self._run(*args, content)

    def remember(
        self,
        kind: str,
        text: str,
        *,
        subject: Optional[str] = None,
        evidence: Optional[list[str]] = None,
        checks: Optional[list[dict]] = None,
        merge: Optional[list[str]] = None,
        channel: str = "eval",
    ) -> dict:
        args = ["remember", "--kind", kind, "--channel", channel]
        if subject:
            args += ["--subject", subject]
        for e in evidence or []:
            args += ["-e", e]
        for m in merge or []:
            args += ["--merge", m]
        for c in checks or []:
            if c["type"] == "file_hash":
                args += ["--check-file", c["path"]]
            elif c["type"] == "file_exists":
                args += ["--check-exists", c["path"]]
            elif c["type"] == "symbol_in_file":
                args += ["--check-symbol", f"{c['path']}::{c['symbol']}"]
            elif c["type"] == "ttl":
                args += ["--ttl", c["expires"]]
            else:
                raise ValueError(f"unknown check type: {c['type']}")
        return self._run(*args, text)

    def recall(self, query: str = "", budget: int = 800, limit: int = 20, verify: bool = True) -> dict:
        args = ["recall", query, "--budget", str(budget), "--limit", str(limit)]
        if not verify:
            args.append("--no-verify")
        return self._run(*args)

    def verify(self, memory_id: Optional[str] = None) -> list:
        args = ["verify"]
        if memory_id:
            args.append(memory_id)
        return self._run(*args)

    def forget(self, memory_id: str, reason: str = "") -> dict:
        return self._run("forget", memory_id, "--reason", reason)

    def audit(self) -> dict:
        return self._run("audit")

    def memories(self, all_: bool = False) -> list:
        args = ["memories"]
        if all_:
            args.append("--all")
        return self._run(*args)

    def compile(self, rebuild: bool = False) -> dict:
        args = ["compile"]
        if rebuild:
            args.append("--rebuild")
        return self._run(*args)

    def contradictions(self, threshold: Optional[float] = None) -> dict:
        args = ["contradictions"]
        if threshold is not None:
            args += ["--threshold", str(threshold)]
        return self._run(*args)

    def duplicates(self, threshold: Optional[float] = None) -> dict:
        args = ["duplicates"]
        if threshold is not None:
            args += ["--threshold", str(threshold)]
        return self._run(*args)
