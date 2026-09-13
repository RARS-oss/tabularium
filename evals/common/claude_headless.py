"""Wrapper over `claude -p` for headless, non-interactive LLM calls -- the harness's only
source of "LLM in the loop" (extraction/answering/judging). Reuses this machine's already
authenticated Claude Code login instead of a separate OpenAI/Anthropic API key: verified in
this environment (`claude --version` / `claude -p "..."`) before this harness was built.

The prompt goes over stdin, not argv -- haystack sessions in H3 can be tens of thousands of
tokens, well past what a single command-line argument can safely carry on Windows.
"""

from __future__ import annotations

import subprocess
from typing import Optional


class ClaudeError(RuntimeError):
    pass


def ask(prompt: str, timeout: int = 180, retries: int = 1) -> str:
    """Run one headless `claude -p` call over stdin and return its stdout, stripped.
    Retries once (by default) on a nonzero exit or timeout before raising."""
    last_err: Optional[BaseException] = None
    for _ in range(retries + 1):
        try:
            proc = subprocess.run(
                ["claude", "-p"],
                input=prompt,
                capture_output=True,
                encoding="utf-8",  # not text=True: that defaults to the system codepage
                # (cp1251 on this machine), which can't encode arbitrary conversation
                # text (LoCoMo's transcripts contain emoji) -- verified by a real crash.
                errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as e:
            last_err = e
            continue
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
        last_err = ClaudeError(f"claude -p exited {proc.returncode}: {(proc.stderr or proc.stdout).strip()[:500]}")
    assert last_err is not None
    raise last_err
