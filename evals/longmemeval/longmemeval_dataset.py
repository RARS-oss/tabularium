"""Download and cache LongMemEval-s (xiaowu0162/longmemeval-cleaned on HuggingFace, ICLR 2025,
MIT license). The redirect chain (HF -> signed CDN URL) was verified live with curl before
writing this; the actual download+parse has NOT been run in this session -- the file is
~277MB and each of its 500 instances spans up to ~40 chat sessions, so a real pilot here would
mean many times more claude_headless calls than locomo/run.py's single-conversation pilot.
Building this without running it, and saying so, beats claiming a result that was never
produced. See evals/README.md for the documented follow-up.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

URL = "https://huggingface.co/datasets/xiaowu0162/longmemeval-cleaned/resolve/main/longmemeval_s_cleaned.json"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load(force: bool = False) -> list[dict]:
    """Each instance: question_id, question_type, question, answer, question_date,
    haystack_session_ids, haystack_dates, haystack_sessions (list of {role, content} turns per
    session), answer_session_ids. Confirmed against the dataset's own documentation, not
    guessed."""
    path = DATA_DIR / "longmemeval_s_cleaned.json"
    if force or not path.exists():
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(URL, path)  # noqa: S310 -- fixed HF dataset URL, ~277MB
    return json.loads(path.read_text(encoding="utf-8"))


def session_transcript(session_turns: list[dict]) -> str:
    return "\n".join(f"{turn.get('role', turn.get('speaker', '?'))}: {turn.get('content', turn.get('text', ''))}" for turn in session_turns)
