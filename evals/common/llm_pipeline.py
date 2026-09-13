"""The three LLM-shaped steps H3 needs -- extraction, answering, judging -- all via
claude_headless. This is deliberately outside tabularium-core: the engine never runs a model:
"the host agent does the thinking." Here, the harness *is* the host.
"""

from __future__ import annotations

import json
import re

from claude_headless import ask

EXTRACT_PROMPT = """You are extracting durable, self-contained facts from a conversation transcript, \
for a memory system that will need to answer questions about it later using only these facts \
(not the original transcript).

Extract every fact a careful listener would want to remember: names, dates, relationships, \
preferences, events, plans. Each fact must stand alone -- readable and unambiguous without the \
surrounding conversation (resolve pronouns to names, keep dates/times as stated).

Return ONLY a JSON array of strings, nothing else. No markdown fences, no commentary.

Transcript:
---
{transcript}
---
"""

ANSWER_PROMPT = """Answer the question using ONLY the facts listed below. If the facts don't contain \
enough information to answer, say "I don't know" -- do not guess or use outside knowledge.

Facts:
{facts}

Question: {question}

Answer in one short sentence.
"""

JUDGE_PROMPT = """You are grading whether a predicted answer matches a gold answer for a \
question-answering benchmark. Minor phrasing differences are fine; the *content* must match \
(same date, same name, same fact). "I don't know" or a clearly wrong answer is INCORRECT.

Question: {question}
Gold answer: {gold}
Predicted answer: {predicted}

Reply with exactly one word: CORRECT or INCORRECT.
"""


def _extract_json_array(text: str) -> list[str]:
    # Claude sometimes wraps JSON in a fence despite instructions; strip it defensively.
    match = re.search(r"\[.*\]", text, re.DOTALL)
    if not match:
        raise ValueError(f"no JSON array found in extraction output: {text[:200]!r}")
    parsed = json.loads(match.group(0))
    return [str(item) for item in parsed]


def extract_facts(transcript: str, timeout: int = 300) -> list[str]:
    reply = ask(EXTRACT_PROMPT.format(transcript=transcript), timeout=timeout)
    return _extract_json_array(reply)


def answer_question(question: str, facts: list[str], timeout: int = 120) -> str:
    facts_block = "\n".join(f"- {f}" for f in facts) if facts else "(none recalled)"
    return ask(ANSWER_PROMPT.format(facts=facts_block, question=question), timeout=timeout)


def judge_answer(question: str, gold: object, predicted: str, timeout: int = 60) -> bool:
    reply = ask(JUDGE_PROMPT.format(question=question, gold=gold, predicted=predicted), timeout=timeout)
    return reply.strip().upper().startswith("CORRECT")
