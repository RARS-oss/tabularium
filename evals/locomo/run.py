"""H3 (LoCoMo half) -- pilot-scale parity: extract facts from a real long conversation into a
scratch vault, answer real questions using only what `recall` returns, judge against gold
answers. Pilot, not the full 10-conversation set (~199 questions each) -- see evals/README.md
for the scope decision and how to scale up (just raise the two arguments to run()).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from scratch_vault import scratch_vault  # noqa: E402
from llm_pipeline import answer_question, extract_facts, judge_answer  # noqa: E402
from locomo_dataset import load as load_locomo  # noqa: E402


def conversation_transcript(conv: dict) -> str:
    session_keys = sorted(
        (k for k in conv if k.startswith("session_") and not k.endswith("_date_time")),
        key=lambda k: int(k.split("_")[1]),
    )
    parts = []
    for key in session_keys:
        date = conv.get(f"{key}_date_time", "")
        parts.append(f"--- {key} ({date}) ---")
        for turn in conv[key]:
            parts.append(f"{turn['speaker']}: {turn['text']}")
    return "\n".join(parts)


def run(n_conversations: int = 1, n_questions_per_conv: int = 10) -> dict:
    data = load_locomo()
    conv_results = []
    for sample in data[:n_conversations]:
        transcript = conversation_transcript(sample["conversation"])
        facts = extract_facts(transcript)
        with scratch_vault("locomo") as v:
            for f in facts:
                v.remember("fact", f)

            per_question = []
            for qa in sample["qa"][:n_questions_per_conv]:
                recalled = v.recall(qa["question"], budget=600)
                recalled_texts = [item["text"] for item in recalled["items"]]
                predicted = answer_question(qa["question"], recalled_texts)
                correct = judge_answer(qa["question"], qa["answer"], predicted)
                per_question.append(
                    {
                        "question": qa["question"],
                        "gold": qa["answer"],
                        "predicted": predicted,
                        "correct": correct,
                        "category": qa.get("category"),
                        "n_recalled": len(recalled_texts),
                    }
                )

            n_correct = sum(1 for q in per_question if q["correct"])
            conv_results.append(
                {
                    "sample_id": sample["sample_id"],
                    "n_facts_extracted": len(facts),
                    "n_questions": len(per_question),
                    "n_correct": n_correct,
                    "accuracy": n_correct / len(per_question) if per_question else None,
                    "questions": per_question,
                }
            )

    total_q = sum(c["n_questions"] for c in conv_results)
    total_correct = sum(c["n_correct"] for c in conv_results)
    return {
        "hypothesis": "H3-locomo",
        "pilot": True,
        "n_conversations": len(conv_results),
        "n_questions_total": total_q,
        "n_correct_total": total_correct,
        "accuracy": total_correct / total_q if total_q else None,
        "conversations": conv_results,
    }


if __name__ == "__main__":
    n_conv = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    n_q = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    result = run(n_conversations=n_conv, n_questions_per_conv=n_q)
    print(json.dumps(result, indent=2))
    out = Path(__file__).resolve().parent.parent / "results" / "locomo.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
