"""Follow-up asked directly: how much does RRF (the BM25+cosine fusion) degrade on a vault that
mixes Russian and English content, using the real local ONNX multilingual embedder (not the
deterministic HashEmbedder the unit tests use)?

Method: 10 topics recorded as English memories, 10 different topics recorded as Russian
memories -- one mixed 20-memory vault, not two separate ones, so cross-language retrieval has
real same-language decoys to be confused by. Each topic is queried twice: once in its own
language (same-language control) and once in the other language (the cross-language case the
project's own README claims -- "ask in Russian, find what was saved in English"). Top-1 accuracy
and mean reciprocal rank (MRR) quantify any gap between the two conditions directly, instead of
asserting the claim holds.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "common"))
from scratch_vault import scratch_vault  # noqa: E402

# (english statement, english query, russian statement, russian query) -- same topic, independent
# phrasing in each language (not machine-translated word-for-word, which would make BM25 token
# overlap do the cross-language work instead of the embedder).
TOPICS = [
    ("We deploy to production only from the release branch, never from main.",
     "which branch do we deploy from",
     "Мы разворачиваем прод только с ветки release, а не с main.",
     "с какой ветки мы деплоим"),
    ("The database backing the API is PostgreSQL, version 16.",
     "what database does the api use",
     "База данных под API — это PostgreSQL, версия 16.",
     "какую базу данных использует апи"),
    ("Code reviews require at least one approval before merging.",
     "how many approvals are needed to merge",
     "Для мержа нужен хотя бы один аппрув от ревьюера.",
     "сколько аппрувов нужно для мержа"),
    ("The on-call rotation changes every Monday morning.",
     "when does on-call rotate",
     "Дежурство меняется каждый понедельник утром.",
     "когда меняется дежурство"),
    ("Secrets are stored in the cloud key vault, never in the repository.",
     "where are secrets stored",
     "Секреты хранятся в облачном key vault, никогда в репозитории.",
     "где хранятся секреты"),
    ("The staging environment is refreshed from production data every night.",
     "how often is staging refreshed",
     "Стейджинг обновляется данными из прода каждую ночь.",
     "как часто обновляется стейджинг"),
    ("New employees get a laptop and VPN access on their first day.",
     "what does a new employee receive on day one",
     "Новые сотрудники получают ноутбук и доступ к VPN в первый день.",
     "что получает новый сотрудник в первый день"),
    ("The support team responds to tickets within four business hours.",
     "how fast does support respond to tickets",
     "Служба поддержки отвечает на тикеты в течение четырёх рабочих часов.",
     "как быстро поддержка отвечает на тикеты"),
    ("Feature flags are managed through the internal dashboard, not config files.",
     "how are feature flags managed",
     "Фича-флаги управляются через внутреннюю панель, а не через конфиги.",
     "как управляются фича-флаги"),
    ("The mobile app releases every two weeks on Wednesdays.",
     "how often does the mobile app release",
     "Мобильное приложение релизится каждые две недели по средам.",
     "как часто релизится мобильное приложение"),
]


def rank_of(recall_items: list[dict], target_id: str) -> "int | None":
    for i, item in enumerate(recall_items):
        if item["id"] == target_id:
            return i + 1
    return None


def run() -> dict:
    with scratch_vault("ru-en-rrf") as v:
        en_ids, ru_ids = [], []
        for en_text, _, ru_text, _ in TOPICS:
            en_ids.append(v.remember("fact", en_text)["id"])
            ru_ids.append(v.remember("fact", ru_text)["id"])

        model = None
        conditions = {"same_language": [], "cross_language": []}
        for i, (en_text, en_query, ru_text, ru_query) in enumerate(TOPICS):
            # Same-language controls.
            r = v.recall(en_query, budget=400)
            model = model or r.get("semantic_model")
            conditions["same_language"].append({"query": en_query, "lang": "en->en", "rank": rank_of(r["items"], en_ids[i])})
            r = v.recall(ru_query, budget=400)
            conditions["same_language"].append({"query": ru_query, "lang": "ru->ru", "rank": rank_of(r["items"], ru_ids[i])})

            # Cross-language: query in one language, target memory recorded in the other.
            r = v.recall(ru_query, budget=400)
            conditions["cross_language"].append({"query": ru_query, "lang": "ru->en", "rank": rank_of(r["items"], en_ids[i])})
            r = v.recall(en_query, budget=400)
            conditions["cross_language"].append({"query": en_query, "lang": "en->ru", "rank": rank_of(r["items"], ru_ids[i])})

        def summarize(entries: list[dict]) -> dict:
            n = len(entries)
            top1 = sum(1 for e in entries if e["rank"] == 1)
            found = [e for e in entries if e["rank"] is not None]
            mrr = sum(1.0 / e["rank"] for e in found) / n if n else 0.0
            return {"n": n, "top1_accuracy": top1 / n if n else None, "found_rate": len(found) / n if n else None, "mrr": mrr}

        same = summarize(conditions["same_language"])
        cross = summarize(conditions["cross_language"])
        return {
            "hypothesis": "cross-language recall quality (risk-point follow-up; relates to the README's own 'ask in Russian, find English' claim)",
            "semantic_model": model,
            "n_topics": len(TOPICS),
            "same_language": same,
            "cross_language": cross,
            "mrr_gap_same_minus_cross": same["mrr"] - cross["mrr"],
            "raw": conditions,
        }


if __name__ == "__main__":
    result = run()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    out = Path(__file__).resolve().parent.parent / "results" / "ru_en_rrf.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
