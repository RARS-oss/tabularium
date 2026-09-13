"""Download and cache the LoCoMo dataset (snap-research/locomo, ACL 2024; 10 conversations,
QA pairs with category labels). Named to avoid any ambiguity with the unrelated HuggingFace
`datasets` PyPI package.
"""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path

URL = "https://raw.githubusercontent.com/snap-research/locomo/main/data/locomo10.json"
DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def load(force: bool = False) -> list[dict]:
    path = DATA_DIR / "locomo10.json"
    if force or not path.exists():
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        urllib.request.urlretrieve(URL, path)  # noqa: S310 -- fixed, known-good HTTPS URL
    return json.loads(path.read_text(encoding="utf-8"))
