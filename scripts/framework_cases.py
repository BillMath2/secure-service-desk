"""Load versioned model case metadata without changing historical reports."""

import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def load_model_cases(filename: str) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = json.loads((ROOT / "config" / filename).read_text())
    return cases


def case_fingerprint(filename: str) -> str:
    return hashlib.sha256((ROOT / "config" / filename).read_bytes()).hexdigest()
