from __future__ import annotations

import json
from pathlib import Path

_SCHEMA_PATH = Path(__file__).resolve().parent.parent / "docs" / "analysis-schema.json"


def load_schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def schema_json(indent: int = 2) -> str:
    return json.dumps(load_schema(), indent=indent, sort_keys=True)
