"""Disk + in-memory cache of completed runs so a re-demo is instant."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from src.config import CACHE_DIR


def cache_path(scenario_id: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR / f"{scenario_id}.json"


def load_run(scenario_id: str) -> dict | None:
    path = cache_path(scenario_id)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def save_run(scenario_id: str, payload: dict) -> Path:
    path = cache_path(scenario_id)
    blob = {
        **payload,
        "cached_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "scenario_id": scenario_id,
    }
    path.write_text(json.dumps(blob, indent=2))
    return path
