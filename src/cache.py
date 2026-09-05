"""Disk + in-memory cache of completed runs so a re-demo is instant."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from src.config import CACHE_DIR

_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def _safe_key(key: str) -> str:
    if _SAFE_KEY_RE.match(key):
        return key
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def cache_path(scenario_id: str) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    root = CACHE_DIR.resolve()
    path = (CACHE_DIR / f"{_safe_key(scenario_id)}.json").resolve()
    if path.parent != root:
        path = (CACHE_DIR / f"{hashlib.sha1(scenario_id.encode('utf-8')).hexdigest()}.json").resolve()
    return path


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
