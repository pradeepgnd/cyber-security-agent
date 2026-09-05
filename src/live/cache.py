"""JSON file cache for live-source responses.

Two things live under `data/cache/live/`:

  <source>/<key>.json   — one raw-response envelope per (source, cache key)
  index/<citation>.json — one resolved LiveRecord per citeable id, written by
                          `enrich` so `--check` / the UI can render a citation

`data/fixtures/live/` mirrors this layout as a committed, read-only snapshot: it
is the fallback on a cold cache and the *only* data source in `frozen` mode.

Response envelope:
    {
      "source": "nvd",
      "key": "CVE-2021-44228",
      "fetched_at": "2026-09-05T12:00:00Z",
      "ttl_seconds": 86400,
      "status": "ok",            # ok | not_found | error
      "payload": <any>
    }
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config import LIVE_CACHE_DIR, LIVE_FIXTURES_DIR

_SAFE_KEY_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return _utc_now().isoformat(timespec="seconds")


def _safe_key(key: str) -> str:
    if _SAFE_KEY_RE.match(key):
        return key
    return hashlib.sha1(key.encode("utf-8")).hexdigest()


def _rel_path(source: str, key: str) -> Path:
    return Path(source) / f"{_safe_key(key)}.json"


@dataclass
class CacheEntry:
    source: str
    key: str
    status: str
    payload: Any
    fetched_at: str
    ttl_seconds: int
    fresh: bool
    origin: str  # "cache" | "fixture"


def _age_ok(fetched_at: str, ttl_seconds: int) -> bool:
    if not fetched_at:
        return False
    try:
        ts = datetime.fromisoformat(fetched_at)
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (_utc_now() - ts).total_seconds() < max(0, ttl_seconds)


def _load_file(path: Path, ttl_seconds: int, origin: str) -> CacheEntry | None:
    try:
        raw = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    fetched_at = str(raw.get("fetched_at") or "")
    return CacheEntry(
        source=str(raw.get("source") or ""),
        key=str(raw.get("key") or ""),
        status=str(raw.get("status") or "ok"),
        payload=raw.get("payload"),
        fetched_at=fetched_at,
        ttl_seconds=int(raw.get("ttl_seconds") or ttl_seconds),
        fresh=_age_ok(fetched_at, ttl_seconds),
        origin=origin,
    )


def _atomic_write(path: Path, obj: Any) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(obj, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path


def read(source: str, key: str, ttl_seconds: int) -> CacheEntry | None:
    """Cached envelope from the live cache, else the committed fixture.

    `None` is a hard miss. A returned entry may be stale (`entry.fresh is
    False`) — the caller decides per cache mode.
    """
    rel = _rel_path(source, key)
    live_path = LIVE_CACHE_DIR / rel
    if live_path.exists():
        entry = _load_file(live_path, ttl_seconds, "cache")
        if entry is not None:
            return entry
    fixture_path = LIVE_FIXTURES_DIR / rel
    if fixture_path.exists():
        return _load_file(fixture_path, ttl_seconds, "fixture")
    return None


def write(
    source: str,
    key: str,
    payload: Any,
    *,
    status: str = "ok",
    ttl_seconds: int,
) -> Path:
    """Atomically write a response envelope to the live cache."""
    return _atomic_write(
        LIVE_CACHE_DIR / _rel_path(source, key),
        {
            "source": source,
            "key": key,
            "fetched_at": iso_now(),
            "ttl_seconds": int(ttl_seconds),
            "status": status,
            "payload": payload,
        },
    )


def write_index(citation_id: str, record: dict) -> Path:
    """Store a resolved record so a citation id can be rendered later."""
    return _atomic_write(LIVE_CACHE_DIR / _rel_path("index", citation_id), record)


def load_live_record(citation_id: str) -> dict | None:
    """Return the stored record dict for a live citation id, or None."""
    rel = _rel_path("index", citation_id)
    for base in (LIVE_CACHE_DIR, LIVE_FIXTURES_DIR):
        path = base / rel
        if not path.exists():
            continue
        try:
            return json.loads(path.read_text())
        except (OSError, ValueError):
            continue
    return None


def resolve_live(citation_id: str) -> str | None:
    """Render a live citation id to text, or None if unknown."""
    rec = load_live_record(citation_id)
    if not rec:
        return None
    summary = rec.get("summary") or rec.get("title")
    if not summary:
        return None
    prov = (
        f"(source: {rec.get('source', '?')}, "
        f"fetched {rec.get('fetched_at') or 'unknown'})"
    )
    return f"{summary}\n{prov}"
