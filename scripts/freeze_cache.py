#!/usr/bin/env python3
"""Snapshot the live cache into the committed fixtures dir.

  python scripts/freeze_cache.py

Copies data/cache/live/ -> data/fixtures/live/ and writes a manifest so the
snapshot's age is visible. Run after warm_cache.py, before committing.
"""

from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.config import LIVE_CACHE_DIR, LIVE_FIXTURES_DIR  # noqa: E402


def main() -> int:
    if not LIVE_CACHE_DIR.exists():
        print(f"nothing to freeze — {LIVE_CACHE_DIR} does not exist. Run warm_cache.py first.")
        return 1

    LIVE_FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    manifest: list[dict] = []
    copied = 0
    for src_path in sorted(LIVE_CACHE_DIR.rglob("*.json")):
        rel = src_path.relative_to(LIVE_CACHE_DIR)
        dst = LIVE_FIXTURES_DIR / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_path, dst)
        copied += 1
        try:
            env = json.loads(src_path.read_text())
        except ValueError:
            env = {}
        manifest.append(
            {
                "path": str(rel),
                "source": env.get("source", ""),
                "key": env.get("key", ""),
                "status": env.get("status", ""),
                "fetched_at": env.get("fetched_at", ""),
            }
        )

    (LIVE_FIXTURES_DIR / "MANIFEST.json").write_text(
        json.dumps(
            {"frozen_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "entries": manifest},
            indent=2,
            sort_keys=True,
        )
    )
    print(f"froze {copied} file(s) into {LIVE_FIXTURES_DIR}")
    print("review data/fixtures/live/MANIFEST.json, then commit.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
