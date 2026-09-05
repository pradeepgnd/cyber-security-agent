"""Shared fixtures.

- Redirects the live-enrichment cache to a tmp dir so tests never touch the
  repo's data/cache or data/fixtures trees.
- Blocks real HTTP from the live sources; a test that wants source behavior
  monkeypatches that source's `_fetch*` helper.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _isolate_live_cache(tmp_path, monkeypatch):
    from src.live import cache

    cache_dir = tmp_path / "cache" / "live"
    fixtures_dir = tmp_path / "fixtures" / "live"
    cache_dir.mkdir(parents=True)
    fixtures_dir.mkdir(parents=True)
    monkeypatch.setattr(cache, "LIVE_CACHE_DIR", cache_dir, raising=False)
    monkeypatch.setattr(cache, "LIVE_FIXTURES_DIR", fixtures_dir, raising=False)
    return cache_dir, fixtures_dir


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    def _no_network(*_args, **_kwargs):
        raise AssertionError(
            "live source attempted a real HTTP call — monkeypatch its _fetch* helper"
        )

    try:
        monkeypatch.setattr("src.live.http.requests.request", _no_network)
    except (ImportError, AttributeError):
        pass
