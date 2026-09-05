from __future__ import annotations

import json

from src.live import cache


def test_write_then_read_fresh() -> None:
    cache.write("nvd", "CVE-2021-44228", {"id": "nvd:CVE-2021-44228", "summary": "x"}, ttl_seconds=3600)
    entry = cache.read("nvd", "CVE-2021-44228", 3600)
    assert entry is not None
    assert entry.fresh is True
    assert entry.status == "ok"
    assert entry.origin == "cache"
    assert entry.payload["id"] == "nvd:CVE-2021-44228"


def test_read_is_stale_when_ttl_exceeded() -> None:
    cache.write("nvd", "CVE-1", {"summary": "x"}, ttl_seconds=3600)
    entry = cache.read("nvd", "CVE-1", ttl_seconds=0)
    assert entry is not None
    assert entry.fresh is False


def test_hard_miss_returns_none() -> None:
    assert cache.read("nvd", "CVE-DOES-NOT-EXIST", 3600) is None


def test_negative_cache_envelope() -> None:
    cache.write("nvd", "CVE-2", None, status="not_found", ttl_seconds=900)
    entry = cache.read("nvd", "CVE-2", 900)
    assert entry.status == "not_found"
    assert entry.payload is None


def test_fixture_fallback(_isolate_live_cache) -> None:
    _, fixtures_dir = _isolate_live_cache
    path = fixtures_dir / "kev" / "catalog.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "source": "kev",
                "key": "catalog",
                "fetched_at": "2020-01-01T00:00:00+00:00",
                "ttl_seconds": 3600,
                "status": "ok",
                "payload": {"index": {"CVE-2021-44228": {}}},
            }
        )
    )
    entry = cache.read("kev", "catalog", 3600)
    assert entry is not None
    assert entry.origin == "fixture"
    assert entry.fresh is False  # old fixture
    assert "CVE-2021-44228" in entry.payload["index"]


def test_atomic_write_leaves_no_tmp_files(_isolate_live_cache) -> None:
    cache_dir, _ = _isolate_live_cache
    cache.write("epss", "CVE-3", {"epss": 0.9}, ttl_seconds=10)
    leftovers = list((cache_dir / "epss").glob(".tmp-*"))
    assert leftovers == []


def test_index_and_resolve_live() -> None:
    cache.write_index(
        "nvd:CVE-2021-44228",
        {"id": "nvd:CVE-2021-44228", "source": "nvd", "summary": "Log4Shell RCE", "fetched_at": "2026-01-01T00:00:00+00:00"},
    )
    text = cache.resolve_live("nvd:CVE-2021-44228")
    assert text and "Log4Shell RCE" in text
    assert "source: nvd" in text
    assert cache.resolve_live("nvd:CVE-0000-0000") is None
    assert cache.resolve_live("not-a-live-id") is None


def test_load_live_record_returns_dict() -> None:
    cache.write_index(
        "epss:CVE-2021-44228",
        {"id": "epss:CVE-2021-44228", "source": "epss", "data": {"epss": 0.975, "percentile": 0.999}},
    )
    rec = cache.load_live_record("epss:CVE-2021-44228")
    assert rec["source"] == "epss"
    assert rec["data"]["epss"] == 0.975
    assert cache.load_live_record("epss:CVE-0000-0000") is None
