from __future__ import annotations

from src.live.policy import CachePolicy


def test_defaults_are_frozen_and_offline() -> None:
    p = CachePolicy.resolve({})
    assert p.mode == "frozen"
    assert p.may_fetch is False
    assert p.serve_stale is True
    assert p.ttl("kev") == 21600


def test_scenario_meta_overrides_mode_and_ttl() -> None:
    p = CachePolicy.resolve({"cache": {"mode": "live", "ttl": {"nvd": 60}}})
    assert p.mode == "live"
    assert p.may_fetch is True
    assert p.ttl("nvd") == 60
    assert p.ttl("osv") == 86400  # untouched


def test_unknown_mode_falls_back_to_frozen() -> None:
    assert CachePolicy.resolve({"cache": {"mode": "banana"}}).mode == "frozen"


def test_malformed_ttl_falls_back() -> None:
    p = CachePolicy.resolve({"cache": {"ttl": {"nvd": "not-an-int"}}})
    assert p.ttl("nvd") == 86400


def test_bypass_forces_fetch() -> None:
    p = CachePolicy.resolve({"cache": {"mode": "bypass"}})
    assert p.force_fetch is True
    assert p.may_fetch is True


def test_swr_serves_stale_and_may_fetch() -> None:
    p = CachePolicy.resolve({"cache": {"mode": "swr"}})
    assert p.serve_stale is True
    assert p.may_fetch is True
