from __future__ import annotations

import pytest

from src.live import cache
from src.live.enrich import enrich
from src.live.sources import kev, nvd
from src.tools.depscan import Package


def _pkg(name, version, *extras):
    return Package(name=name, version=version, source="x", extras=list(extras) or [name])


def test_frozen_no_cache_is_graceful() -> None:
    res = enrich(cve_ids=["CVE-2021-44228"], scenario_meta={"cache": {"mode": "frozen"}})
    assert res.records == []
    assert res.mode == "frozen"
    assert any("frozen" in line for line in res.trace)


def test_no_seeds_short_circuits() -> None:
    res = enrich(cve_ids=[], packages=[], scenario_meta={})
    assert res.records == []
    assert "no CVE ids or packages" in res.trace[0]


def test_live_merges_sources_and_writes_index(monkeypatch) -> None:
    def fake_nvd(cve_id, raw=None):
        return {
            "id": f"nvd:{cve_id}",
            "source": "nvd",
            "kind": "cve",
            "cve_id": cve_id,
            "title": f"{cve_id} — NVD",
            "summary": "test summary",
            "url": "http://x",
            "severity": "critical",
            "refs": [],
            "data": {},
        }

    monkeypatch.setattr(nvd, "_fetch", fake_nvd)
    monkeypatch.setattr(
        kev,
        "_fetch_catalog",
        lambda: {"count": 1, "index": {"CVE-2021-44228": {"name": "Log4Shell", "date_added": "2021-12-10"}}},
    )
    # OSV / EPSS: force network errors so they degrade without a real HTTP call
    from src.live.http import LiveHTTPError
    from src.live.sources import epss, osv

    monkeypatch.setattr(osv, "_fetch_by_cve", lambda c: (_ for _ in ()).throw(LiveHTTPError("x")))
    monkeypatch.setattr(osv, "_fetch_by_package", lambda e, n, v: (_ for _ in ()).throw(LiveHTTPError("x")))
    monkeypatch.setattr(epss, "_fetch_batch", lambda ids: {})

    res = enrich(
        cve_ids=["CVE-2021-44228"],
        packages=[_pkg("log4j-core", "2.14.1", "org.apache.logging.log4j:log4j-core", "log4j-core")],
        scenario_meta={"cache": {"mode": "live"}},
    )
    ids = res.allowed_ids
    assert "nvd:CVE-2021-44228" in ids
    assert "kev:CVE-2021-44228" in ids
    # index written so the citation resolves later
    assert cache.resolve_live("nvd:CVE-2021-44228") is not None
    assert cache.resolve_live("kev:CVE-2021-44228") is not None


def test_one_bad_source_does_not_stop_the_rest(monkeypatch) -> None:
    monkeypatch.setattr(nvd, "_fetch", lambda c, raw=None: {"id": f"nvd:{c}", "source": "nvd", "cve_id": c, "title": "t", "summary": "s", "severity": "high"})

    def _explode(*a, **k):
        raise RuntimeError("kev is down")

    monkeypatch.setattr(kev, "collect", _explode)

    res = enrich(cve_ids=["CVE-2021-44228"], scenario_meta={"cache": {"mode": "live"}})
    assert "nvd:CVE-2021-44228" in res.allowed_ids
    assert any("kev: error" in line for line in res.trace)


def test_cve_seed_cap(monkeypatch) -> None:
    seen = []
    monkeypatch.setattr(
        nvd,
        "_fetch",
        lambda c, raw=None: seen.append(c) or {"id": f"nvd:{c}", "source": "nvd", "cve_id": c, "title": "t", "summary": "s", "severity": "low"},
    )
    monkeypatch.setattr(kev, "_fetch_catalog", lambda: {"index": {}})
    from src.live.sources import epss, osv

    monkeypatch.setattr(epss, "_fetch_batch", lambda ids: {})
    monkeypatch.setattr(osv, "_fetch_by_cve", lambda c: [])

    many = [f"CVE-2021-{i:04d}" for i in range(50)]
    enrich(cve_ids=many, scenario_meta={"cache": {"mode": "live"}})
    from src.config import LIVE_MAX_CVES_PER_RUN

    assert len(seen) <= LIVE_MAX_CVES_PER_RUN


def test_records_capped_per_agent(monkeypatch) -> None:
    import src.live.enrich as enrich_mod
    from src.live.sources import epss, kev, osv

    monkeypatch.setattr(enrich_mod, "LIVE_MAX_RECORDS_PER_AGENT", 3)
    monkeypatch.setattr(
        nvd,
        "_fetch",
        lambda c, raw=None: {
            "id": f"nvd:{c}",
            "source": "nvd",
            "cve_id": c,
            "title": "t",
            "summary": "s",
            # give CVE-2021-0009 the top CVSS so it must survive the cap
            "severity": "critical" if c.endswith("0003") else "low",
            "data": {"cvss_score": 9.9 if c.endswith("0003") else 1.0},
        },
    )
    monkeypatch.setattr(kev, "_fetch_catalog", lambda: {"index": {}})
    monkeypatch.setattr(epss, "_fetch_batch", lambda ids: {})
    monkeypatch.setattr(osv, "_fetch_by_cve", lambda c: [])

    res = enrich(
        cve_ids=[f"CVE-2021-{i:04d}" for i in range(8)],
        scenario_meta={"cache": {"mode": "live"}},
    )
    assert len(res.records) == 3
    assert "nvd:CVE-2021-0003" in res.allowed_ids  # highest CVSS kept
    assert any("capped" in line for line in res.trace)
