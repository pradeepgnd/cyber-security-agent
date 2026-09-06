from __future__ import annotations

from src.live.sources import epss, nvd, osv
from src.live.sources.base import Seeds, cached_fetch
from src.live.http import LiveHTTPError, LiveNotFound
import pytest
from src.live.policy import CachePolicy
from src.tools.depscan import Package

NVD_RAW = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2023-11-07T03:39:22.567",
                "descriptions": [
                    {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."},
                    {"lang": "es", "value": "..."},
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                    ]
                },
                "weaknesses": [{"description": [{"value": "CWE-502"}, {"value": "CWE-400"}]}],
                "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}],
            }
        }
    ]
}


def test_nvd_parse_pulls_cvss_cwe_summary() -> None:
    rec = nvd._parse("CVE-2021-44228", NVD_RAW)
    assert rec["id"] == "nvd:CVE-2021-44228"
    assert rec["severity"] == "critical"
    assert rec["data"]["cvss_score"] == 10.0
    assert "CWE-502" in rec["data"]["cwes"]
    assert "Log4j2" in rec["summary"]
    assert rec["url"].endswith("CVE-2021-44228")


def test_nvd_parse_empty_is_none() -> None:
    assert nvd._parse("CVE-9999-0", {"vulnerabilities": []}) is None


def test_osv_vuln_to_record_extracts_alias_and_refs() -> None:
    v = {
        "id": "GHSA-jfh8-c2jp-5v3q",
        "summary": "Remote code execution in Log4j",
        "details": "Long details here.",
        "aliases": ["CVE-2021-44228"],
        "references": [{"url": "https://example/advisory"}],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}],
        "affected": [{"package": {"name": "org.apache.logging.log4j:log4j-core"}, "ranges": []}],
    }
    rec = osv._vuln_to_record(v)
    assert rec["id"] == "osv:GHSA-jfh8-c2jp-5v3q"
    assert rec["cve_id"] == "CVE-2021-44228"
    assert rec["refs"] == ["https://example/advisory"]
    assert "CVSS:3.1" in rec["severity"]


def test_osv_ecosystem_mapping() -> None:
    maven = Package(name="log4j-core", version="2.14.1", source="x", extras=["org.apache.logging.log4j:log4j-core", "log4j-core"])
    pypi = Package(name="commons-text", version="1.9", source="x", extras=["commons-text"])
    assert osv._ecosystem_target(maven) == ("Maven", "org.apache.logging.log4j:log4j-core")
    assert osv._ecosystem_target(pypi) == ("PyPI", "commons-text")


def test_epss_record_shape() -> None:
    rec = epss._record("CVE-2021-44228", 0.97565, 0.99999)
    assert rec["id"] == "epss:CVE-2021-44228"
    assert rec["data"]["epss"] == 0.97565
    assert rec["kind"] == "score"


def test_cached_fetch_frozen_skips_network_on_miss() -> None:
    policy = CachePolicy.resolve({"cache": {"mode": "frozen"}})

    def _boom():
        raise AssertionError("must not fetch in frozen mode")

    got = cached_fetch("nvd", "CVE-X", policy, _boom)
    assert got.status == "skipped"
    assert got.payload is None


def test_cached_fetch_live_writes_and_returns() -> None:
    policy = CachePolicy.resolve({"cache": {"mode": "live"}})
    got = cached_fetch("nvd", "CVE-Y", policy, lambda: {"id": "nvd:CVE-Y", "summary": "s"})
    assert got.status == "ok"
    assert got.origin == "network"
    # second call served from fresh cache, no fetch
    again = cached_fetch("nvd", "CVE-Y", policy, lambda: (_ for _ in ()).throw(AssertionError("no refetch")))
    assert again.payload["id"] == "nvd:CVE-Y"


def test_cached_fetch_error_negative_caches() -> None:
    policy = CachePolicy.resolve({"cache": {"mode": "live"}})

    def _fail():
        raise LiveHTTPError("boom")

    got = cached_fetch("nvd", "CVE-Z", policy, _fail)
    assert got.status == "error"
    from src.live import cache

    entry = cache.read("nvd", "CVE-Z", 3600)
    assert entry.status == "error"


class _Resp:
    def __init__(self, status: int, *, headers=None, text="", json_data=None):
        self.status_code = status
        self.headers = headers or {}
        self.text = text
        self._json = json_data

    def json(self):
        if self._json is None:
            raise ValueError("no json")
        return self._json


def test_422_raises_immediately_without_retry(monkeypatch) -> None:
    monkeypatch.setattr("src.live.http.time.sleep", lambda *_a, **_k: None)
    calls = {"n": 0}

    def req(*_a, **_k):
        calls["n"] += 1
        return _Resp(422, text='{"message":"Validation Failed","errors":[{"code":"already_exists"}]}')

    monkeypatch.setattr("src.live.http.requests.request", req)
    from src.live.http import request_json

    with pytest.raises(LiveHTTPError) as ei:
        request_json("github", "POST", "https://example.invalid/labels")
    assert ei.value.status_code == 422
    assert calls["n"] == 1


def test_403_with_retry_after_retries(monkeypatch) -> None:
    monkeypatch.setattr("src.live.http.time.sleep", lambda *_a, **_k: None)
    calls = {"n": 0}

    def req(*_a, **_k):
        calls["n"] += 1
        if calls["n"] == 1:
            return _Resp(403, headers={"Retry-After": "0"}, text="rate")
        return _Resp(200, json_data={"ok": True}, text="{}")

    monkeypatch.setattr("src.live.http.requests.request", req)
    from src.live.http import request_json

    assert request_json("github", "GET", "https://example.invalid/x") == {"ok": True}
    assert calls["n"] == 2


def test_403_without_rate_limit_raises_immediately(monkeypatch) -> None:
    monkeypatch.setattr("src.live.http.time.sleep", lambda *_a, **_k: None)
    calls = {"n": 0}

    def req(*_a, **_k):
        calls["n"] += 1
        return _Resp(403, text="bad credentials / missing scope")

    monkeypatch.setattr("src.live.http.requests.request", req)
    from src.live.http import request_json

    with pytest.raises(LiveHTTPError) as ei:
        request_json("github", "GET", "https://example.invalid/x")
    assert ei.value.status_code == 403
    assert calls["n"] == 1


def test_204_allow_empty_returns_dict(monkeypatch) -> None:
    monkeypatch.setattr("src.live.http.time.sleep", lambda *_a, **_k: None)

    def req(*_a, **_k):
        return _Resp(204, text="")

    monkeypatch.setattr("src.live.http.requests.request", req)
    from src.live.http import request_json

    assert request_json("github", "DELETE", "https://example.invalid/x", allow_empty=True) == {}

