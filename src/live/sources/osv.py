"""OSV.dev — package+version → advisories, and CVE-id → advisory.

Emits `osv:<vuln id>` records (usually GHSA). These are real advisory documents,
so they stay separate from the merged NVD/KEV/EPSS view.
"""

from __future__ import annotations

from src.config import LIVE_SOURCE_URLS
from src.live.http import LiveNotFound, request_json
from src.live.models import LiveRecord
from src.live.policy import CachePolicy
from src.live.sources.base import Seeds, cached_fetch, norm_cve
from src.tools.depscan import Package

_BASE = LIVE_SOURCE_URLS["osv"].rstrip("/")
_QUERY_URL = f"{_BASE}/v1/query"


def _ecosystem_target(pkg: Package) -> tuple[str, str] | None:
    """(ecosystem, name) for OSV, or None if we can't map it confidently."""
    maven = next((e for e in pkg.extras if ":" in e and "." in e.split(":")[0]), None)
    if maven:
        return "Maven", maven
    if pkg.name and pkg.name.replace("-", "").replace("_", "").replace(".", "").isalnum():
        return "PyPI", pkg.name
    return None


def _vuln_to_record(v: dict) -> dict | None:
    vid = v.get("id")
    if not vid:
        return None
    aliases = [str(a) for a in v.get("aliases") or []]
    cve = next((a for a in aliases if a.upper().startswith("CVE-")), "")
    summary = v.get("summary") or ""
    details = v.get("details") or ""
    body = summary if summary else details[:600]
    if summary and details:
        body = f"{summary}\n{details[:400]}"
    refs = [r.get("url", "") for r in v.get("references") or [] if r.get("url")]
    severity = ""
    for s in v.get("severity") or []:
        if s.get("type") == "CVSS_V3":
            severity = str(s.get("score", ""))
    return {
        "id": f"osv:{vid}",
        "source": "osv",
        "kind": "advisory",
        "cve_id": norm_cve(cve) if cve else "",
        "title": f"{vid} — OSV advisory",
        "summary": body,
        "url": f"https://osv.dev/vulnerability/{vid}",
        "severity": severity,
        "refs": refs[:8],
        "data": {
            "aliases": aliases,
            "affected": [
                {
                    "package": (a.get("package") or {}).get("name", ""),
                    "ranges": a.get("ranges") or [],
                }
                for a in v.get("affected") or []
            ],
        },
    }


def _fetch_by_package(ecosystem: str, name: str, version: str) -> list[dict]:
    raw = request_json(
        "osv",
        "POST",
        _QUERY_URL,
        json_body={"package": {"ecosystem": ecosystem, "name": name}, "version": version},
    )
    recs = [_vuln_to_record(v) for v in (raw or {}).get("vulns") or []]
    return [r for r in recs if r]


def _fetch_by_cve(cve_id: str) -> list[dict]:
    raw = request_json("osv", "POST", _QUERY_URL, json_body={"id": cve_id})
    vulns = (raw or {}).get("vulns")
    if vulns is None:
        raw2 = request_json("osv", "GET", f"{_BASE}/v1/vulns/{cve_id}")
        vulns = [raw2] if raw2 and raw2.get("id") else []
    recs = [_vuln_to_record(v) for v in vulns or []]
    recs = [r for r in recs if r]
    if not recs:
        raise LiveNotFound(f"osv: nothing for {cve_id}")
    return recs


def collect(seeds: Seeds, policy: CachePolicy) -> list[LiveRecord]:
    out: dict[str, LiveRecord] = {}

    for pkg in seeds.packages:
        target = _ecosystem_target(pkg)
        if not target:
            continue
        ecosystem, name = target
        key = f"{ecosystem}:{name}@{pkg.version}"
        got = cached_fetch(
            "osv",
            key,
            policy,
            lambda e=ecosystem, n=name, v=pkg.version: _fetch_by_package(e, n, v),
        )
        for rec in got.payload or []:
            if isinstance(rec, dict) and rec.get("id"):
                out[rec["id"]] = LiveRecord.model_validate(rec)

    for cve in dict.fromkeys(norm_cve(c) for c in seeds.cve_ids):
        if not cve.startswith("CVE-"):
            continue
        got = cached_fetch("osv", cve, policy, lambda c=cve: _fetch_by_cve(c))
        for rec in got.payload or []:
            if isinstance(rec, dict) and rec.get("id"):
                out[rec["id"]] = LiveRecord.model_validate(rec)

    return list(out.values())
