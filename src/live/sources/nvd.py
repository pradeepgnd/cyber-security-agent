"""NVD 2.0 — CVE detail, CVSS, CWE, references. One `nvd:CVE-…` record per id.

The cache stores the *parsed* record, not the raw NVD envelope (which is large).
"""

from __future__ import annotations

from src.config import LIVE_SOURCE_URLS, NVD_API_KEY
from src.live.http import LiveNotFound, request_json
from src.live.models import LiveRecord
from src.live.policy import CachePolicy
from src.live.sources.base import Seeds, cached_fetch, norm_cve

_URL = LIVE_SOURCE_URLS["nvd"]


def _parse(cve_id: str, payload: dict) -> dict | None:
    vulns = (payload or {}).get("vulnerabilities") or []
    if not vulns:
        return None
    cve = (vulns[0] or {}).get("cve") or {}
    descs = cve.get("descriptions") or []
    summary = next(
        (d.get("value", "") for d in descs if d.get("lang") == "en"),
        descs[0].get("value", "") if descs else "",
    )
    severity, score = "", None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = (cve.get("metrics") or {}).get(key) or []
        if metrics:
            data = metrics[0].get("cvssData") or {}
            severity = (
                data.get("baseSeverity") or metrics[0].get("baseSeverity") or ""
            ).lower()
            score = data.get("baseScore")
            break
    cwes = [
        d.get("value", "")
        for w in (cve.get("weaknesses") or [])
        for d in (w.get("description") or [])
        if str(d.get("value", "")).startswith("CWE-")
    ]
    refs = [r.get("url", "") for r in (cve.get("references") or []) if r.get("url")]
    return {
        "id": f"nvd:{cve_id}",
        "source": "nvd",
        "kind": "cve",
        "cve_id": cve_id,
        "title": f"{cve_id} — NVD",
        "summary": summary,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "severity": severity,
        "refs": refs[:8],
        "data": {
            "cvss_score": score,
            "cwes": cwes,
            "published": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
        },
    }


def _fetch(cve_id: str) -> dict:
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else None
    raw = request_json("nvd", "GET", _URL, params={"cveId": cve_id}, headers=headers)
    parsed = _parse(cve_id, raw)
    if parsed is None:
        raise LiveNotFound(f"nvd: no record for {cve_id}")
    return parsed


def collect(seeds: Seeds, policy: CachePolicy) -> list[LiveRecord]:
    out: list[LiveRecord] = []
    for cve in dict.fromkeys(norm_cve(c) for c in seeds.cve_ids):
        if not cve.startswith("CVE-"):
            continue
        got = cached_fetch("nvd", cve, policy, lambda c=cve: _fetch(c))
        if isinstance(got.payload, dict) and got.payload.get("id"):
            out.append(LiveRecord.model_validate(got.payload))
    return out
