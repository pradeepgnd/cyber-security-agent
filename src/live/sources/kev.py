"""CISA KEV — the known-exploited-vulnerabilities catalog.

Fetched once per run as a single document (~2 MB), then membership-checked in
memory against the seed CVE ids. Emits `kev:CVE-…` only for CVEs in the catalog.
"""

from __future__ import annotations

from src.config import LIVE_SOURCE_URLS
from src.live.http import request_json
from src.live.models import LiveRecord
from src.live.policy import CachePolicy
from src.live.sources.base import Seeds, cached_fetch, norm_cve

_URL = LIVE_SOURCE_URLS["kev"]
_CATALOG_KEY = "catalog"


def _fetch_catalog() -> dict:
    raw = request_json("kev", "GET", _URL)
    index: dict[str, dict] = {}
    for item in (raw or {}).get("vulnerabilities") or []:
        cve = norm_cve(item.get("cveID", ""))
        if cve:
            index[cve] = {
                "date_added": item.get("dateAdded", ""),
                "due_date": item.get("dueDate", ""),
                "name": item.get("vulnerabilityName", ""),
                "required_action": item.get("requiredAction", ""),
                "known_ransomware": item.get("knownRansomwareCampaignUse", ""),
            }
    return {"count": len(index), "index": index}


def collect(seeds: Seeds, policy: CachePolicy) -> list[LiveRecord]:
    wanted = [c for c in dict.fromkeys(norm_cve(c) for c in seeds.cve_ids) if c.startswith("CVE-")]
    if not wanted:
        return []

    got = cached_fetch("kev", _CATALOG_KEY, policy, _fetch_catalog)
    index = (got.payload or {}).get("index") if isinstance(got.payload, dict) else None
    if not index:
        return []

    out: list[LiveRecord] = []
    for cve in wanted:
        meta = index.get(cve)
        if not meta:
            continue
        out.append(
            LiveRecord.model_validate(
                {
                    "id": f"kev:{cve}",
                    "source": "kev",
                    "kind": "exploited",
                    "cve_id": cve,
                    "title": f"{cve} — CISA KEV (known-exploited)",
                    "summary": (
                        f"{meta.get('name') or cve} is in the CISA Known Exploited "
                        f"Vulnerabilities catalog (added {meta.get('date_added') or '?'}, "
                        f"remediate by {meta.get('due_date') or '?'}). "
                        f"Required action: {meta.get('required_action') or 'apply vendor fix'}. "
                        f"Known ransomware use: {meta.get('known_ransomware') or 'unknown'}."
                    ),
                    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
                    "severity": "high",
                    "refs": [],
                    "data": meta,
                }
            )
        )
    return out
