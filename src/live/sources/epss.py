"""EPSS (FIRST) — exploit-probability score per CVE. One `epss:CVE-…` per id.

The API is batch; we fetch all missing CVEs in one call, then write a per-CVE
cache entry so later runs reuse each score independently.
"""

from __future__ import annotations

from src.config import LIVE_SOURCE_URLS
from src.live import cache
from src.live.http import request_json
from src.live.models import LiveRecord
from src.live.policy import CachePolicy
from src.live.sources.base import Seeds, norm_cve

_URL = LIVE_SOURCE_URLS["epss"]


def _record(cve_id: str, epss: float, pct: float) -> dict:
    return {
        "id": f"epss:{cve_id}",
        "source": "epss",
        "kind": "score",
        "cve_id": cve_id,
        "title": f"{cve_id} — EPSS {epss:.3f} (p{pct * 100:.1f})",
        "summary": (
            f"EPSS exploit-probability {epss:.4f}, percentile {pct:.4f}. "
            "Higher means more likely to be exploited in the wild in the next 30 days."
        ),
        "url": f"https://api.first.org/data/v1/epss?cve={cve_id}",
        "severity": "",
        "refs": [],
        "data": {"epss": epss, "percentile": pct},
    }


def _fetch_batch(cve_ids: list[str]) -> dict[str, dict]:
    raw = request_json("epss", "GET", _URL, params={"cve": ",".join(cve_ids)})
    rows = (raw or {}).get("data") or []
    out: dict[str, dict] = {}
    for row in rows:
        cve = norm_cve(row.get("cve", ""))
        if not cve:
            continue
        try:
            out[cve] = _record(cve, float(row.get("epss", 0)), float(row.get("percentile", 0)))
        except (TypeError, ValueError):
            continue
    return out


def collect(seeds: Seeds, policy: CachePolicy) -> list[LiveRecord]:
    wanted = [c for c in dict.fromkeys(norm_cve(c) for c in seeds.cve_ids) if c.startswith("CVE-")]
    if not wanted:
        return []

    out: list[LiveRecord] = []
    missing: list[str] = []
    ttl = policy.ttl("epss")
    for cve in wanted:
        entry = cache.read("epss", cve, ttl)
        if entry is not None and (entry.fresh or policy.serve_stale) and not policy.force_fetch:
            if isinstance(entry.payload, dict) and entry.payload.get("id"):
                out.append(LiveRecord.model_validate(entry.payload))
            continue
        missing.append(cve)

    if missing and policy.may_fetch:
        try:
            batch = _fetch_batch(missing)
        except Exception:  # noqa: BLE001 — negative-cache each, move on
            batch = {}
        for cve in missing:
            rec = batch.get(cve)
            if rec:
                cache.write("epss", cve, rec, status="ok", ttl_seconds=ttl)
                out.append(LiveRecord.model_validate(rec))
            else:
                cache.write("epss", cve, None, status="not_found", ttl_seconds=policy.negative_ttl)
    return out
