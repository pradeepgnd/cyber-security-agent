"""Fan-out orchestrator for the live-enrichment sidecar.

Called from a deterministic agent pre-step with the CVE ids / packages / IOCs the
agent already holds. Returns normalized `LiveRecord`s plus the trace lines and
the set of citeable ids the agent should allow.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.config import LIVE_MAX_CVES_PER_RUN, LIVE_MAX_RECORDS_PER_AGENT
from src.live import cache
from src.live.models import LiveRecord, format_live_records
from src.live.policy import CachePolicy
from src.live.sources import SOURCE_MODULES
from src.live.sources.base import Seeds, norm_cve
from src.tools.depscan import Package


@dataclass
class EnrichResult:
    records: list[LiveRecord] = field(default_factory=list)
    trace: list[str] = field(default_factory=list)
    mode: str = "frozen"

    @property
    def allowed_ids(self) -> set[str]:
        return {r.id for r in self.records}

    @property
    def context_block(self) -> str:
        return format_live_records(self.records)

    def by_cve(self, cve_id: str) -> list[LiveRecord]:
        cve = norm_cve(cve_id)
        return [r for r in self.records if r.cve_id == cve]


_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _as_float(value: object) -> float:
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return 0.0


def _priority(rec: LiveRecord) -> tuple[int, int, float, float]:
    """Rank for keeping the most decision-relevant records when capped.

    KEV membership first, then severity, then CVSS, then EPSS.
    """
    kev = 1 if rec.source == "kev" else 0
    sev = _SEV_RANK.get((rec.severity or "").lower(), 0)
    return (kev, sev, _as_float(rec.data.get("cvss_score")), _as_float(rec.data.get("epss")))


def _seeds(cve_ids, packages, iocs) -> Seeds:
    seen: list[str] = []
    for c in cve_ids or []:
        cve = norm_cve(c)
        if cve.startswith("CVE-") and cve not in seen:
            seen.append(cve)
    return Seeds(
        cve_ids=seen[:LIVE_MAX_CVES_PER_RUN],
        packages=list(packages or []),
        iocs=list(iocs or []),
    )


def enrich(
    *,
    cve_ids: list[str] | None = None,
    packages: list[Package] | None = None,
    iocs: list[str] | None = None,
    scenario_meta: dict | None = None,
) -> EnrichResult:
    policy = CachePolicy.resolve(scenario_meta)
    seeds = _seeds(cve_ids, packages, iocs)

    if not seeds.cve_ids and not seeds.packages:
        return EnrichResult(trace=["enrichment: no CVE ids or packages to resolve"], mode=policy.mode)

    merged: dict[str, LiveRecord] = {}
    trace: list[str] = [f"enrichment mode={policy.mode}, {len(seeds.cve_ids)} CVE seed(s)"]

    for name, module in SOURCE_MODULES:
        try:
            recs = module.collect(seeds, policy)
        except Exception as exc:  # noqa: BLE001 — one bad source must not stop the rest
            trace.append(f"{name}: error ({exc})")
            continue
        for rec in recs:
            merged[rec.id] = rec
        if recs:
            trace.append(f"{name}: {len(recs)} record(s)")
        elif policy.mode == "frozen":
            trace.append(f"{name}: no cached record (frozen)")
        else:
            trace.append(f"{name}: 0 records")

    records = sorted(merged.values(), key=_priority, reverse=True)
    if len(records) > LIVE_MAX_RECORDS_PER_AGENT:
        trace.append(
            f"capped {len(records)} live record(s) to {LIVE_MAX_RECORDS_PER_AGENT} "
            "(kept KEV / highest severity / CVSS / EPSS)"
        )
        records = records[:LIVE_MAX_RECORDS_PER_AGENT]

    for rec in records:
        cache.write_index(rec.id, {**rec.model_dump(), "fetched_at": rec.fetched_at or cache.iso_now()})

    return EnrichResult(records=records, trace=trace, mode=policy.mode)
