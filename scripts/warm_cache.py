#!/usr/bin/env python3
"""Populate the live-enrichment cache for a scenario, before a demo.

  python scripts/warm_cache.py --scenario log4shell
  python scripts/warm_cache.py --all --mode live

Seeds are derived deterministically from the scenario (dependency scan + local
CVE match + any CVE ids named in meta.json), never from a model.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# Deterministic log-signature -> candidate CVEs (script-only; see PHASE3_NOTES #1).
SIGNATURE_CVES = {
    "jndi": ["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
    "log4j": ["CVE-2021-44228"],
    "commons-text": ["CVE-2022-42889"],
}


def _seeds_for(scenario_id: str):
    from src.scenarios import load_scenario
    from src.tools.cve_match import match_cves
    from src.tools.depscan import scan_artifacts

    loaded = load_scenario(scenario_id)
    packages = scan_artifacts(loaded["artifacts"])
    cve_ids = {h.cve_id.upper() for h in match_cves(packages)}

    blob = " ".join(loaded["artifacts"].values()) + " " + " ".join(loaded["raw_logs"].values())
    blob += " " + " ".join(str(k) for k in loaded["meta"].get("expected_keywords") or [])
    cve_ids |= {m.upper() for m in CVE_RE.findall(blob)}
    low = blob.lower()
    for sig, cves in SIGNATURE_CVES.items():
        if sig in low:
            cve_ids |= set(cves)
    return sorted(cve_ids), packages


def warm(scenario_id: str) -> int:
    from src.live.enrich import enrich

    cve_ids, packages = _seeds_for(scenario_id)
    print(f"\n=== {scenario_id} ===")
    print(f"seed CVEs: {', '.join(cve_ids) or '(none)'}")
    print(f"seed packages: {', '.join(p.key() for p in packages) or '(none)'}")

    result = enrich(cve_ids=cve_ids, packages=packages, scenario_meta={})
    for line in result.trace:
        print(f"  {line}")
    for rec in result.records:
        print(f"  + {rec.id}  [{rec.severity or '-'}]  {rec.title}")
    return 0 if result.records or not cve_ids else 1


def main() -> int:
    parser = argparse.ArgumentParser(description="Warm the live-enrichment cache")
    parser.add_argument("--scenario", help="scenario id")
    parser.add_argument("--all", action="store_true", help="every scenario")
    parser.add_argument(
        "--mode",
        default="live",
        choices=["live", "bypass"],
        help="cache mode for this run (default: live)",
    )
    args = parser.parse_args()

    os.environ["CACHE_MODE"] = args.mode  # must be set before src.config import

    from src.scenarios import list_scenarios

    targets = list_scenarios() if args.all else [args.scenario] if args.scenario else []
    if not targets:
        parser.error("pass --scenario <id> or --all")

    rc = 0
    for sid in targets:
        rc |= warm(sid)
    print("\ndone." if rc == 0 else "\ndone (some scenarios produced no live records).")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
