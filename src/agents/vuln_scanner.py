from __future__ import annotations

import time

from src.agents.common import emit_trace, run_llm_findings, skip_llm
from src.live.enrich import enrich
from src.rag.retrievers import format_retrieved, retrieve
from src.state import SecurityState
from src.tools.cve_match import hits_as_text, match_cves
from src.tools.depscan import packages_as_text, scan_artifacts

PROMPT = """You are the Vulnerability Scanner.
You are given a deterministic dependency inventory and version-matched local CVE records.
Turn matches into findings. Include the vulnerable package@version and the fixed version.
Only cite retrieved chunk ids.

Scenario: {scenario_id}

Packages:
{packages}

Deterministic CVE matches:
{hits}

Retrieved CVE context:
{context}

Live intel (OSV / NVD / CISA KEV / EPSS — cite these ids too when used):
{live_intel}

Rules:
- If a match names CVE-2021-44228 / log4j-core, that finding MUST appear.
- If there are no packages or no matches, emit at most one info finding saying so.
- recommended_action should name the fixed version when known.
- Prefer the fixed version from OSV live intel when it disagrees with the local KB, and note the discrepancy.
- If live intel shows a CVE is in CISA KEV, mark that finding at least high severity.
"""


def vuln_scanner_node(state: SecurityState) -> dict:
    started = time.perf_counter()
    packages = scan_artifacts(state.get("artifacts") or {})
    hits = match_cves(packages)
    emit_trace(
        {
            "agent": "vuln_scanner",
            "phase": "prestep",
            "message": f"Scanned {len(packages)} package(s), {len(hits)} CVE match(es)",
        }
    )
    if not packages and not hits:
        return skip_llm(
            "vuln_scanner",
            started,
            "No packages or CVE matches — skipping LLM",
        )
    query = " ".join(h.cve_id for h in hits) or " ".join(p.name for p in packages) or "vulnerability"
    if any("log4" in p.name.lower() for p in packages) or any("44228" in h.cve_id for h in hits):
        query = "log4j jndi rce CVE-2021-44228"
    retrieved = retrieve("cve", query, k=4)
    emit_trace(
        {
            "agent": "vuln_scanner",
            "phase": "retrieve",
            "message": f"Retrieved {len(retrieved)} CVE chunk(s)",
            "retrieved_ids": [cid for _, cid, _ in retrieved],
        }
    )

    enriched = enrich(
        cve_ids=[h.cve_id for h in hits],
        packages=packages,
        scenario_meta=state.get("scenario_meta") or {},
    )
    for line in enriched.trace:
        emit_trace({"agent": "vuln_scanner", "phase": "enrich", "message": line})

    return run_llm_findings(
        agent="vuln_scanner",
        prompt=PROMPT,
        started=started,
        retrieved=retrieved,
        extra_allowed_ids=enriched.allowed_ids,
        scenario_id=state.get("scenario_id", ""),
        packages=packages_as_text(packages),
        hits=hits_as_text(hits),
        context=format_retrieved(retrieved),
        live_intel=enriched.context_block,
    )
