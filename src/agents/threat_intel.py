from __future__ import annotations

import re
import time

from src.agents.common import emit_trace, run_llm_findings
from src.live.enrich import enrich
from src.rag.retrievers import format_retrieved, retrieve_many
from src.state import SecurityState

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
IOC_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _slice(state: SecurityState) -> list[dict]:
    findings = state.get("findings") or []
    return [f for f in findings if f.get("agent") in {"log_monitor", "vuln_scanner"}] or findings


PROMPT = """You are Threat Intelligence.
Given extracted IOCs / CVE ids and retrieved CVE + ATT&CK cards, decide what we are seeing
and whether we are affected. Emit findings (CVE matches, exploit context, affected verdict).
Only cite chunk ids from the retrieved set.

Scenario: {scenario_id}

Extracted IOCs / CVE ids:
{iocs}

Prior findings (title + severity):
{prior}

Retrieved CVE and ATT&CK context:
{context}

Live intel (NVD / CISA KEV / EPSS / OSV — cite these ids too when used):
{live_intel}

Rules:
- If Log4Shell / JNDI / CVE-2021-44228 is indicated, say so explicitly and name the CVE.
- If SSH brute force + valid-account success is indicated, map T1110 / T1078 / T1021.004.
- Do not invent CVEs that are not in the retrieved context or extracted ids.
- When live intel confirms a CVE is in CISA KEV or has a high EPSS score, raise the finding's severity/confidence and say so.
"""


def threat_intel_node(state: SecurityState) -> dict:
    started = time.perf_counter()
    prior = _slice(state)
    blob = "\n".join(
        f"{f.get('title', '')} {f.get('description', '')} {' '.join(f.get('evidence') or [])}"
        for f in prior
    )
    cves = sorted({m.upper() for m in CVE_RE.findall(blob)})
    ips = sorted(set(IOC_RE.findall(blob)))
    ioc_text = f"CVEs: {', '.join(cves) or 'none'}\nIPs: {', '.join(ips) or 'none'}\nSignal text:\n{blob[:2000]}"
    emit_trace(
        {
            "agent": "threat_intel",
            "phase": "prestep",
            "message": f"Extracted {len(cves)} CVE id(s), {len(ips)} IP IOC(s)",
        }
    )
    if cves or "jndi" in blob.lower() or "log4" in blob.lower():
        cve_q = "log4j jndi rce CVE-2021-44228"
        mitre_q = "T1190 exploit public-facing application rce"
    else:
        cve_q = "openssh brute force credential attack"
        mitre_q = "T1110 brute force T1078 valid accounts T1021.004 SSH lateral movement"
    retrieved = retrieve_many([("cve", cve_q), ("mitre", mitre_q)], k=4)
    emit_trace(
        {
            "agent": "threat_intel",
            "phase": "retrieve",
            "message": f"Retrieved {len(retrieved)} CVE/ATT&CK chunk(s)",
            "retrieved_ids": [cid for _, cid, _ in retrieved],
        }
    )
    prior_text = "\n".join(
        f"- [{f.get('severity')}] {f.get('title')}" for f in prior
    ) or "(none yet)"

    enriched = enrich(
        cve_ids=cves,
        iocs=ips,
        scenario_meta=state.get("scenario_meta") or {},
    )
    for line in enriched.trace:
        emit_trace({"agent": "threat_intel", "phase": "enrich", "message": line})

    return run_llm_findings(
        agent="threat_intel",
        prompt=PROMPT,
        started=started,
        retrieved=retrieved,
        extra_allowed_ids=enriched.allowed_ids,
        scenario_id=state.get("scenario_id", ""),
        iocs=ioc_text,
        prior=prior_text,
        context=format_retrieved(retrieved),
        live_intel=enriched.context_block,
    )
