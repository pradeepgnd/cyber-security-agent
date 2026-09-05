from __future__ import annotations

import time

from src.agents.common import emit_trace, run_llm_findings, skip_llm
from src.rag.retrievers import format_retrieved, retrieve
from src.state import SecurityState
from src.tools.log_parse import events_as_text, parse_logs

PROMPT = """You are the Log Monitor on a SOC multi-agent team.
Turn the deterministic parse results into a concise list of findings.
Map each finding to a MITRE ATT&CK technique when possible (T1110, T1190, T1078, T1059, T1021, T1136).
Only cite chunk ids from the retrieved detection rules below. Do not invent ids.

Scenario: {scenario_id}

Deterministic parse:
{events}

Retrieved detection rules:
{context}

Rules:
- Prefer fewer, higher-quality findings over a laundry list.
- Include concrete evidence lines.
- Ignore obvious noise (single failed logins, ordinary 404s) unless they support a pattern.
- confidence is 0-1.
"""


def log_monitor_node(state: SecurityState) -> dict:
    started = time.perf_counter()
    events = parse_logs(state.get("raw_logs") or {})
    emit_trace(
        {
            "agent": "log_monitor",
            "phase": "prestep",
            "message": f"Parsed logs — {len(events)} suspicious event group(s)",
        }
    )
    if not events:
        return skip_llm(
            "log_monitor",
            started,
            "No suspicious events — skipping LLM",
        )
    query = events_as_text(events)
    if "jndi" in query.lower() or "log4" in query.lower():
        q = "jndi ldap rce log4shell public-facing exploit detection"
    elif "failed" in query.lower() or "brute" in query.lower():
        q = "repeated failed password ssh brute force success after failures"
    else:
        q = query[:400] or "suspicious authentication or web exploit"
    retrieved = retrieve("detections", q, k=4)
    emit_trace(
        {
            "agent": "log_monitor",
            "phase": "retrieve",
            "message": f"Retrieved {len(retrieved)} detection rule(s)",
            "retrieved_ids": [cid for _, cid, _ in retrieved],
        }
    )
    return run_llm_findings(
        agent="log_monitor",
        prompt=PROMPT,
        started=started,
        retrieved=retrieved,
        scenario_id=state.get("scenario_id", ""),
        events=query,
        context=format_retrieved(retrieved),
    )
