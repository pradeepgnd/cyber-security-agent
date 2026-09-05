from __future__ import annotations

import time

from src.agents.common import emit_trace, run_llm_findings, skip_llm
from src.rag.retrievers import format_retrieved, retrieve
from src.state import SecurityState


def _categories(findings: list[dict]) -> str:
    if not findings:
        return "(no findings yet)"
    lines = []
    for f in findings:
        if f.get("agent") == "policy_checker":
            continue
        lines.append(f"- [{f.get('severity')}] {f.get('agent')}: {f.get('title')}")
    return "\n".join(lines) or "(no findings yet)"


PROMPT = """You are the Policy Checker.
Map the finding categories onto NIST 800-53 and SOC 2 controls from the retrieved set.
Emit one finding per relevant control with severity reflecting the gap.
Put the verdict in the title as PASS, PARTIAL, or FAIL (example: "AC-7 Unsuccessful Logon Attempts — FAIL").
Only cite retrieved chunk ids.

Scenario: {scenario_id}

Finding categories:
{categories}

Retrieved controls:
{context}

Rules:
- Cover at least AC-7 / AU-6 / SI-4 for brute-force auth abuse, and RA-5 / CM-6 for vulnerable deps.
- For Log4Shell also consider SI-4 and CC7.2 / CC7.3.
- recommended_action is the control-aligned fix, not a generic "review".
"""


def policy_checker_node(state: SecurityState) -> dict:
    started = time.perf_counter()
    findings = state.get("findings") or []
    cats = _categories(findings)
    emit_trace(
        {
            "agent": "policy_checker",
            "phase": "prestep",
            "message": f"Collected {len(findings)} prior finding(s) for control mapping",
        }
    )
    if not findings:
        return skip_llm(
            "policy_checker",
            started,
            "No findings to map — skipping LLM",
        )
    blob = cats.lower()
    if "log4" in blob or "jndi" in blob or "44228" in blob:
        query = "RA-5 vulnerability monitoring CM-6 configuration SI-4 system monitoring CC7"
    else:
        query = "AC-7 unsuccessful logon AU-6 audit review SI-4 monitoring CC6 CC7"
    retrieved = retrieve("controls", query, k=5)
    emit_trace(
        {
            "agent": "policy_checker",
            "phase": "retrieve",
            "message": f"Retrieved {len(retrieved)} control excerpt(s)",
            "retrieved_ids": [cid for _, cid, _ in retrieved],
        }
    )
    return run_llm_findings(
        agent="policy_checker",
        prompt=PROMPT,
        started=started,
        retrieved=retrieved,
        scenario_id=state.get("scenario_id", ""),
        categories=cats,
        context=format_retrieved(retrieved),
    )
