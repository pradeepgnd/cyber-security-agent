from __future__ import annotations

import time

from src.agents.common import done_update, emit_trace, failed_step
from src.llm import stream_text
from src.rag.retrievers import format_retrieved, retrieve
from src.state import Finding, SecurityState

WEIGHTS = {"critical": 10.0, "high": 7.0, "medium": 4.0, "low": 1.0, "info": 0.0}


def compute_risk_score(findings: list[dict]) -> float:
    raw = 0.0
    for f in findings:
        sev = str(f.get("severity", "info"))
        try:
            conf = float(f.get("confidence", 0.6))
        except (TypeError, ValueError):
            conf = 0.6
        raw += WEIGHTS.get(sev, 1.0) * conf
    return round(min(100.0, raw * 3.0), 1)


PROMPT = """You are Incident Response. Write a prioritized, phased remediation plan
as markdown (not JSON). Phases MUST appear as headings:

## Contain
## Eradicate
## Recover
## Harden

Each bullet should be a concrete action and cite a retrieved runbook id in square
brackets like [rb-ssh-brute-force]. Only cite ids from the retrieved set.
Do not invent tools that were not implied by the findings.

Scenario: {scenario_id}
Risk score (already computed): {risk_score}

All findings:
{findings}

Retrieved runbooks:
{context}

Write the plan now. Markdown only.
"""


def incident_response_node(state: SecurityState) -> dict:
    started = time.perf_counter()
    findings = state.get("findings") or []
    risk = compute_risk_score(findings)
    emit_trace(
        {
            "agent": "incident_response",
            "phase": "prestep",
            "message": f"Aggregated {len(findings)} finding(s); risk_score={risk}",
        }
    )
    blob = " ".join(f.get("title", "") for f in findings).lower()
    if "log4" in blob or "jndi" in blob or "44228" in blob:
        query = "rce log4shell containment eradication dependency patching recover harden"
    else:
        query = "brute force credential rotation account containment ssh harden recover"
    retrieved = retrieve("runbooks", query, k=5)
    ids = [cid for _, cid, _ in retrieved]
    emit_trace(
        {
            "agent": "incident_response",
            "phase": "retrieve",
            "message": f"Retrieved {len(retrieved)} runbook(s)",
            "retrieved_ids": ids,
        }
    )
    finding_text = "\n".join(
        f"- [{f.get('severity')}] {f.get('agent')}: {f.get('title')} — {f.get('description', '')[:240]}"
        for f in findings
    ) or "(no findings)"
    emit_trace({"agent": "incident_response", "phase": "llm", "message": "Writing remediation plan"})
    try:
        plan = "".join(
            stream_text(
                PROMPT,
                scenario_id=state.get("scenario_id", ""),
                risk_score=risk,
                findings=finding_text,
                context=format_retrieved(retrieved),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return failed_step("incident_response", started, f"plan generation failed: {exc}")

    if not plan.strip():
        return failed_step("incident_response", started, "empty plan")

    summary_finding = Finding(
        id="ir-plan",
        agent="incident_response",
        title=f"Remediation plan issued (risk {risk})",
        description="Phased contain → eradicate → recover → harden plan is in final_plan.",
        severity="high" if risk >= 40 else "medium",
        confidence=0.8,
        evidence=[f"{len(findings)} input findings"],
        citations=[cid for cid in ids if cid in plan],
        recommended_action="Execute the phased plan; confirm each gate before moving on.",
    )
    emit_trace(
        {
            "agent": "incident_response",
            "phase": "findings",
            "message": f"Plan ready ({len(plan)} chars)",
            "retrieved_ids": ids,
        }
    )
    return done_update(
        "incident_response",
        started,
        [summary_finding],
        ids,
        f"plan {len(plan)} chars; risk={risk}",
        {"final_plan": plan, "risk_score": risk},
    )
