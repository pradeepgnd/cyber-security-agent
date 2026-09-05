"""Shared specialist shape: pre-step → retrieve → one LLM call → citation filter."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel

from src.llm import StructuredOutputError, structured
from src.state import Finding, FindingBatch


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def emit_trace(payload: dict[str, Any]) -> None:
    try:
        from langgraph.config import get_stream_writer

        get_stream_writer()(payload)
    except Exception:  # noqa: BLE001 — outside a graph run this is a no-op
        pass


def allowed_citation_ids(retrieved: list[tuple[str, str, float]]) -> set[str]:
    ids: set[str] = set()
    for _, chunk_id, _ in retrieved:
        ids.add(chunk_id)
        if "#" in chunk_id:
            ids.add(chunk_id.split("#", 1)[0])
    return ids


def sanitize_findings(
    findings: list[Finding],
    *,
    agent: str,
    allowed_ids: set[str],
) -> list[Finding]:
    cleaned: list[Finding] = []
    for i, finding in enumerate(findings, 1):
        fid = finding.id.strip() or f"{agent}-{i:03d}"
        citations = [c for c in finding.citations if c in allowed_ids]
        confidence = min(1.0, max(0.0, finding.confidence))
        cleaned.append(
            finding.model_copy(
                update={
                    "id": fid,
                    "agent": agent,
                    "citations": citations,
                    "confidence": confidence,
                }
            )
        )
    return cleaned


def failed_step(agent: str, started: float, summary: str) -> dict:
    return {
        "findings": [],
        "visited": [agent],
        "agent_log": [
            {
                "agent": agent,
                "status": "failed",
                "summary": summary,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "retrieved_ids": [],
                "started_at": utc_now(),
            }
        ],
    }


def done_update(
    agent: str,
    started: float,
    findings: list[Finding],
    retrieved_ids: list[str],
    summary: str,
    extra: dict | None = None,
) -> dict:
    update = {
        "findings": [f.model_dump() for f in findings],
        "visited": [agent],
        "agent_log": [
            {
                "agent": agent,
                "status": "done",
                "summary": summary,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "retrieved_ids": retrieved_ids,
                "started_at": utc_now(),
            }
        ],
    }
    if extra:
        update.update(extra)
    return update


def run_llm_findings(
    *,
    agent: str,
    prompt: str,
    schema: type[BaseModel] = FindingBatch,
    started: float,
    retrieved: list[tuple[str, str, float]],
    extra_allowed_ids: set[str] | None = None,
    **variables: object,
) -> dict:
    emit_trace({"agent": agent, "phase": "llm", "message": "Calling model for findings"})
    try:
        batch = structured(schema, prompt, **variables)
    except StructuredOutputError as exc:
        emit_trace({"agent": agent, "phase": "error", "message": str(exc)})
        return failed_step(agent, started, f"structured output failed: {exc}")

    findings_raw = getattr(batch, "findings", None)
    if findings_raw is None:
        return failed_step(agent, started, "model returned no findings field")
    allowed = allowed_citation_ids(retrieved) | (extra_allowed_ids or set())
    findings = sanitize_findings(list(findings_raw), agent=agent, allowed_ids=allowed)
    ids = [cid for _, cid, _ in retrieved]
    summary = f"{len(findings)} finding(s); retrieved {len(ids)} chunk(s)"
    emit_trace(
        {
            "agent": agent,
            "phase": "findings",
            "message": summary,
            "retrieved_ids": ids,
            "finding_titles": [f.title for f in findings],
        }
    )
    extra = {}
    if hasattr(batch, "plan"):
        extra["final_plan"] = batch.plan
    if hasattr(batch, "risk_score"):
        extra["risk_score"] = float(batch.risk_score)
    return done_update(agent, started, findings, ids, summary, extra or None)
