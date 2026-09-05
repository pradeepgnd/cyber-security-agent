"""Shared graph state and structured-output schemas."""

from __future__ import annotations

import operator
from typing import Annotated, Literal, TypedDict

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
AgentName = Literal[
    "log_monitor",
    "threat_intel",
    "vuln_scanner",
    "policy_checker",
    "incident_response",
]
StepStatus = Literal["running", "done", "failed", "skipped"]
NextAgent = Literal[
    "log_monitor",
    "threat_intel",
    "vuln_scanner",
    "policy_checker",
    "incident_response",
    "FINISH",
]


class Finding(BaseModel):
    id: str = ""
    agent: str = ""
    title: str
    description: str
    severity: Severity
    confidence: float = Field(ge=0, le=1)
    evidence: list[str] = Field(default_factory=list)
    citations: list[str] = Field(default_factory=list)
    recommended_action: str = ""


class FindingBatch(BaseModel):
    findings: list[Finding] = Field(default_factory=list)


class AgentStep(BaseModel):
    agent: str
    status: StepStatus
    summary: str = ""
    latency_ms: int = 0
    retrieved_ids: list[str] = Field(default_factory=list)
    started_at: str = ""


class RoutingDecision(BaseModel):
    next_agent: NextAgent
    reason: str


class IncidentPlan(BaseModel):
    risk_score: float = Field(ge=0, le=100)
    plan: str


class SecurityState(TypedDict):
    scenario_id: str
    raw_logs: dict[str, str]
    artifacts: dict[str, str]
    scenario_meta: dict
    findings: Annotated[list[dict], operator.add]
    agent_log: Annotated[list[dict], operator.add]
    visited: Annotated[list[str], operator.add]
    next_agent: str
    iterations: int
    final_plan: str
    risk_score: float
    routing_reason: str
