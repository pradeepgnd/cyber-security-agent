from __future__ import annotations

import os

from src.supervisor import RoutingPolicy, _legal_choices


def test_defaults() -> None:
    policy = RoutingPolicy.resolve({})
    assert policy.max_iterations == 8
    assert policy.max_visits_per_agent == 1
    assert policy.terminal_agent == "incident_response"


def test_meta_overrides_and_clamp() -> None:
    policy = RoutingPolicy.resolve(
        {
            "max_iterations": 99,
            "max_visits_per_agent": 2,
            "required_agents": ["log_monitor", "nope"],
            "terminal_agent": "incident_response",
        }
    )
    assert policy.max_iterations <= 12
    assert policy.max_visits_per_agent == 2
    assert policy.required_agents == ("log_monitor",)


def test_env_override(monkeypatch) -> None:
    monkeypatch.setenv("SUPERVISOR_MAX_ITERATIONS", "3")
    policy = RoutingPolicy.resolve({})
    assert policy.max_iterations == 3
    monkeypatch.delenv("SUPERVISOR_MAX_ITERATIONS", raising=False)
    # scenario meta still wins over env
    os.environ.pop("SUPERVISOR_MAX_ITERATIONS", None)
    policy = RoutingPolicy.resolve({"max_iterations": 4})
    assert policy.max_iterations == 4


def test_incident_response_requires_findings() -> None:
    policy = RoutingPolicy.resolve({})
    legal = _legal_choices(
        {
            "visited": [],
            "findings": [],
            "next_agent": "",
            "iterations": 0,
            "scenario_id": "x",
            "raw_logs": {},
            "artifacts": {},
            "scenario_meta": {},
            "agent_log": [],
            "final_plan": "",
            "risk_score": 0,
            "routing_reason": "",
        },
        policy,
    )
    assert "incident_response" not in legal
    legal2 = _legal_choices(
        {
            "visited": ["log_monitor"],
            "findings": [{"title": "x", "severity": "high"}],
            "next_agent": "",
            "iterations": 1,
            "scenario_id": "x",
            "raw_logs": {},
            "artifacts": {},
            "scenario_meta": {},
            "agent_log": [],
            "final_plan": "",
            "risk_score": 0,
            "routing_reason": "",
        },
        policy,
    )
    assert "log_monitor" not in legal2  # already visited
    assert "incident_response" in legal2
