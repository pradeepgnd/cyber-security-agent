"""Supervisor routing with a code-enforced loop policy."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass

from src.agents.common import emit_trace
from src.config import (
    AGENT_NAMES,
    SUPERVISOR_ABSOLUTE_MAX,
    SUPERVISOR_DEFAULT_MAX_ITERATIONS,
    SUPERVISOR_DEFAULT_MAX_VISITS,
    SUPERVISOR_TERMINAL_AGENT,
    env_int,
)
from src.llm import StructuredOutputError, structured
from src.state import RoutingDecision, SecurityState

SPECIALISTS = tuple(AGENT_NAMES)


@dataclass(frozen=True)
class RoutingPolicy:
    max_iterations: int
    max_visits_per_agent: int
    required_agents: tuple[str, ...]
    terminal_agent: str

    @classmethod
    def resolve(cls, scenario_meta: dict | None) -> RoutingPolicy:
        meta = scenario_meta or {}
        routing = meta.get("routing") if isinstance(meta.get("routing"), dict) else {}

        def pick(key: str, env_name: str, default: int) -> int:
            if key in routing:
                return int(routing[key])
            if key in meta:
                return int(meta[key])
            env_val = env_int(env_name)
            if env_val is not None:
                return env_val
            return default

        max_iter = pick("max_iterations", "SUPERVISOR_MAX_ITERATIONS", SUPERVISOR_DEFAULT_MAX_ITERATIONS)
        max_visits = pick(
            "max_visits_per_agent",
            "SUPERVISOR_MAX_VISITS_PER_AGENT",
            SUPERVISOR_DEFAULT_MAX_VISITS,
        )
        required = routing.get("required_agents") or meta.get("required_agents") or []
        terminal = (
            routing.get("terminal_agent")
            or meta.get("terminal_agent")
            or SUPERVISOR_TERMINAL_AGENT
        )
        max_iter = min(max(1, max_iter), SUPERVISOR_ABSOLUTE_MAX)
        max_visits = max(1, max_visits)
        required_t = tuple(a for a in required if a in SPECIALISTS)
        if terminal not in SPECIALISTS:
            terminal = SUPERVISOR_TERMINAL_AGENT
        return cls(max_iter, max_visits, required_t, terminal)


PROMPT = """You are the SOC supervisor. Choose the next specialist, or FINISH.
You do not analyze logs yourself.

Available agents:
- log_monitor: parse auth/web/app logs, surface suspicious events
- threat_intel: map IOCs/CVEs to local threat intel and ATT&CK
- vuln_scanner: scan artifacts (requirements.txt, Dockerfile) for known CVEs
- policy_checker: map findings to NIST 800-53 / SOC 2 control gaps
- incident_response: write the phased remediation plan (must run last, only after ≥1 finding)
- FINISH: stop. Only legal after incident_response has run.

Policy (enforced in code; do not violate it):
- max_iterations={max_iterations} (you are on hop {iterations})
- max_visits_per_agent={max_visits_per_agent}
- required_agents={required_agents}
- terminal_agent={terminal_agent}
- already visited: {visited}
- legal choices this turn: {legal}

Scenario: {scenario_id}
{scenario_summary}

Findings so far (title + severity only):
{findings}

Pick the single best next_agent and a short reason (one or two sentences).
Prefer required agents that have not run yet. Do not pick incident_response until
there is at least one finding. After incident_response, pick FINISH.
"""


def _legal_choices(state: SecurityState, policy: RoutingPolicy) -> list[str]:
    counts = Counter(state.get("visited") or [])
    findings = state.get("findings") or []
    legal: list[str] = []
    for name in SPECIALISTS:
        if counts[name] >= policy.max_visits_per_agent:
            continue
        if name == policy.terminal_agent and not findings:
            continue
        legal.append(name)
    if policy.terminal_agent in (state.get("visited") or []):
        return ["FINISH"]
    return legal


def supervisor_node(state: SecurityState) -> dict:
    policy = RoutingPolicy.resolve(state.get("scenario_meta") or {})
    iterations = int(state.get("iterations") or 0) + 1
    visited = list(state.get("visited") or [])
    findings = state.get("findings") or []

    def finish(reason: str, nxt: str) -> dict:
        emit_trace({"agent": "supervisor", "phase": "route", "message": reason, "next_agent": nxt})
        return {"next_agent": nxt, "routing_reason": reason, "iterations": iterations}

    if policy.terminal_agent in visited:
        return finish("Terminal agent already ran — finishing.", "FINISH")

    if iterations >= policy.max_iterations:
        if policy.terminal_agent not in visited:
            return finish(
                f"Hit max_iterations={policy.max_iterations}; forcing {policy.terminal_agent}.",
                policy.terminal_agent,
            )
        return finish("Hit max_iterations and terminal agent ran — finishing.", "FINISH")

    legal = _legal_choices(state, policy)
    if not legal:
        if policy.terminal_agent not in visited and findings:
            return finish("No specialists left; forcing terminal agent.", policy.terminal_agent)
        return finish("No legal specialists remain — finishing.", "FINISH")

    if policy.terminal_agent not in legal and not findings:
        # keep investigating
        pass

    finding_lines = "\n".join(
        f"- [{f.get('severity')}] {f.get('title')}" for f in findings
    ) or "(none yet)"
    summary = (state.get("scenario_meta") or {}).get("summary") or ""

    emit_trace(
        {
            "agent": "supervisor",
            "phase": "llm",
            "message": f"Routing hop {iterations}/{policy.max_iterations}",
        }
    )

    def ask(blocked: list[str] | None = None) -> RoutingDecision:
        allowed = [a for a in legal if a not in (blocked or [])]
        if not allowed:
            raise StructuredOutputError("no legal agents left to ask for")
        return structured(
            RoutingDecision,
            PROMPT,
            max_iterations=policy.max_iterations,
            iterations=iterations,
            max_visits_per_agent=policy.max_visits_per_agent,
            required_agents=", ".join(policy.required_agents) or "(none)",
            terminal_agent=policy.terminal_agent,
            visited=", ".join(visited) or "(none)",
            legal=", ".join(allowed),
            scenario_id=state.get("scenario_id", ""),
            scenario_summary=summary,
            findings=finding_lines,
        )

    try:
        decision = ask()
    except StructuredOutputError as exc:
        fallback = legal[0]
        return finish(f"Supervisor parse failed ({exc}); falling back to {fallback}.", fallback)

    choice = decision.next_agent
    if choice not in legal and choice != "FINISH":
        try:
            decision = ask(blocked=[choice])
            choice = decision.next_agent
        except StructuredOutputError:
            choice = legal[0]
            decision = RoutingDecision(next_agent=choice, reason=f"Rejected illegal {choice}; defaulting.")

    if choice == "FINISH" and policy.terminal_agent not in visited:
        choice = policy.terminal_agent if findings else legal[0]
        reason = f"FINISH rejected until {policy.terminal_agent} runs; routing to {choice}."
        return finish(reason, choice)

    if choice not in legal and choice != "FINISH":
        choice = legal[0]
        return finish(f"Corrected illegal route to {choice}.", choice)

    return finish(decision.reason, choice)


def route_next(state: SecurityState) -> str:
    nxt = state.get("next_agent") or "FINISH"
    if nxt == "FINISH":
        return "FINISH"
    if nxt in SPECIALISTS:
        return nxt
    return "FINISH"
