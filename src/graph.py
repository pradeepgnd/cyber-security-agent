"""LangGraph assembly: supervisor hub with five specialist spokes."""

from __future__ import annotations

from langgraph.graph import END, START, StateGraph

try:
    from langgraph.checkpoint.memory import InMemorySaver as MemorySaver
except ImportError:  # langgraph < 0.3
    from langgraph.checkpoint.memory import MemorySaver

from src.agents.incident_response import incident_response_node
from src.agents.log_monitor import log_monitor_node
from src.agents.policy_checker import policy_checker_node
from src.agents.threat_intel import threat_intel_node
from src.agents.vuln_scanner import vuln_scanner_node
from src.state import SecurityState
from src.supervisor import route_next, supervisor_node


def build_graph(*, checkpointer: bool = True):
    graph = StateGraph(SecurityState)
    graph.add_node("supervisor", supervisor_node)
    graph.add_node("log_monitor", log_monitor_node)
    graph.add_node("threat_intel", threat_intel_node)
    graph.add_node("vuln_scanner", vuln_scanner_node)
    graph.add_node("policy_checker", policy_checker_node)
    graph.add_node("incident_response", incident_response_node)

    graph.add_edge(START, "supervisor")
    graph.add_conditional_edges(
        "supervisor",
        route_next,
        {
            "log_monitor": "log_monitor",
            "threat_intel": "threat_intel",
            "vuln_scanner": "vuln_scanner",
            "policy_checker": "policy_checker",
            "incident_response": "incident_response",
            "FINISH": END,
        },
    )
    for name in (
        "log_monitor",
        "threat_intel",
        "vuln_scanner",
        "policy_checker",
        "incident_response",
    ):
        graph.add_edge(name, "supervisor")

    saver = MemorySaver() if checkpointer else None
    return graph.compile(checkpointer=saver)


def initial_state(
    scenario_id: str,
    raw_logs: dict[str, str],
    artifacts: dict[str, str],
    scenario_meta: dict,
) -> SecurityState:
    return {
        "scenario_id": scenario_id,
        "raw_logs": raw_logs,
        "artifacts": artifacts,
        "scenario_meta": scenario_meta,
        "findings": [],
        "agent_log": [],
        "visited": [],
        "next_agent": "",
        "iterations": 0,
        "final_plan": "",
        "risk_score": 0.0,
        "routing_reason": "",
    }


def run_config(scenario_id: str, thread_id: str | None = None) -> dict:
    return {
        "configurable": {"thread_id": thread_id or scenario_id},
        "run_name": f"soc-{scenario_id}",
        "tags": [scenario_id, "phase1"],
        "metadata": {"scenario_id": scenario_id},
    }
