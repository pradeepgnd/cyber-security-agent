#!/usr/bin/env python3
"""Headless SOC run. Same stream the UI consumes.

  python run_cli.py --scenario ssh_bruteforce
  python run_cli.py --scenario log4shell --check
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.cache import load_run, save_run
from src.config import AGENT_LABELS, OPENROUTER_MODEL
from src.graph import build_graph, initial_state, run_config
from src.integrations.github_issues import file_incident
from src.rag.retrievers import resolve_chunk
from src.scenarios import list_scenarios, load_scenario


def _print_tokens(node: str, token: str, last_node: list[str]) -> None:
    if last_node[0] != node:
        print(f"\n--- {AGENT_LABELS.get(node, node)} ---", flush=True)
        last_node[0] = node
    print(token, end="", flush=True)


def run_scenario(scenario_id: str, *, use_cache: bool = True) -> dict:
    if use_cache:
        cached = load_run(scenario_id)
        if cached:
            print(f"[cache] loaded {scenario_id} from disk")
            return cached

    loaded = load_scenario(scenario_id)
    state = initial_state(
        scenario_id,
        loaded["raw_logs"],
        loaded["artifacts"],
        loaded["meta"],
    )
    graph = build_graph()
    config = run_config(scenario_id)
    last_node = [""]
    final: dict = dict(state)

    print(f"model={OPENROUTER_MODEL}  scenario={scenario_id}")
    for mode, data in graph.stream(
        state,
        config=config,
        stream_mode=["updates", "messages", "custom"],
    ):
        if mode == "custom" and isinstance(data, dict):
            agent = data.get("agent", "?")
            print(f"\n[{agent}/{data.get('phase', '-')}] {data.get('message', data)}", flush=True)
        elif mode == "messages":
            msg, meta = data
            node = (meta or {}).get("langgraph_node", "")
            content = getattr(msg, "content", "") or ""
            if content and node == "incident_response":
                _print_tokens(node, content, last_node)
            elif content and node == "supervisor":
                _print_tokens(node, content, last_node)
            elif content:
                # specialists emit JSON — show a heartbeat, never the raw object
                print(".", end="", flush=True)
        elif mode == "updates" and isinstance(data, dict):
            for node, update in data.items():
                if not isinstance(update, dict):
                    continue
                final.update({k: v for k, v in update.items() if k not in {"findings", "agent_log", "visited"}})
                if "findings" in update:
                    final.setdefault("findings", [])
                    final["findings"] = [*final.get("findings", []), *update["findings"]]
                if "agent_log" in update:
                    final.setdefault("agent_log", [])
                    final["agent_log"] = [*final.get("agent_log", []), *update["agent_log"]]
                if "visited" in update:
                    final.setdefault("visited", [])
                    final["visited"] = [*final.get("visited", []), *update["visited"]]
                nxt = update.get("next_agent")
                if nxt:
                    print(f"\n>> supervisor → {nxt}: {update.get('routing_reason', '')}", flush=True)

    result = {
        "scenario_id": scenario_id,
        "findings": final.get("findings", []),
        "agent_log": final.get("agent_log", []),
        "visited": final.get("visited", []),
        "final_plan": final.get("final_plan", ""),
        "risk_score": final.get("risk_score", 0),
        "model": OPENROUTER_MODEL,
    }
    save_run(scenario_id, result)
    return result


def check_result(result: dict, meta: dict) -> int:
    errors: list[str] = []
    findings = result.get("findings") or []
    plan = result.get("final_plan") or ""
    if meta.get("expect_clean"):
        noisy = [
            f
            for f in findings
            if f.get("agent") != "incident_response"
            and str(f.get("severity", "")).lower() not in {"info"}
        ]
        if noisy:
            errors.append(
                "clean control produced security findings: "
                + ", ".join(f.get("title", "?") for f in noisy)
            )
        print("\n=== visit order ===")
        print(" → ".join(result.get("visited") or []) or "(none)")
        print(f"findings={len(findings)}  risk={result.get('risk_score')}  plan_chars={len(plan)}")
        if errors:
            print("CHECK FAILED:")
            for e in errors:
                print(f"  - {e}")
            return 1
        print("CHECK PASSED (clean control)")
        return 0

    if not findings:
        errors.append("no findings")
    if not plan.strip():
        errors.append("empty plan")

    haystack = " ".join(
        f"{f.get('title', '')} {f.get('description', '')}" for f in findings
    ) + " " + plan
    haystack_l = haystack.lower()
    for kw in meta.get("expected_keywords") or []:
        if str(kw).lower() not in haystack_l:
            errors.append(f"missing expected keyword: {kw}")

    unresolved: list[str] = []
    for f in findings:
        for cid in f.get("citations") or []:
            if resolve_chunk(cid) is None:
                unresolved.append(cid)
    if unresolved:
        errors.append(f"unresolved citations: {sorted(set(unresolved))}")

    print("\n=== visit order ===")
    print(" → ".join(result.get("visited") or []) or "(none)")
    print(f"findings={len(findings)}  risk={result.get('risk_score')}  plan_chars={len(plan)}")
    if errors:
        print("CHECK FAILED:")
        for e in errors:
            print(f"  - {e}")
        return 1
    print("CHECK PASSED")
    return 0


def _print_github_preview(preview: dict) -> None:
    print(f"\n=== GitHub dry run  repo={preview.get('repo')} ===")
    print(f"would create 1 parent + {preview.get('count', {}).get('children', 0)} child issues")
    print("\n-- labels --")
    for lab in preview.get("labels") or []:
        print(f"  {lab['name']:22s} color={lab['color']}")
    parent = preview.get("parent") or {}
    print("\n-- parent --")
    print(parent.get("title", ""))
    print(parent.get("body", "")[:2000])
    for i, child in enumerate(preview.get("children") or [], 1):
        print(f"\n-- child {i} --")
        print(child.get("title", ""))
        print((child.get("body") or "")[:800])


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the SOC graph from the terminal")
    parser.add_argument("--scenario", default="ssh_bruteforce", help="scenario id")
    parser.add_argument("--list", action="store_true", help="list scenarios")
    parser.add_argument("--check", action="store_true", help="assert meta.json expected keywords")
    parser.add_argument("--no-cache", action="store_true", help="ignore disk cache")
    parser.add_argument("--github", action="store_true", help="file the run to GitHub Issues")
    parser.add_argument(
        "--github-dry-run",
        action="store_true",
        help="print GitHub issue payloads without posting",
    )
    args = parser.parse_args()

    if args.list:
        print("\n".join(list_scenarios()) or "(no scenarios)")
        return 0

    result = run_scenario(args.scenario, use_cache=not args.no_cache)
    print("\n\n=== findings ===")
    for f in result.get("findings") or []:
        print(f"[{f.get('severity')}] {f.get('agent')}: {f.get('title')}  cites={f.get('citations')}")
    print("\n=== plan (head) ===")
    print((result.get("final_plan") or "")[:1200])

    if args.github_dry_run or args.github:
        preview = file_incident(result, dry_run=True)
        _print_github_preview(preview)
        if args.github and not args.github_dry_run:
            out = file_incident(result, dry_run=False)
            if out.get("skipped"):
                print("GitHub: already filed — nothing duplicated")
            elif out.get("ok"):
                print(f"GitHub: filed parent #{out.get('parent')} in {out.get('repo')}")
                save_run(args.scenario, result)
            else:
                print(f"GitHub: FAILED {out.get('error') or out.get('errors')}")
                if result.get("github"):
                    save_run(args.scenario, result)
                return 1

    if args.check:
        meta = load_scenario(args.scenario)["meta"]
        return check_result(result, meta)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
