"""Streamlit SOC dashboard — live agent trace, streamed IR plan, citation-backed findings."""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pandas as pd
import streamlit as st

from src.cache import load_run, save_run
from src.config import (
    AGENT_LABELS,
    AGENT_NAMES,
    LANGSMITH_PROJECT,
    LANGSMITH_TRACING,
    OPENROUTER_MODEL,
    SEVERITY_COLORS,
)
from src.graph import build_graph, initial_state, run_config
from src.integrations.github_issues import preview_incident, file_incident, qualifying_findings, text_on
from src.rag.ingest import rebuild_collections
from src.rag.retrievers import collection_stats, reset_client, resolve_chunk
from src.scenarios import (
    UploadError,
    classify_file,
    list_scenarios,
    load_scenario,
    load_uploaded,
)

CHIP_COLORS = {
    "idle": "#6b7280",
    "running": "#2563eb",
    "done": "#059669",
    "skipped": "#9ca3af",
    "failed": "#dc2626",
}


def _severity_badge(severity: str) -> str:
    sev = str(severity or "info").lower()
    bg = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["info"])
    fg = text_on(bg)
    return (
        f'<span style="background:{bg};color:{fg};border-radius:6px;'
        f'padding:2px 8px;font-size:0.8rem;font-weight:600;text-transform:uppercase;">'
        f"{sev}</span>"
    )


def _sev_style(val) -> str:
    bg = SEVERITY_COLORS.get(str(val).lower(), SEVERITY_COLORS["info"])
    fg = text_on(bg)
    return f"background-color: {bg}; color: {fg}"


def _severity_frame(rows: list[dict]):
    df = pd.DataFrame(rows)
    if df.empty or "severity" not in df.columns:
        return df
    return df.style.map(_sev_style, subset=["severity"])


def _chip_html(name: str, status: str) -> str:
    color = CHIP_COLORS.get(status, "#6b7280")
    label = AGENT_LABELS.get(name, name)
    return (
        f'<div style="border:1px solid {color};color:{color};border-radius:999px;'
        f'padding:6px 12px;text-align:center;font-size:0.85rem;font-weight:600;">'
        f"{label}<br><span style='font-weight:400;font-size:0.75rem'>{status}</span></div>"
    )


def _render_chips(placeholder, statuses: dict[str, str]) -> None:
    cols = placeholder.columns(len(AGENT_NAMES))
    for col, name in zip(cols, AGENT_NAMES):
        col.markdown(_chip_html(name, statuses.get(name, "idle")), unsafe_allow_html=True)


def _live_badges(citations: list[str]) -> list[str]:
    """Provenance chips for a finding's live citations (NVD / KEV / EPSS / OSV)."""
    try:
        from src.live.cache import load_live_record
    except Exception:  # noqa: BLE001
        return []
    out: list[str] = []
    seen: set[str] = set()
    for cid in citations or []:
        if ":" not in cid or cid in seen:
            continue
        seen.add(cid)
        rec = load_live_record(cid)
        if not rec:
            continue
        src = rec.get("source", "")
        data = rec.get("data") or {}
        if src == "kev":
            out.append("🔴 CISA KEV — known-exploited")
        elif src == "nvd":
            score = data.get("cvss_score")
            sev = (rec.get("severity") or "").upper()
            out.append(f"NVD CVSS {score} {sev}".strip() if score is not None else f"NVD {sev}".strip())
        elif src == "epss":
            epss, pct = data.get("epss"), data.get("percentile")
            if epss is not None:
                label = f"EPSS {float(epss):.3f}"
                if pct is not None:
                    label += f" · p{float(pct) * 100:.0f}"
                out.append(label)
        elif src == "osv":
            out.append(f"OSV {cid.split(':', 1)[1]}")
    return out


def _render_badges(badges: list[str]) -> None:
    if not badges:
        return
    spans = " ".join(
        '<span style="background:#eef2ff;color:#3730a3;border-radius:6px;'
        f'padding:2px 8px;margin-right:6px;font-size:0.8rem;">{b}</span>'
        for b in badges
    )
    st.markdown(spans, unsafe_allow_html=True)


def _finalize_statuses(statuses: dict[str, str], visited: list[str]) -> dict[str, str]:
    out = dict(statuses)
    for name in AGENT_NAMES:
        if name in visited:
            if out.get(name) not in {"failed", "done"}:
                out[name] = "done"
        elif out.get(name) == "idle":
            out[name] = "skipped"
    return out


def render_cached(result: dict) -> None:
    findings = result.get("findings") or []
    plan = result.get("final_plan") or "_No plan cached._"
    _tabs(
        findings,
        plan,
        result.get("raw_logs") or {},
        result.get("risk_score"),
        result.get("artifacts") or {},
    )
    _github_panel(result)


def _github_panel(result: dict) -> None:
    from src.config import GITHUB_ENABLED, GITHUB_REPO

    st.subheader("File to GitHub")
    n_child = len(qualifying_findings(result))
    st.caption(
        f"about to create 1 parent and {n_child} child issue(s) in `{GITHUB_REPO}`. "
        "Findings may contain IPs and usernames — do not file into a public repo."
    )
    filed = result.get("github") or {}
    if filed.get("parent"):
        st.success(
            f"Already filed parent #{filed['parent']} in {filed.get('repo', GITHUB_REPO)} "
            f"({len(filed.get('issues') or {})} children). Re-file is a no-op."
        )
        return
    if st.button("File to GitHub"):
        st.session_state["gh_preview"] = preview_incident(result)
    preview = st.session_state.get("gh_preview")
    if not preview:
        return
    st.markdown(f"**Parent:** {preview['parent']['title']}")
    st.markdown(preview["parent"]["body"])
    for i, child in enumerate(preview.get("children") or [], 1):
        with st.expander(f"Child {i}: {child['title']}"):
            st.markdown(child["body"])
    if not GITHUB_ENABLED:
        st.button("Post to GitHub", disabled=True)
        st.warning("GITHUB_ENABLED=false — posting disabled. Set GITHUB_ENABLED=true and GITHUB_TOKEN to post.")
        return
    if st.button("Confirm post to GitHub", type="primary"):
        out = file_incident(result, dry_run=False)
        if out.get("skipped"):
            st.info("Already filed.")
        elif out.get("ok"):
            st.success(f"Filed parent #{out.get('parent')} in {out.get('repo')}")
            save_run(str(result.get("scenario_id") or "run"), result)
        else:
            st.error(out.get("error") or str(out.get("errors") or "filing failed"))
            if result.get("github"):
                save_run(str(result.get("scenario_id") or "run"), result)


def _tabs(
    findings: list[dict],
    plan: str,
    raw_logs: dict[str, str],
    risk_score,
    artifacts: dict[str, str] | None = None,
) -> None:
    findings_tab, plan_tab, compliance_tab, logs_tab = st.tabs(
        ["Findings", "Response Plan", "Compliance", "Raw logs"]
    )
    with findings_tab:
        if not findings:
            st.info("No findings yet.")
        else:
            rows = [
                {
                    "severity": f.get("severity"),
                    "agent": f.get("agent"),
                    "title": f.get("title"),
                    "confidence": f.get("confidence"),
                    "live": sum(1 for c in f.get("citations") or [] if ":" in c),
                    "citations": ", ".join(f.get("citations") or []),
                }
                for f in findings
            ]
            st.dataframe(_severity_frame(rows), use_container_width=True, hide_index=True)
            for f in findings:
                st.markdown(
                    f"{_severity_badge(f.get('severity'))} **{f.get('title')}**",
                    unsafe_allow_html=True,
                )
                with st.expander("Details"):
                    st.write(f.get("description") or "")
                    _render_badges(_live_badges(f.get("citations") or []))
                    if f.get("recommended_action"):
                        st.markdown(f"**Action:** {f['recommended_action']}")
                    if f.get("evidence"):
                        st.code("\n".join(f["evidence"][:8]))
                    for cid in f.get("citations") or []:
                        text = resolve_chunk(cid)
                        st.markdown(f"**{cid}**")
                        st.caption((text or "citation not found")[:800])
    with plan_tab:
        if risk_score:
            st.metric("Risk score", risk_score)
        st.markdown(plan)
    with compliance_tab:
        policy = [f for f in findings if f.get("agent") == "policy_checker"]
        if not policy:
            st.info("Policy Checker did not run or produced no control gaps.")
        else:
            st.dataframe(
                _severity_frame(
                    [
                        {
                            "control": f.get("title"),
                            "severity": f.get("severity"),
                            "gap": f.get("description"),
                            "action": f.get("recommended_action"),
                            "citations": ", ".join(f.get("citations") or []),
                        }
                        for f in policy
                    ]
                ),
                use_container_width=True,
                hide_index=True,
            )
    with logs_tab:
        if not raw_logs and not artifacts:
            st.info("No logs on this run.")
        for name, text in raw_logs.items():
            with st.expander(name, expanded=False):
                st.code(text[:8000], language="text")
        for name, text in (artifacts or {}).items():
            with st.expander(f"{name} (artifact)", expanded=False):
                st.code(text[:8000], language="text")


def run_live(bundle: dict, chip_box, trace_box, plan_box) -> dict:
    scenario_id = bundle["scenario_id"]
    state = initial_state(
        scenario_id, bundle["raw_logs"], bundle["artifacts"], bundle["meta"]
    )
    graph = build_graph()
    statuses = {name: "idle" for name in AGENT_NAMES}
    _render_chips(chip_box, statuses)

    status_widgets: dict = {}
    live_slots: dict[tuple[str, str], object] = {}
    token_counts: dict[str, int] = {}
    supervisor_reason: list[str] = []
    plan_tokens: list[str] = []
    final: dict = {
        "findings": [],
        "agent_log": [],
        "visited": [],
        "final_plan": "",
        "risk_score": 0,
        "raw_logs": bundle["raw_logs"],
        "artifacts": bundle.get("artifacts") or {},
        "scenario_id": scenario_id,
        "model": OPENROUTER_MODEL,
    }

    def ensure_status(agent: str):
        if agent not in status_widgets:
            with trace_box:
                status_widgets[agent] = st.status(
                    AGENT_LABELS.get(agent, agent), expanded=True
                )
        return status_widgets[agent]

    def set_line(agent: str, key: str, text: str) -> None:
        slot = (agent, key)
        if slot not in live_slots:
            with ensure_status(agent):
                live_slots[slot] = st.empty()
        live_slots[slot].markdown(text)

    for mode, data in graph.stream(
        state,
        config=run_config(scenario_id),
        stream_mode=["updates", "messages", "custom"],
    ):
        if mode == "custom" and isinstance(data, dict):
            agent = data.get("agent", "supervisor")
            if agent in statuses and statuses[agent] == "idle":
                statuses[agent] = "running"
                _render_chips(chip_box, statuses)
            widget = ensure_status(agent)
            widget.write(data.get("message", ""))
            if data.get("retrieved_ids"):
                widget.write("retrieved: " + ", ".join(data["retrieved_ids"]))
        elif mode == "messages":
            msg, meta = data
            node = (meta or {}).get("langgraph_node", "")
            content = getattr(msg, "content", "") or ""
            if not content or not node:
                continue
            if node in statuses and statuses[node] == "idle":
                statuses[node] = "running"
                _render_chips(chip_box, statuses)
            if node == "supervisor":
                supervisor_reason.append(content)
                set_line(node, "stream", "".join(supervisor_reason))
            elif node == "incident_response":
                plan_tokens.append(content)
                text = "".join(plan_tokens)
                set_line(node, "stream", f"Writing plan… {len(text)} chars")
                plan_box.markdown(text)
            else:
                token_counts[node] = token_counts.get(node, 0) + len(content)
                set_line(node, "stream", f"Generating findings… {token_counts[node]} tokens")
        elif mode == "updates" and isinstance(data, dict):
            for node, update in data.items():
                if not isinstance(update, dict):
                    continue
                if node in statuses:
                    failed = any(
                        step.get("status") == "failed"
                        for step in update.get("agent_log") or []
                    )
                    statuses[node] = "failed" if failed else "done"
                    _render_chips(chip_box, statuses)
                    if node in status_widgets:
                        status_widgets[node].update(
                            label=f"{AGENT_LABELS.get(node, node)} — {statuses[node]}",
                            state="error" if failed else "complete",
                            expanded=False,
                        )
                if "findings" in update:
                    final["findings"].extend(update["findings"])
                if "agent_log" in update:
                    final["agent_log"].extend(update["agent_log"])
                if "visited" in update:
                    final["visited"].extend(update["visited"])
                if update.get("final_plan"):
                    final["final_plan"] = update["final_plan"]
                    plan_box.markdown(update["final_plan"])
                if update.get("risk_score") is not None:
                    final["risk_score"] = update["risk_score"]
                if update.get("next_agent"):
                    nxt = update["next_agent"]
                    widget = ensure_status("supervisor")
                    widget.write(f"→ {nxt}: {update.get('routing_reason', '')}")
                    if nxt in statuses and nxt != "FINISH":
                        statuses[nxt] = "running"
                        _render_chips(chip_box, statuses)

    statuses = _finalize_statuses(statuses, final["visited"])
    _render_chips(chip_box, statuses)
    if not final.get("final_plan") and plan_tokens:
        final["final_plan"] = "".join(plan_tokens)
    save_run(scenario_id, final)
    return final


st.set_page_config(page_title="SOC Multi-Agent", layout="wide")
st.title("SOC Multi-Agent")
st.caption("Supervisor + 5 specialists · local RAG · citations on every finding")

with st.sidebar:
    st.subheader("Run")
    input_mode = st.radio("Input", ["Bundled scenario", "Upload files"])
    bundle: dict | None = None
    upload_error: str | None = None

    if input_mode == "Bundled scenario":
        scenarios = list_scenarios()
        scenario_choice = st.selectbox(
            "Scenario", scenarios, index=0 if scenarios else None
        )
        if scenario_choice:
            bundle = load_scenario(scenario_choice)
    else:
        uploaded = st.file_uploader(
            "Text logs and manifests",
            accept_multiple_files=True,
            help="Up to 10 files, 2 MB each. Manifests (requirements, Dockerfiles, …) "
            "are artifacts; everything else is treated as a log.",
        )
        if uploaded:
            try:
                bundle = load_uploaded(uploaded)
                st.caption(f"Run id: `{bundle['scenario_id']}`")
                st.table(
                    [
                        {"file": f.name, "kind": classify_file(f.name)}
                        for f in uploaded
                    ]
                )
            except UploadError as exc:
                upload_error = str(exc)
                st.error(upload_error)

    st.markdown(f"**Model:** `{OPENROUTER_MODEL}`")
    st.markdown(
        f"**LangSmith:** {'on · ' + LANGSMITH_PROJECT if LANGSMITH_TRACING else 'off'}"
    )
    if st.button("Rebuild knowledge base"):
        with st.spinner("Rebuilding Chroma index…"):
            stats = rebuild_collections(wipe=True)
            reset_client()
        st.success("Knowledge base rebuilt")
        st.json(stats)
    st.markdown("**KB chunks**")
    try:
        stats = collection_stats()
        st.table([{"collection": k, "chunks": v} for k, v in stats.items()])
    except Exception as exc:  # noqa: BLE001
        st.warning(f"Index not built yet ({exc}). Click Rebuild knowledge base.")

    st.markdown("**Live intel cache**")
    try:
        from src.config import CACHE_MODE, LIVE_SOURCES
        from src.live import cache as _live_cache

        st.caption(f"mode: `{CACHE_MODE}`  ·  frozen = never calls the network")
        st.table(
            [
                {
                    "source": name,
                    "cached": len(list((_live_cache.LIVE_CACHE_DIR / name).glob("*.json")))
                    if (_live_cache.LIVE_CACHE_DIR / name).exists()
                    else 0,
                    "frozen": len(list((_live_cache.LIVE_FIXTURES_DIR / name).glob("*.json")))
                    if (_live_cache.LIVE_FIXTURES_DIR / name).exists()
                    else 0,
                }
                for name in LIVE_SOURCES
            ]
        )
    except Exception as exc:  # noqa: BLE001
        st.caption(f"live cache unavailable ({exc})")

    ignore_cache = st.checkbox("Ignore disk cache", value=False)
    run_clicked = st.button("Run analysis", type="primary", disabled=bundle is None)

chip_box = st.container()
_render_chips(chip_box, {n: "idle" for n in AGENT_NAMES})
trace_box = st.container()
st.subheader("Response plan")
plan_box = st.empty()

if "results" not in st.session_state:
    st.session_state.results = {}

run_id = bundle["scenario_id"] if bundle else None


def _fill_from_bundle(result: dict, src: dict) -> dict:
    result.setdefault("raw_logs", src["raw_logs"])
    result.setdefault("artifacts", src.get("artifacts") or {})
    return result


if run_id and not run_clicked and run_id in st.session_state.results:
    result = st.session_state.results[run_id]
    plan_box.markdown(result.get("final_plan") or "")
    render_cached(result)
elif run_id and bundle and not run_clicked and not ignore_cache:
    cached = load_run(run_id)
    if cached:
        _fill_from_bundle(cached, bundle)
        st.session_state.results[run_id] = cached
        plan_box.markdown(cached.get("final_plan") or "")
        st.info("Showing cached run. Tick “Ignore disk cache” and re-run for a live trace.")
        render_cached(cached)

if run_clicked and bundle and run_id:
    if not ignore_cache:
        cached = load_run(run_id)
        if cached:
            _fill_from_bundle(cached, bundle)
            st.session_state.results[run_id] = cached
            plan_box.markdown(cached.get("final_plan") or "")
            st.info("Loaded from disk cache.")
            render_cached(cached)
            st.stop()
    result = run_live(bundle, chip_box, trace_box, plan_box)
    _fill_from_bundle(result, bundle)
    st.session_state.results[run_id] = result
    render_cached(result)
