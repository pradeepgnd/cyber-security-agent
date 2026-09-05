# Cybersecurity AI Agent — Plan

A multi-agent system, built on LangGraph + LangChain + RAG, that monitors logs, cross-references
threats, scans for vulnerabilities, drafts incident response plans, and checks compliance —
modeled on the `deep-agents-walkthrough/competitive_analysis_agent` pattern from the sibling
`langgraph-advanced` repo (one orchestrator, several named subagents, file-based deliverables).

> This project started as a subfolder of `langgraph-advanced` and was moved out to its own
> repo (`cyber-security-agent`) once Phase 1 was built; references below to "this repo" /
> relative paths into `deep-agents-walkthrough` or `studio-agent` refer to that sibling repo.

Work proceeds in phases. Phase 1 is the MVP and is built first, end to end, before any Phase 2/3
item is started.

---

## Phase 1 — Core multi-agent system (MVP)

### Architecture

Deepagents-style orchestrator: one main agent (`create_deep_agent`) with 5 subagents, coordinating
over a shared scratchpad of markdown findings files — not a hand-wired `StateGraph`. This fits the
"investigate → correlate → report" shape of a security workflow better than rigid graph nodes, and
mirrors `competitive_analysis_agent.py`'s orchestrator/research-agent/critique-agent split.

### Location & setup

New top-level `cybersecurity-agent/` folder (sibling to `studio-agent/` and
`deep-agents-walkthrough/`):

```
cybersecurity-agent/
  cybersecurity_agent.py     # orchestrator + 5 subagent defs (main deliverable)
  langgraph.json             # exposes `graph` for `langgraph dev` / Studio
  requirements.txt
  .env.example
  README.md                  # how to run, same shape as other projects' READMEs
  knowledge_base/
    cves.json                # sample CVE records
    policies/                # NIST 800-53 / ISO 27001 / SOC2 control excerpts
    threat_reports/          # MITRE ATT&CK technique summaries
  sample_data/
    auth.log                 # sample logs for Log Monitor Agent to read
    access.log
    requirements.txt         # sample "target project" deps for Vulnerability Scanner
  vector_store/              # local Chroma persistence dir (built on first run, gitignored)
```

LLM: `ChatOpenAI` via OpenRouter (`OPENROUTER_API_KEY` / `OPENROUTER_MODEL`), matching the
convention already used in `deep-agents-walkthrough` and `studio-agent`.

### RAG

Local curated corpus, embedded into a local Chroma vector store (built from
`knowledge_base/**` on first run, persisted under `vector_store/`). One shared tool:

```python
retrieve_knowledge_base(query: str, source: Literal["cve", "policy", "threat_report"]) -> list[dict]
```

Does a similarity search filtered by `source` metadata. Given to the Threat Intelligence and
Policy Checker subagents.

### The 5 subagents

| Agent | Tool(s) | Output |
|---|---|---|
| **Log Monitor Agent** | `read_logs(path)` — parses `sample_data/*.log` for anomaly signals (failed-login bursts, unusual IPs/ports, spikes) via regex/heuristics | `log_findings.md` |
| **Threat Intelligence Agent** | `retrieve_knowledge_base(source="cve"\|"threat_report")` — cross-references packages/services named in log findings against the local CVE corpus | `threat_findings.md` |
| **Vulnerability Scanner Agent** | `scan_dependencies(requirements_path)` — pure-Python static check of a sample project's `requirements.txt` against the CVE corpus (version-range match) | `vuln_findings.md` |
| **Incident Response Agent** | none (reads the other findings files) — drafts a prioritized, step-by-step remediation plan | `incident_response_plan.md` |
| **Policy Checker Agent** | `retrieve_knowledge_base(source="policy")` — maps findings to NIST/ISO/SOC2 control IDs, flags gaps | `compliance_report.md` |

### Orchestrator workflow

1. Record the original request in `analysis_request.txt`.
2. Log Monitor Agent gathers findings.
3. Threat Intelligence Agent + Vulnerability Scanner Agent run (can be called in parallel by the
   orchestrator, same as `competitive_analysis_agent` parallelizes research calls).
4. Policy Checker Agent runs against all findings so far.
5. Incident Response Agent drafts the action plan from everything collected.
6. Orchestrator writes a final `security_summary.md` synthesizing all five outputs.

### Deliverable for Phase 1

- Runnable via `langgraph dev` (Studio chat tab).
- Runnable as a plain CLI demo (`python cybersecurity_agent.py`), like
  `studio-agent/agent.py`'s `__main__` block.
- `README.md` documenting setup and a sample run, same shape as the other projects' docs.

**Phase 1 is done when:** a single run against the bundled `sample_data/` produces all five
findings files plus `security_summary.md`, with the Threat Intel and Policy Checker agents visibly
citing retrieved knowledge-base entries (proving the RAG path is exercised, not skipped).

---

## Phase 2 — Realism upgrades (after Phase 1 works)

- Threat Intelligence Agent gains a live NVD CVE REST API tool alongside the local RAG fallback
  (network optional, API key optional).
- Vulnerability Scanner Agent adds a real-tool integration path (`pip-audit` / `trivy` subprocess
  call) when the binary is present, falling back to the static Python check otherwise.
- Log Monitor ingests a second, noisier synthetic log set to stress-test the anomaly heuristics.

## Phase 3 — Productionization (optional, later)

- LangSmith tracing on every subagent call, matching `studio-agent`'s traced pattern.
- Persist findings/history via a checkpointer so repeated runs build an incident timeline.
- A small `chat.py` / API wrapper for interacting outside Studio, same shape as `studio/chat.py`.

---

## Open decisions carried into implementation

None blocking — Phase 1 above already resolves architecture, RAG source, scanner scope, and
location/provider to their recommended defaults. Revisit only if something in Phase 1 turns out
to not fit once built.

---

## Demo UI (post-Phase 1 addition)

Added a `streamlit_app.py` demo UI alongside the existing CLI/Studio entry points, so the agent
can be shown to a non-technical audience without a terminal or LangGraph Studio. Chosen over a
FastAPI+web frontend or Studio-only demo because it's pure Python, single file, and needs no
separate frontend/backend.

- Imports `cybersecurity_agent` directly (same compiled graph the CLI uses) and drives it with
  `.stream(..., stream_mode="updates")` so a sidebar-configured run shows live per-subagent
  progress instead of one blocking spinner.
- Renders `result["files"]` as one tab per generated deliverable
  (`log_findings.md`, `threat_findings.md`, `vuln_findings.md`, `compliance_report.md`,
  `incident_response_plan.md`, `security_summary.md`), plus the final assistant message as a
  summary banner.
- New deps: `streamlit`, `python-dotenv` (added to `requirements.txt`).
- Run with `streamlit run streamlit_app.py` (documented in `README.md` as "Option C").
