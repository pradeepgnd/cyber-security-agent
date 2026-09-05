# Phase 1 Plan — Multi-Agent Cybersecurity AI (Hackathon, 1 day)

## Context

You're building a hackathon demo of an AI-powered SOC: multiple specialist agents that read logs,
correlate against threat intelligence, scan for weaknesses, map to compliance controls, and produce a
remediation plan. Phase 1 proves the architecture end to end with a RAG knowledge base, LangGraph
orchestration and a Streamlit demo UI. Nothing exists yet — the working directory is empty, Python
3.12 and Docker are present, no `uv`, no `ollama`, no provider keys in the environment.

The deliverable is a demo that survives a judge asking "how does it know that?" — hence the local
knowledge base with per-finding citations, and a supervisor that visibly *chooses* which agents to run.

### Decisions locked in

| Area | Choice |
|---|---|
| LLM | OpenRouter (OpenAI-compatible); model + key via `.env`. Model-agnostic — no tool-calling or `response_format` dependency |
| Orchestration | LangGraph, supervisor + 5 specialist agents |
| Vector store | Chroma (persistent, on disk) |
| Embeddings | Local, no API cost |
| Agents in Phase 1 | All 5, shallow but real |
| Data | 100% local synthetic corpus, no network at demo time |
| Scenarios | 2 — SSH brute force → lateral movement; Log4Shell on a public API |
| UI | Streamlit SOC dashboard with a live agent trace |
| Extras | LangSmith tracing (optional), per-finding citations |
| Deferred to Phase 2 | Vuln Scanner / Policy Checker depth, human-in-the-loop approval gate, local JSON run trace, live NVD, benign control case |

---

## Architecture

```
                    ┌──────────────┐
   scenario ───────►│  Supervisor  │◄──── routes until FINISH (max 8 hops)
   (logs +          └──────┬───────┘
    artifacts)             │ next_agent
        ┌──────────┬───────┼────────┬──────────────┐
        ▼          ▼       ▼        ▼              ▼
   Log Monitor  Threat  Vuln    Policy      Incident Response
                Intel   Scanner Checker     (always runs last)
        │          │       │        │              │
        └──────────┴───────┴────────┴──────────────┘
                           │ retrieval
                   ┌───────▼────────┐
                   │ Chroma (5 KB   │  cve · mitre · controls
                   │  collections)  │  runbooks · detections
                   └────────────────┘
```

Every specialist follows the same three-step shape — this is deliberate, it's what makes 5 agents
buildable in a day:

1. **Deterministic pre-step** (regex/parse — no LLM). Cheap, reliable, gives the LLM structure.
2. **Retrieve** from its own Chroma collection, seeded by the pre-step output.
3. **One LLM call with structured output** → a list of `Finding` objects carrying `citations`.

The supervisor is the only place with genuinely open-ended routing.

---

## Repo layout

```
cyber-agent/
├── .env.example              OPENROUTER_API_KEY, OPENROUTER_MODEL, LANGSMITH_*
├── requirements.txt
├── README.md                 setup + 3-minute demo script
├── app.py                    Streamlit entrypoint
├── run_cli.py                headless run: python run_cli.py --scenario ssh_bruteforce
├── src/
│   ├── config.py             env loading, paths, model names
│   ├── llm.py                OpenRouter ChatOpenAI factory + structured-output helper
│   ├── state.py              SecurityState, Finding, AgentStep (pydantic + TypedDict)
│   ├── graph.py              LangGraph assembly, conditional edges, checkpointer
│   ├── supervisor.py         routing node + guardrails
│   ├── agents/
│   │   ├── log_monitor.py
│   │   ├── threat_intel.py
│   │   ├── vuln_scanner.py
│   │   ├── policy_checker.py
│   │   └── incident_response.py
│   ├── tools/
│   │   ├── log_parse.py      auth.log / nginx / app-log regex parsers, brute-force counter
│   │   ├── depscan.py        requirements.txt / pom.xml / Dockerfile → package@version list
│   │   └── cve_match.py      package+version → local CVE records (deterministic)
│   └── rag/
│       ├── embeddings.py     local embedding function + LangChain adapter
│       ├── ingest.py         markdown+frontmatter → chunks → Chroma collections
│       └── retrievers.py     per-collection retriever factory, returns text + chunk_id
├── data/
│   ├── kb/
│   │   ├── cve/              ~15 records (Log4Shell, OpenSSH, Struts, libs used in scenario 2)
│   │   ├── mitre/            ~10 ATT&CK technique cards (T1110, T1190, T1078, T1059, T1021…)
│   │   ├── controls/         NIST 800-53 (AC-7, AU-6, SI-4, RA-5, CM-6) + SOC2 CC6/CC7 excerpts
│   │   ├── runbooks/         ~8 IR runbooks (brute force, RCE, credential rotation, containment)
│   │   └── detections/       ~8 Sigma-style detection rules in markdown
│   ├── scenarios/
│   │   ├── ssh_bruteforce/   auth.log, syslog, meta.json (expected findings for self-check)
│   │   └── log4shell/        nginx_access.log, app.log, requirements.txt, Dockerfile, meta.json
│   └── chroma/               persisted index (gitignored)
└── scripts/build_kb.py       one-shot: wipe + rebuild all collections
```

Every KB file is markdown with YAML frontmatter (`id`, `title`, `source`, `type`, `tags`,
`severity`) — the frontmatter becomes Chroma metadata, and `id` is what a citation points at.

---

## Component detail

### `src/llm.py` — OpenRouter, model-independent structured output
`ChatOpenAI(model=OPENROUTER_MODEL, api_key=OPENROUTER_API_KEY, base_url="https://openrouter.ai/api/v1",
temperature=0, default_headers={"HTTP-Referer": ..., "X-Title": ...})`.

**Structured output does not depend on the model's capabilities.** No tool-calling, no
`response_format`, no `with_structured_output()` — those all vary by model and by how OpenRouter
routes it. Instead a single `structured(schema, prompt, **vars) -> BaseModel` helper used by every
agent, which works against any model that can emit text:

1. Render the Pydantic schema into the prompt via `PydanticOutputParser.get_format_instructions()`,
   with a hard instruction to reply with the JSON object and nothing else.
2. Call the model, take the raw string.
3. Parse defensively: strip ```json fences and any prose before/after, extract the outermost
   balanced `{...}`, then `model_validate_json`.
4. On a validation failure, one repair round-trip — send back the bad output plus the validation
   error and ask for corrected JSON only.
5. Still failing → raise a typed `StructuredOutputError` the node catches, recording a `failed`
   `AgentStep` so one bad agent degrades the run instead of killing the graph.

Consequence for the rest of the design: **agents never use LangChain tool-binding either.** Every
"tool" (log parsing, dependency scanning, CVE version matching, retrieval) is a plain Python function
the node calls directly, with results injected into the prompt. The LLM classifies and reasons; it
never decides to call a function. This is why swapping `OPENROUTER_MODEL` for anything — a 7B local
model through OpenRouter, or a frontier model — changes quality but never breaks the graph.

Optional: an env flag `USE_NATIVE_STRUCTURED_OUTPUT=true` opts into `with_structured_output()` for
models known to support it. Off by default, never on the demo path.

The helper has a `structured_stream(...)` twin that yields tokens as they arrive while accumulating
the full string, then runs the exact same parse/repair pipeline on the accumulated result. Streaming
therefore costs nothing in reliability — parsing is unchanged, it just happens after the last token
instead of after a silent wait.

### Streaming (design-wide)

The graph is consumed with LangGraph's multi-mode stream, `stream(..., stream_mode=["updates", "messages"])`:

- **`updates`** → node-level events: which agent the supervisor picked and why, what it retrieved,
  what findings it committed. Drives the status chips and the trace blocks.
- **`messages`** → raw LLM tokens tagged with the node that produced them. Drives live text.

Both modes are synchronous generators, so Streamlit consumes them with `st.write_stream` directly —
no asyncio bridge, no threads. What the user sees, per agent:

| Agent output | Streamed as |
|---|---|
| Supervisor routing decision | tokens → "Routing to Threat Intel because…" appears as it's written |
| Specialist findings (JSON) | token count + spinner while generating, then the parsed findings table snaps in — raw JSON is never shown |
| **Incident Response plan (markdown prose)** | **token-by-token into the panel** — this is the money shot of the demo, a remediation plan visibly writing itself |

Deterministic pre-steps (log parsing, dep scan, retrieval) emit their own trace lines *before* the
LLM call, so something appears on screen within ~200 ms of Run — well before the first token.

`run_cli.py` uses the same stream and prints tokens to stdout, so terminal debugging shows exactly
what the UI shows.

### `src/state.py`
```
Finding:      id, agent, title, description, severity(critical|high|medium|low|info),
              confidence(0-1), evidence[str], citations[chunk_id], recommended_action
AgentStep:    agent, status, summary, latency_ms, retrieved_ids[], started_at
SecurityState: scenario_id, raw_logs{name:text}, artifacts{name:text},
              findings: Annotated[list[Finding], operator.add]
              agent_log: Annotated[list[AgentStep], operator.add]
              visited: Annotated[list[str], operator.add]
              next_agent, iterations, final_plan, risk_score
```
The `operator.add` reducers are what let nodes append without clobbering each other.

### `src/supervisor.py`
Structured output: `{next_agent: Literal[...], reason: str}`. Prompt gets the scenario summary,
findings so far (title + severity only, to keep tokens down) and the visited list.

**Loop limits are prompt/config-supplied, with the code cap as backstop.** A `RoutingPolicy` object
resolves in this order:

1. limits declared in the scenario's `meta.json` or the routing prompt config
   (`max_iterations`, `max_visits_per_agent`, `required_agents`, `terminal_agent`);
2. env overrides (`SUPERVISOR_MAX_ITERATIONS`, …);
3. built-in defaults — `max_iterations=8`, `max_visits_per_agent=1`,
   `terminal_agent="incident_response"`.

Whatever the resolved policy, the code enforces it — the LLM is told the limits in its prompt so its
routing is informed, but a supervisor that ignores them is corrected, not trusted:

- agent visited more than `max_visits_per_agent` times → that choice is rejected and the supervisor
  is re-asked once with the invalid option removed;
- `incident_response` may only be chosen after ≥1 finding exists;
- `iterations >= max_iterations` → force `terminal_agent`, then FINISH. This is the hard stop and it
  is unconditional — a prompt-supplied policy can lower it but never disable it or raise it past
  `SUPERVISOR_ABSOLUTE_MAX` (12).

So: tunable per scenario without touching code, and still incapable of running away on stage.

### The five agents

| Agent | Deterministic pre-step | Retrieves from | Emits |
|---|---|---|---|
| **Log Monitor** | parse auth/nginx/app logs; count failed logins per src IP, flag new-geo success, flag JNDI/`${jndi:` and path-traversal payloads, spot sudo/`useradd` after login | `detections` | suspicious events + ATT&CK-mapped candidate findings |
| **Threat Intel** | extract IOCs, CVE ids, payload signatures from Log Monitor findings | `cve` + `mitre` | CVE matches, exploit context, "are we affected?" verdict |
| **Vuln Scanner** | `depscan.py` parses `requirements.txt` / `Dockerfile` from the scenario → package@version; `cve_match.py` does the version comparison | `cve` | vulnerable dependency findings with fixed-version |
| **Policy Checker** | collect finding categories | `controls` | control-by-control gap table (NIST + SOC2) with pass/fail/partial |
| **Incident Response** | aggregate all findings, compute risk score | `runbooks` | prioritized, phased plan: contain → eradicate → recover → harden, each step citing a runbook |

Only Incident Response gets the full findings list; the others see a filtered slice. Keeps prompts
small and latency down.

### `src/rag/` — retrieval
- Chunking: KB docs are already small; chunk at ~800 chars / 100 overlap, keep frontmatter fields as
  metadata on every chunk.
- Five Chroma collections rather than one, so each agent's retrieval is namespaced and can't drift
  into irrelevant material.
- `retrieve(collection, query, k=4)` returns `(text, chunk_id, score)` triples. **Citations are the
  chunk ids** — an agent may only cite ids present in its own retrieved set, and the node drops any
  hallucinated id before writing the finding to state. Cheap, and it's the honest version of citations.

**Embeddings:** default to the ONNX MiniLM that ships with `chromadb` (`DefaultEmbeddingFunction`,
~80 MB, no PyTorch) wrapped in a thin LangChain `Embeddings` adapter, rather than
`sentence-transformers` (pulls ~2 GB of torch). Same model, a fraction of the install time — which
matters a lot on a one-day clock.

### `app.py` — Streamlit SOC dashboard
- **Sidebar:** scenario selector, active model, "Rebuild knowledge base" button, KB stats
  (docs/chunks per collection), LangSmith on/off indicator, **Run analysis**.
- **Top row:** five status chips (idle / running / done / skipped) that light up live.
- **Center:** live trace driven by the dual-mode stream above — one `st.status` block per agent that
  opens the moment the supervisor routes to it, filling in with the routing reason (streamed),
  retrieved chunk ids, and then the findings. Blocks auto-collapse when the agent completes so the
  active agent is always the one in view.
- **Bottom tabs:** `Findings` (dataframe, severity-colored, expandable evidence + citation text) ·
  `Response Plan` (markdown, phased — **streams token-by-token as it's written**) · `Compliance`
  (control gap table) · `Raw logs`.
- Cache completed runs per scenario in `st.session_state` **and** to disk so a re-demo is instant and
  can't fail on a bad connection.

### LangSmith
Enabled purely by env (`LANGSMITH_TRACING`, `LANGSMITH_API_KEY`, `LANGSMITH_PROJECT`); zero code
paths depend on it, and the app runs identically with it unset. Tag runs with the scenario id.

---

## Build order (≈8.5h)

| # | Block | Time |
|---|---|---|
| 1 | Scaffold, `requirements.txt`, `.env`, **build + test the model-independent JSON parser** | 0:45 |
| 2 | Author the knowledge base + 2 scenario datasets | 1:15 |
| 3 | `rag/` — ingest, build script, retrieval smoke test | 0:45 |
| 4 | `state.py`, `llm.py`, Log Monitor + Threat Intel end to end | 1:30 |
| 5 | Vuln Scanner, Policy Checker, Incident Response | 1:15 |
| 6 | Supervisor + graph assembly + guardrails; `run_cli.py` green on both scenarios | 1:00 |
| 7 | Streamlit dashboard + streaming trace | 1:30 |
| 8 | Prompt tuning against `meta.json` expectations, README, demo script, dry run | 0:45 |

Blocks 1 and 3 are the gates — if OpenRouter structured output or retrieval isn't solid, everything
downstream wobbles. `run_cli.py` exists so the graph can be debugged without Streamlit in the loop.

---

## Verification

1. `python scripts/build_kb.py` → prints per-collection doc/chunk counts, non-zero for all five.
2. Retrieval smoke test: query `"log4j jndi rce"` against `cve` returns CVE-2021-44228 as top hit;
   `"repeated failed password"` against `detections` returns the brute-force rule.
3. `python run_cli.py --scenario ssh_bruteforce` → non-empty findings, every citation id resolves to
   a real chunk, plan is non-empty, agent visit order printed.
4. Same for `--scenario log4shell` → Threat Intel names CVE-2021-44228, Vuln Scanner flags the
   vulnerable dependency from `requirements.txt`.
5. Each scenario's `meta.json` lists expected finding keywords; `run_cli.py --check` asserts they
   appear — a poor man's eval, and it catches prompt regressions during tuning.
6. `streamlit run app.py` → run both scenarios, confirm chips animate, all four tabs populate,
   citations expand to real KB text. Specifically for streaming: first trace line on screen in under
   a second, supervisor reasoning and the incident-response plan both visibly typing out, no frozen
   spinner at any point, and findings appearing per-agent rather than all at the end.
7. Unset `LANGSMITH_*` and rerun to confirm the app is unaffected.
8. **Model independence:** run `run_cli.py --scenario log4shell` twice with two different
   `OPENROUTER_MODEL` values (one weak/cheap, one strong) — both must complete with valid findings.
   Plus a unit test feeding the parser fenced JSON, JSON-with-prose, and malformed JSON.
9. **Loop policy:** set `SUPERVISOR_MAX_ITERATIONS=2` and confirm the run still terminates through
   `incident_response`; confirm a `meta.json`-declared limit overrides the default and that a value
   above 12 is clamped.

---

## Risks

- ~~Structured output on OpenRouter~~ — removed as a risk by the model-independent JSON path above;
  no agent depends on tool-calling or `response_format` support. Residual risk is only *quality*
  (a weak model producing thin findings), not breakage. Block 1 verifies the parser against whatever
  model is in `.env`, including a deliberately malformed response.
- **Latency** — 5 agents × 1 LLM call is 40–90 s per run. **Solved by streaming**: the run is fully
  streamed at both the graph and token level (see *Streaming* below), so the UI is never blank and
  the judge is reading output within a second or two of clicking Run. Total wall-clock is unchanged;
  perceived latency is what matters in a demo. Disk cache is a secondary backstop for re-demos.
- **Supervisor loops** — policy comes from prompt/scenario config when supplied, otherwise the
  built-in defaults; either way the code enforces it and the absolute cap can't be raised past 12.
- **Synthetic logs that are too easy** — the agents will look trivially smart. Keep some noise in the
  data (legitimate failed logins, ordinary 404s) so triage looks like judgment rather than grep.

## Explicitly out of scope for Phase 1

Live NVD/OTX lookups · real `trivy`/`pip-audit` execution · human-in-the-loop approval before
remediation · benign control scenario · auth/multi-user · persistence beyond the run cache.
