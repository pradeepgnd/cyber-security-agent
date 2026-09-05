# How the Cybersecurity Multi-Agent SOC Works

A supervisor-orchestrated LangGraph. One **supervisor** node routes to five
**specialist** nodes over a local Chroma RAG knowledge base. Every specialist
runs the same shape: deterministic pre-step → RAG retrieve → one LLM call →
citation filter. Results accumulate in a shared `SecurityState`. The run ends
when `incident_response` has produced a phased remediation plan.

---

## 1. Entry points and the run lifecycle

```mermaid
flowchart TD
    subgraph Entrypoints
        UI["app.py<br/>Streamlit dashboard"]
        CLI["run_cli.py<br/>headless"]
    end

    UI --> CacheChk{"disk cache hit?<br/>(data/cache/&lt;scenario&gt;.json)"}
    CLI --> CacheChk
    CacheChk -- yes, and not ignored --> Replay["render cached run<br/>(instant replay)"]
    CacheChk -- no / ignore cache --> Load["load_scenario()<br/>read meta.json + logs + artifacts<br/>from data/scenarios/&lt;id&gt;/"]

    Load --> Init["initial_state()<br/>seed SecurityState"]
    Init --> Build["build_graph()<br/>compile StateGraph + MemorySaver"]
    Build --> Stream["graph.stream(state, stream_mode=<br/>updates + messages + custom)"]

    Stream --> Consume["consumer renders 3 streams:<br/>• custom  -> trace lines / status chips<br/>• messages -> token stream (supervisor reason, IR plan)<br/>• updates -> findings, agent_log, visited, plan"]
    Consume --> Save["save_run() -> data/cache/&lt;scenario&gt;.json"]
    Save --> Done(["findings + compliance table + risk score + plan"])

    Replay --> Done
```

Key files: `app.py` / `run_cli.py` (drivers), `src/scenarios.py` (loader),
`src/cache.py` (disk replay), `src/graph.py` (graph assembly).

---

## 2. The supervisor loop (the LangGraph)

```mermaid
flowchart TD
    START((START)) --> SUP[supervisor_node]

    SUP -->|route_next reads state.next_agent| ROUTE{next_agent?}

    ROUTE -->|log_monitor| LM[log_monitor_node]
    ROUTE -->|threat_intel| TI[threat_intel_node]
    ROUTE -->|vuln_scanner| VS[vuln_scanner_node]
    ROUTE -->|policy_checker| PC[policy_checker_node]
    ROUTE -->|incident_response| IR[incident_response_node]
    ROUTE -->|FINISH| END((END))

    LM --> SUP
    TI --> SUP
    VS --> SUP
    PC --> SUP
    IR --> SUP

    classDef hub fill:#2563eb,color:#fff,stroke:#1e3a8a;
    classDef spoke fill:#eef2ff,color:#1e293b,stroke:#6366f1;
    class SUP hub;
    class LM,TI,VS,PC,IR spoke;
```

- Wiring is a **hub-and-spoke**: `START → supervisor`, a conditional edge from
  `supervisor` to any specialist or `END`, and every specialist has a fixed
  edge back to `supervisor` (`src/graph.py:30-50`).
- State fields `findings`, `agent_log`, `visited` are `Annotated[..., operator.add]`
  reducers, so each specialist's return is **appended**, not overwritten
  (`src/state.py:64-77`).
- `MemorySaver` checkpointer keyed by `thread_id = scenario_id`.

---

## 3. How the supervisor decides (code-enforced policy, then LLM)

The LLM never gets the final say — code narrows the choice to a legal set first,
and overrides an illegal or premature pick.

```mermaid
flowchart TD
    A["supervisor_node()"] --> B["RoutingPolicy.resolve(scenario_meta)<br/>max_iterations (def 8, cap 12)<br/>max_visits_per_agent (def 1)<br/>required_agents, terminal_agent=incident_response"]
    B --> C["iterations += 1"]

    C --> D{terminal agent<br/>already visited?}
    D -- yes --> FIN["finish -> FINISH"]
    D -- no --> E{iterations >=<br/>max_iterations?}
    E -- yes --> F["force incident_response<br/>(or FINISH if it already ran)"]
    E -- no --> G["_legal_choices():<br/>drop agents at visit cap;<br/>drop incident_response if no findings yet;<br/>if IR visited -> only FINISH"]

    G --> H{any legal<br/>choices?}
    H -- no --> I["force terminal agent if findings,<br/>else FINISH"]
    H -- yes --> J["LLM call: structured(RoutingDecision, PROMPT)<br/>prompt lists legal choices + policy + findings"]

    J --> K{parse ok?}
    K -- no --> L["fallback = legal[0]"]
    K -- yes --> M{choice legal?}
    M -- no --> N["re-ask once with choice blocked;<br/>still bad -> legal[0]"]
    M -- yes --> O{choice == FINISH<br/>but IR not run?}
    O -- yes --> P["route to incident_response<br/>(or legal[0] if still no findings)"]
    O -- no --> Q["emit trace, set next_agent = choice"]

    L --> Q
    N --> Q
    P --> Q
    F --> Q
    I --> Q
    Q --> R["return {next_agent, routing_reason, iterations}"]
```

Source: `src/supervisor.py` — `RoutingPolicy.resolve` (23-62),
`_legal_choices` (96-108), `supervisor_node` (111-198), `route_next` (201-207).
Guarantees: `incident_response` runs only after ≥1 finding, runs **last**, each
specialist runs at most `max_visits_per_agent` times, and the run is bounded by
`max_iterations`.

---

## 4. Inside a specialist node (shared shape)

All of `log_monitor`, `threat_intel`, `vuln_scanner`, `policy_checker` follow
`src/agents/common.py`. `incident_response` is a variant that streams markdown
instead of parsing JSON.

```mermaid
flowchart LR
    IN["SecurityState<br/>(raw_logs, artifacts, findings so far)"] --> PRE

    subgraph PRE["1. Deterministic pre-step (no LLM)"]
        direction TB
        p1["log_monitor: parse_logs() regex -> ParsedEvent[]"]
        p2["threat_intel: regex-extract CVE ids + IP IOCs from prior findings"]
        p3["vuln_scanner: scan_artifacts() + match_cves() vs local CVE table"]
        p4["policy_checker: bucket prior findings into categories"]
    end

    PRE --> QRY["2. Build a query string<br/>(keyword-branch: log4shell/jndi vs brute-force)"]
    QRY --> RET["3. retrieve() / retrieve_many()<br/>Chroma similarity search on one/more collections<br/>-> (text, chunk_id, score) triples"]
    RET --> LLM["4. run_llm_findings():<br/>structured(FindingBatch, PROMPT, context=retrieved)<br/>one LLM call, JSON parsed from text + 1 repair retry"]
    LLM --> SAN["5. sanitize_findings():<br/>assign id + agent, clamp confidence,<br/>DROP any citation not in retrieved chunk ids"]
    SAN --> OUT["return done_update():<br/>findings[] , visited=[agent] , agent_log=[step]"]

    OUT --> BACK(["back to supervisor"])
```

- **Retrieval is scoped per collection**: `cve`, `mitre`, `controls`,
  `runbooks`, `detections` (`src/config.py:20`). Each agent queries the
  collection(s) relevant to its job.
- **Citations can't be hallucinated**: `sanitize_findings` keeps only chunk ids
  that were actually retrieved (`src/agents/common.py:37-58`), and
  `--check` / the UI re-resolve every id against Chroma via `resolve_chunk`.
- **Model-agnostic structured output**: `src/llm.py` renders Pydantic format
  instructions into the prompt, extracts the outermost `{...}` from the reply,
  validates, and does exactly one repair round-trip on failure. No tool-calling,
  no `response_format` on the demo path.

---

## 5. Incident Response node (terminal)

```mermaid
flowchart TD
    A["incident_response_node()"] --> B["compute_risk_score(findings)<br/>severity weight x confidence, x3, capped 100"]
    B --> C["keyword-branch query -> retrieve('runbooks', k=5)"]
    C --> D["stream_text(PROMPT, ...)<br/>token-streamed MARKDOWN plan<br/>## Contain / ## Eradicate / ## Recover / ## Harden"]
    D --> E{plan non-empty?}
    E -- no --> F["failed_step()"]
    E -- yes --> G["emit summary Finding 'ir-plan'<br/>citations = runbook ids that appear in the plan text"]
    G --> H["done_update(final_plan=plan, risk_score=risk)"]
    H --> I(["supervisor -> FINISH next hop"])
```

Source: `src/agents/incident_response.py`.

---

## 6. Knowledge base build (offline, one-time)

```mermaid
flowchart LR
    MD["data/kb/**/*.md<br/>cve · mitre · controls · runbooks · detections"] --> ING["scripts/build_kb.py<br/>-> src/rag/ingest.rebuild_collections()"]
    ING --> CHUNK["chunk + embed<br/>ONNX MiniLM (all-MiniLM-L6-v2, ~80MB, downloaded once)"]
    CHUNK --> CHROMA[("data/chroma/<br/>5 persistent collections")]
    CHROMA --> RET["src/rag/retrievers.retrieve()<br/>used by every specialist at run time"]
```

`--smoke` asserts `CVE-2021-44228` is a top hit for "log4j jndi rce" and a
brute-force rule is a top hit for "repeated failed password".

---

## 7. End-to-end example: `ssh_bruteforce` scenario

```mermaid
sequenceDiagram
    participant D as Driver (app/CLI)
    participant S as Supervisor
    participant LM as Log Monitor
    participant TI as Threat Intel
    participant PC as Policy Checker
    participant IR as Incident Response
    participant KB as Chroma KB

    D->>S: initial_state(scenario, syslog, meta)
    S->>S: policy: required=[...], terminal=incident_response
    S-->>LM: route (no findings yet)
    LM->>LM: parse_logs() -> brute_force + success_after_failures events
    LM->>KB: retrieve("detections", "repeated failed password ...")
    LM-->>S: findings[T1110 brute force, T1078 valid-account login]
    S-->>TI: route (prefer required, not yet run)
    TI->>KB: retrieve_many(cve + mitre)
    TI-->>S: findings[map to T1110 / T1078 / T1021.004]
    S-->>PC: route
    PC->>KB: retrieve("controls", "AC-7 AU-6 SI-4 ...")
    PC-->>S: findings[AC-7 FAIL, AU-6 PARTIAL, SI-4 ...]
    S-->>IR: route (>=1 finding, still not run)
    IR->>IR: compute_risk_score()
    IR->>KB: retrieve("runbooks", "brute force credential rotation ...")
    IR-->>D: streamed markdown plan (Contain/Eradicate/Recover/Harden)
    IR-->>S: final_plan + risk_score
    S-->>D: FINISH
```

(`vuln_scanner` is the analogous required agent on the `log4shell` scenario,
where it flags `log4j-core@2.14.1` from `requirements.txt` / the `Dockerfile`.)

---

## State object passed between every node

| Field | Written by | Reducer | Purpose |
|---|---|---|---|
| `raw_logs`, `artifacts`, `scenario_meta` | `initial_state` | replace | scenario inputs |
| `findings` | every specialist | **append** | citation-backed findings list |
| `agent_log` | every specialist | **append** | per-step status + latency + retrieved ids (trace) |
| `visited` | every specialist | **append** | drives visit-cap + terminal-agent policy |
| `next_agent`, `routing_reason`, `iterations` | supervisor | replace | routing decision for `route_next` |
| `final_plan`, `risk_score` | `incident_response` | replace | terminal output |

Defined in `src/state.py:64-77`.
