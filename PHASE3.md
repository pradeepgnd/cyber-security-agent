# Phase 3 Plan — Analyst-supplied input

## Context

Phase 1 (`PLAN.md`) built the architecture: a supervisor routing five specialists over a local
Chroma corpus, model-independent structured output, a streamed Streamlit trace. Phase 2
(`PHASE2.md`) added the live-enrichment sidecar behind a TTL cache.

Phase 3 is one change: **the UI accepts any text file.**

Today the app can only run the two bundled scenarios under `data/scenarios/`. An analyst cannot
point it at their own `auth.log`, and the demo cannot answer "does this work on *my* data?" — the
first question anyone asks. Phase 3 adds an upload path that produces the same in-memory bundle a
bundled scenario produces, so nothing downstream of `initial_state` knows or cares where the data
came from.

The graph, the agents, the supervisor and the knowledge base are all untouched.

### Decisions locked in

| Area | Choice |
|---|---|
| Upload storage | **In memory for the run only.** Uploads are not written into `data/scenarios/`; only the completed run is cached |
| File classification | **Detect manifests, default to log** — the inverse of today's rule (see Loader) |
| Run id for uploads | `upload-<sha1 of sorted name+content>[:8]` — deterministic, so the same upload replays from cache, and namespaced away from bundled ids |
| Loader location | `src/scenarios.py`, beside `load_scenario` — not in `app.py`, so it is unit-testable without Streamlit |
| CLI | Unchanged. `run_cli.py` and `scripts/warm_cache.py` keep calling `load_scenario`; a `--file` flag is a later convenience |
| Deferred to Phase 4 | Supervisor routing fixes (including the precondition gate), `intel_live` Chroma ingestion, the approval gate, a benign control scenario |

---

## Architecture

```
   ┌── bundled ──►  data/scenarios/<id>/  ──► load_scenario(id) ──┐
   │                                                              │   {scenario_id, meta,
   │                                                              ├──►  raw_logs, artifacts}
   └── uploaded ─►  st.file_uploader      ──► load_uploaded(fs) ──┘            │
                                                                               ▼
                                                                       initial_state()
                                                                               │
                                                                               ▼
                                                              supervisor + 5 specialists
                                                                     (unchanged)
```

Both input paths converge on the same bundle shape. That is the whole design — the new code is a
second producer of an existing contract, not a new path through the graph.

---

## Loader (`src/scenarios.py`)

Add `load_uploaded(files) -> dict` returning the same shape as `load_scenario`:
`scenario_id`, `meta`, `raw_logs`, `artifacts`.

**Classification is inverted.** Today the rule is "is the name a known log?" then `raw_logs`, else
`artifacts`:

```python
if path.name in LOG_NAMES or path.suffix == ".log":
    raw_logs[path.name] = text
else:
    artifacts[path.name] = text
```

For arbitrary input that is the wrong question — a user's `messages.txt` would land in `artifacts`
and be handed to the dependency scanner. Detect **manifests** instead and default everything else
to a log:

```python
MANIFEST_NAMES = {"requirements.txt", "pom.xml", "package.json", "go.mod",
                  "gemfile", "pipfile", "build.gradle", "cargo.toml"}
MANIFEST_SUFFIXES = {".csproj", ".gradle"}

def _is_manifest(name: str) -> bool:
    low = name.lower()
    return (low in MANIFEST_NAMES
            or "dockerfile" in low
            or any(low.endswith(s) for s in MANIFEST_SUFFIXES))
```

This matches what the tools already assume: `depscan.scan_artifacts` has an `else` branch that
tries both the requirements and Dockerfile parsers on an artifact name it does not recognise, so an
unfamiliar manifest still gets a real attempt.

Caps: **10 files, 2 MB each**, decoded as `utf-8` with `errors="replace"` — mirroring
`load_scenario`'s `read_text(errors="replace")`.

Synthesised meta, so the supervisor prompt still has a scenario line:

```python
{"summary": f"{len(files)} uploaded file(s): {', '.join(names)}"}
```

No `required_agents`, no `expected_keywords`, no `cache` block — `RoutingPolicy.resolve({})` and
`CachePolicy.resolve({})` both fall back to their built-in defaults, which is correct for input
nobody has curated.

---

## Parser fallback (`src/tools/log_parse.py`)

`parse_logs` dispatches purely on filename:

```python
if "auth" in lower or lower == "syslog" or "secure" in lower:   _parse_auth
if "nginx" in lower or "access" in lower:                       _parse_nginx
if "app" in lower or lower.endswith(".log"):                    _parse_app
```

An uploaded `mylog.txt` or `server-events` matches none of the three, yields zero events, and
`log_monitor` reports nothing. **Without a fallback the entire upload feature is inert for any log
not named like the bundled ones.**

When no branch matches, run all three. `_parse_app` already early-returns for auth/nginx names, and
`_dedupe` keys on `(kind, summary)`, so the overlap is safe.

---

## Run id and cache (`src/cache.py`)

Uploads get `scenario_id = f"upload-{sha1(sorted name+content).hexdigest()[:8]}"` — deterministic,
so re-uploading the same files replays from the run cache instead of paying for a fresh run, and
namespaced so an upload can never collide with a bundled scenario.

Independently: `cache_path` builds `CACHE_DIR / f"{scenario_id}.json"` with no sanitising. That is
safe today because ids come from directory names, but it becomes a path-traversal vector the moment
an upload derives the id. Harden it with the allowlist pattern already in
`src/live/cache.py::_safe_key` (regex match, else sha1).

---

## `app.py`

- **Sidebar**: `st.radio("Input", ["Bundled scenario", "Upload files"])`. The upload branch shows
  `st.file_uploader(accept_multiple_files=True)` and a small table of the classification result
  (`file` then `log | artifact`), so a misfiled upload is visible *before* running rather than
  inferred from a confusing result.
- **Refactor `run_live(scenario_id, …)` to `run_live(bundle, …)`.** It currently calls
  `load_scenario(scenario_id)` itself (line 173), and the main flow calls it three more times
  (lines 355, 365, 372) purely to backfill `raw_logs` for the Raw logs tab. An upload has no folder
  to re-read, so all four become `bundle["raw_logs"]`. `run_live` has exactly one caller (line 371),
  so the refactor is contained; `run_cli.py` and `scripts/warm_cache.py` keep using `load_scenario`
  unchanged.
- The Run button's `disabled` condition becomes "no bundled scenario selected **and** no files
  uploaded".

Uploaded content reaches the model the same way bundled log content already does — as parsed event
summaries and evidence lines, never as raw text — and `sanitize_findings` still drops any citation
id the model invents. Treat uploaded text as data, not instructions.

---

## Files touched

| File | Change |
|---|---|
| `src/scenarios.py` | `load_uploaded`, manifest classifier |
| `src/tools/log_parse.py` | unknown-filename fallback in `parse_logs` |
| `src/cache.py` | `_safe_key` on `cache_path` |
| `app.py` | input radio, uploader, classification table, `run_live(bundle, …)` refactor |
| `tests/test_uploads.py` | new |
| `tests/test_tools.py` | extend |

## Testing (all offline, no API key)

| File | Covers |
|---|---|
| `tests/test_uploads.py` | manifest vs log classification incl. `Dockerfile.prod`, `mylog.txt`, `messages.txt`; id is deterministic for identical content and differs for different content; size and count caps reject; `cache_path` with a traversal id stays inside `CACHE_DIR` |
| `tests/test_tools.py` | extend: `parse_logs` on a dict keyed `mylog.txt` holding brute-force lines still finds `brute_force` — the regression lock for the fallback |

## Verification

1. `pytest -q` — all green, including the two files above.
2. `python run_cli.py --scenario ssh_bruteforce --check --no-cache` and
   `--scenario log4shell --check --no-cache` — both still CHECK PASSED. The CLI path is untouched;
   this is the regression guard for the `load_scenario` refactor.
3. `streamlit run app.py`, **Bundled scenario** — both scenarios behave exactly as before,
   including disk-cache replay.
4. Same app, **Upload files** — upload a copy of `data/scenarios/ssh_bruteforce/auth.log` renamed to
   `mylog.txt`. The classification table shows it as a log; `log_monitor` still finds the brute
   force; the run caches under an `upload-…` id and replays instantly on a second upload of the
   same file.
5. Upload `data/scenarios/log4shell/requirements.txt` alone — classified as artifact,
   `vuln_scanner` flags `log4j-core@2.14.1`.
6. Upload a 3 MB file, and separately 11 files — each rejected with a clear message, no run started.
7. `git status --short` shows only the intended files.

## Build order (≈1:30)

| # | Block | Time |
|---|---|---|
| 1 | `load_uploaded` + manifest classifier + `parse_logs` fallback + `cache_path` hardening + tests | 0:45 |
| 2 | `app.py` — radio, uploader, classification table, `run_live(bundle, …)` refactor | 0:45 |

Block 1 is the gate: it is fully testable headlessly, so the Streamlit wiring in block 2 lands on a
loader that is already proven.

## Risks

- **No precondition gate.** Supervisor routing is out of scope, so an agent with no input still
  runs: upload a manifest alone and `log_monitor` calls `parse_logs({})`, gets no events, and the
  "(no suspicious events…)" string becomes its retrieval query — an LLM call goes out anyway.
  `vuln_scanner` behaves the same on a logs-only upload and, per its own prompt, emits one info
  finding. Cost is one supervisor hop plus one specialist call, and a possible filler finding; the
  run still completes correctly. This is why a `PRECONDITIONS` map in `_legal_choices` is the
  natural first follow-up.
- **Misclassified upload** — a log named `package.json`, or a manifest named `deps.txt`, lands on
  the wrong side. Mitigation: the sidebar table shows the classification before the run, so it is
  visible and the fix is a rename. Not worth per-file override widgets at this stage.
- **Upload quality** — an arbitrary file may produce no events and thin findings. That is the honest
  result, not a bug. The Raw logs tab shows what was actually ingested so the user can see why.
- **`run_live` refactor touching the bundled path** — the same function serves both inputs, so a
  mistake breaks the working demo. Mitigation: verification step 2 runs the CLI (which does not use
  `run_live`) and step 3 re-runs both bundled scenarios in the UI before any upload is attempted.

## Explicitly out of scope for Phase 3

Supervisor routing changes, including the `PRECONDITIONS` gate and `required_agents` enforcement ·
writing uploads into `data/scenarios/` for reuse · per-file log/artifact override in the UI ·
`--file` on `run_cli.py` · binary, archive, or PCAP input · `intel_live` Chroma ingestion ·
the human-in-the-loop approval gate · a benign control scenario · Redis cache backend.
