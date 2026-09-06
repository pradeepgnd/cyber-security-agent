# Phase 4 Plan — GitHub issue tracking

## Context

Phase 1 (`PLAN.md`) built the architecture: a supervisor routing five specialists over a local
Chroma corpus, with a citation on every finding. Phase 2 (`PHASE2.md`) added live threat-intel
enrichment behind a TTL cache. Phase 3 (`PHASE3.md`) let the UI run on analyst-supplied files
instead of only the two bundled scenarios.

All three phases end at the same place: a report on screen. The remediation plan is the output
nobody acts on, because acting means retyping it into a tracker.

Phase 4 files it instead — a parent incident issue plus one issue per finding, in the repo the
project already lives in.

GitHub rather than a dedicated tracker is the right call here for three concrete reasons:

- **The body is plain Markdown.** `final_plan` is *already* markdown — contain/eradicate/recover/
  harden headings and all. It posts verbatim. Jira Cloud's v3 API would need every description
  converted to ADF, a nested JSON document format.
- **Zero new infrastructure.** The repo is `pradeepgnd/cyber-security-agent`. No second SaaS
  account, no separate project to provision, and a scratch repo makes a safe demo target.
- **Least privilege is the default.** A fine-grained PAT scoped to one repository with
  `Issues: Read and write` is the whole credential surface.

The graph, the agents, the supervisor and the knowledge base are untouched. This is a post-run
action on the `result` dict.

### Decisions locked in

| Area | Choice |
|---|---|
| Integration point | **Post-run action on `result`**, not a graph node and not an LLM tool. `PLAN.md` forbids tool-binding, and firing irreversible POSTs mid-stream is exactly what an approval gate exists to prevent. Mirrors how `save_run()` is called after the stream completes |
| Tracker | **GitHub Issues** via the REST API, `POST /repos/{owner}/{repo}/issues`. Markdown bodies, no format conversion |
| Auth | Fine-grained PAT, `Authorization: Bearer <token>`, scoped to one repo with `Issues: Read and write`. `GITHUB_API_URL` is overridable so GitHub Enterprise Server (`https://host/api/v3`) is a config change |
| Hierarchy | **Parent incident issue + one child issue per finding**, linked by a markdown task list in the parent body. GitHub renders that as tracked tasks with progress and adds "tracked by" backlinks automatically — no sub-issues API, works on every plan tier |
| Severity | **Labels** (`severity:critical`, `severity:high`, …), not a priority field. GitHub has no priority, and labels are the idiomatic equivalent |
| Severity colours | **CVSS / NVD ramp** — the colours NVD renders on CVE pages. Defined once as `SEVERITY_COLORS` in `src/config.py` and consumed by both the GitHub label bootstrap and the Streamlit tables, so the two cannot drift |
| Default | `GITHUB_ENABLED=false` plus a **dry run** that renders payloads and posts nothing — mirrors `CACHE_MODE=frozen`, keeps the demo working with no token, and stays testable under `tests/conftest.py`'s network block |
| Granularity | One parent, plus a child per finding at or above `GITHUB_MIN_SEVERITY`. Makes "a single issue" and "file everything" both reachable without a code change |
| Deferred to Phase 5 | Analyst follow-up chat, supervisor routing fixes, the approval gate, an eval harness, ATT&CK Navigator export, SARIF/STIX, Jira/ServiceNow/TheHive/Slack |

---

## Architecture

```
   graph.stream(...) ──► result {findings, final_plan, risk_score, visited, …}
                              │
                              ├──► save_run()                          (existing)
                              │
                              └──► src/integrations/github_issues.py   NEW
                                     build_parent_payload(result)
                                     build_finding_payload(finding, parent)
                                     build_task_list(child_numbers)
                                     file_incident(result, dry_run)
                                        → request_json("github", …)
                                        → result["github"] = {…} → save_run()
```

The filer reads a finished `result` and writes its issue numbers back into it, so re-filing is
idempotent. Nothing is written into graph state.

Pure mapping is split from network orchestration so the payload logic is unit-testable offline:

```
build_parent_payload(result) -> dict                        pure
build_finding_payload(finding, parent_number) -> dict        pure
build_task_list(child_numbers) -> str                        pure
file_incident(result, *, dry_run=False) -> dict              orchestration
```

---

## Mapping

| Source | GitHub field |
|---|---|
| `run_id` + `risk_score` | parent issue title |
| `final_plan` | parent issue body — **markdown, posted verbatim** |
| `Finding.title` | child issue title, truncated to 256 chars |
| `description` + `evidence` + `recommended_action` + `citations` | child issue body |
| `Finding.severity` | `severity:<level>` label, coloured from `SEVERITY_COLORS` |
| MITRE tags | labels, plus a constant `soc-agent` label and `incident:<run_id>` |

Applying a label that does not exist creates it with a *random* colour, which is why the severity
labels are bootstrapped explicitly — see the next section.

---

## Severity colour coding

Severity is the one field a triager scans first, and today it is plain text everywhere: the findings
table at [app.py:137](app.py:137) and the Compliance table at [app.py:172](app.py:172) both render
it as a bare string, and the only colour in the app is `CHIP_COLORS` for agent status.

### The ramp

| Severity | Hex | Reads as |
|---|---|---|
| `critical` | `#CC0500` | dark red |
| `high` | `#DF3D03` | orange-red |
| `medium` | `#F9A009` | amber |
| `low` | `#FFCB0D` | yellow |
| `info` | `#6C757D` | grey |

This is the ramp NVD renders on CVE pages, so it reads correctly to anyone who has looked at a CVSS
score — and the Vuln Scanner is already surfacing those scores through the Phase 2 enrichment.

### Single source of truth

`SEVERITY_COLORS: dict[str, str]` in `src/config.py`, keyed by the five `Severity` literals from
[src/state.py:10](src/state.py:10). Stored **with** the leading `#`, matching the existing
`CHIP_COLORS` convention in `app.py`.

The GitHub labels API wants 6-hex **without** the `#`, so the filer strips it at the boundary
(`color.lstrip("#")`). One canonical definition, one conversion, no second copy to drift.

### GitHub side — `ensure_labels()`

`POST /repos/{repo}/labels` with `{"name": "severity:critical", "color": "CC0500", "description":
"SOC agent severity"}`. Called once at the start of `file_incident`, guarded by a module-level flag
so it does not repeat per issue, and skipped entirely in dry run.

**This is where block 1 changes behaviour the feature depends on.** GitHub answers a duplicate label
with **422 `already_exists`**. Block 1's retry-predicate fix makes 422 fail *fast* rather than being
retried three times — correct in general, but it means `ensure_labels` receives a prompt exception
on every run after the first. It must catch that specific 422 and fall through to
`PATCH /repos/{repo}/labels/{name}`, which both silences the expected duplicate and re-syncs the
colour if someone edited it by hand. Letting the 422 propagate would break filing entirely on the
second run.

### UI side — two surfaces, two techniques

The findings tab has a summary table and per-finding expanders, and they cannot use the same
mechanism:

| Surface | Technique |
|---|---|
| `st.dataframe` at [app.py:137](app.py:137), and the Compliance table at [app.py:172](app.py:172) | pandas `Styler` — `st.dataframe(df.style.map(_sev_style, subset=["severity"]))`. Use `.map`, **not** `.applymap`, which pandas deprecated in 2.1 |
| `st.expander(f"[{severity}] {title}")` | a `_severity_badge(severity) -> str` helper mirroring the existing `_chip_html`, rendered with `st.markdown(..., unsafe_allow_html=True)` |

### Contrast

`#FFCB0D` (low) and `#F9A009` (medium) are light swatches — white text on them is unreadable.
GitHub computes label text colour from background luminance automatically, so the label side needs
nothing. The Streamlit badges do: add a `_text_on(hex) -> str` helper using the standard
relative-luminance threshold so light backgrounds get dark text. Without it two of the five levels
are illegible in the UI, which is worse than no colour at all.

### Dependency note

Colouring the dataframe imports pandas directly. It is present today only transitively via
Streamlit, so add `pandas>=2.1` to `requirements.txt` rather than relying on another package's
dependency tree.

---

## Filing order

Parent first, then children, then PATCH the parent body with the task list:

1. `POST /issues` → parent, body = the plan, no task list yet.
2. For each qualifying finding: `POST /issues` → child, body ends with `Part of #<parent>`.
3. `PATCH /issues/<parent>` → append `- [ ] #<child>` lines.

The alternative — children first, then a parent that lists them — is one call cheaper but leaves
orphaned children if the parent POST fails. Parent-first means every child is discoverable through
its own `Part of #N` reference even if the final PATCH never happens. GitHub also adds "tracked by"
backlinks automatically once the task list lands.

## Idempotency

Runs are cached and replayed, so re-filing must not duplicate. The dedup key is
`sha1(run_id + finding.title + finding.agent).hexdigest()[:12]` — **not** `Finding.id`, which is
LLM-generated and not stable across runs.

Created numbers are written back and re-saved:

```python
result["github"] = {"repo": "owner/name", "parent": 41, "issues": {dedup_key: 42, …}}
save_run(run_id, result)
```

Any finding already in `result["github"]["issues"]` is skipped on a re-file.

As a recovery path when the local cache is lost, each body ends with an HTML comment marker:

```markdown
<!-- soc-agent-key: 9f2a1c4b8e01 -->
```

It is invisible in rendered markdown and findable via
`GET /search/issues?q=repo:owner/name+"9f2a1c4b8e01"+in:body`. Search is eventually consistent and
separately rate-limited (30 req/min), so it is a fallback, never the primary check.

## Partial failure

Three children created and then a secondary rate limit: record what succeeded into
`result["github"]`, report what did not, and let the user re-run to resume. A GitHub outage must
never crash the app or lose the run.

## Injection containment

Finding text is LLM-generated from user-uploaded logs — Phase 3 shipped, so that input is now
genuinely arbitrary. Finding-derived text may populate **only** `title`, `body` and `labels`.
`repo`, `assignees` and `milestone` come from config alone, so a log line reading *"assign this to
@admin"* cannot do anything.

An `@mention` inside a body would still notify a real person, so bodies pass through a
mention-defusing step (`@name` → `` `@name` ``) before posting.

## Config

New block in `src/config.py` and `.env.example`:

```
GITHUB_ENABLED=false
GITHUB_API_URL=https://api.github.com      # https://<host>/api/v3 for Enterprise Server
GITHUB_REPO=pradeepgnd/cyber-security-agent
GITHUB_TOKEN=                              # fine-grained PAT, Issues: Read and write
GITHUB_MIN_SEVERITY=high                   # critical | high | medium | low | info
```

Required request headers: `Accept: application/vnd.github+json` and
`X-GitHub-Api-Version: 2022-11-28`.

## Wiring

- `app.py`: a **File to GitHub** button that first shows a preview — *"about to create 1 parent and
  4 child issues in pradeepgnd/cyber-security-agent"* — with the rendered markdown, and only posts
  on a second click. That preview is the consent point for sending log-derived data to GitHub.
- `run_cli.py`: `--github` and `--github-dry-run`, added beside the existing flags at
  [run_cli.py:159](run_cli.py:159).

---

## Shared HTTP fix (`src/live/http.py`) — required, not optional

`request_json` ([src/live/http.py:55](src/live/http.py:55)) cannot serve a write API as written.

**Non-retryable 4xx are retried.** At [lines 88–93](src/live/http.py:88), `raise_for_status()`
raises `HTTPError`, which is a `RequestException`, so it is caught and backed off. A bad token (401)
or a validation error (422 — a malformed label, or Issues disabled on the repo) would be retried
three times and then surfaced as a generic `"github: request failed"`. Undebuggable exactly when the
message matters most.

**403 is ambiguous on GitHub**, unlike anywhere in Phase 2:

| 403 flavour | Retryable? | Signal |
|---|---|---|
| Secondary rate limit | **yes** | `Retry-After` header, or `x-ratelimit-remaining: 0` |
| Insufficient token scope | **no** | neither header present |

So the retry predicate is: retry 408, 429, 5xx, and 403 *only when* a rate-limit signal is present.
Everything else surfaces immediately with the response body in the message.

**404 means "not found or no access."** GitHub returns 404 rather than 403 for a private repo the
token cannot see, to avoid leaking existence. `request_json` currently raises `LiveNotFound` on 404;
the GitHub caller must render that as *"repo not found, or the token lacks access"* rather than a
bare "not found".

**Rate interval.** GitHub asks for roughly one second between mutative requests. Add
`"github": 1.0` to `_RATE_INTERVALS` ([line 17](src/live/http.py:17)).

**204 No Content.** Add `allow_empty: bool = False` so a 204 returns `{}` instead of raising
`ValueError` through the retry loop. Not needed for `POST /issues` (201 with a body) but needed the
moment comments or label deletion are added.

All of these also improve the Phase 2 sources, which currently burn three attempts on any permanent
4xx.

---

## Files touched

| File | Change |
|---|---|
| `src/live/http.py` | retry predicate (408/429/5xx + conditional 403); `allow_empty`; `"github"` rate bucket |
| `src/integrations/github_issues.py` | **new** — payload builders, task list, dedup, `file_incident`, `ensure_labels` |
| `src/config.py` | `GITHUB_*` block, `SEVERITY_COLORS` |
| `app.py` | File to GitHub button with preview; `_severity_badge`, `_text_on`, dataframe Styler |
| `run_cli.py` | `--github`, `--github-dry-run` |
| `.env.example` | `GITHUB_*` block |
| `requirements.txt` | `pandas>=2.1` — now a direct import, not just transitive via Streamlit |
| `tests/test_github_issues.py` | **new** |
| `tests/test_live_sources.py` | extend |

## Testing (all offline, no GitHub token)

| File | Covers |
|---|---|
| `tests/test_github_issues.py` | payload mapping incl. 256-char title truncation and severity-to-label; the dedup key is stable across two runs with the same finding and differs when the agent differs; a second `file_incident` on a result that already has `result["github"]` issues zero POSTs; dry run issues zero POSTs; finding text cannot reach `assignees` / `milestone`; `@mention` in a finding body is defused; `build_task_list` renders `- [ ] #N` lines; the `soc-agent-key` marker appears in every body |
| `tests/test_github_issues.py` (colour) | `SEVERITY_COLORS` covers exactly the five `Severity` literals — no missing key, no extra; label payloads carry 6-hex with **no** leading `#`; `ensure_labels` on a 422 `already_exists` issues a `PATCH` rather than raising; `ensure_labels` issues zero requests in dry run; `_text_on("#FFCB0D")` returns a dark colour and `_text_on("#CC0500")` a light one |
| `tests/test_live_sources.py` | extend: 422 raises immediately without retrying; 403 **with** `Retry-After` retries; 403 **without** a rate-limit header raises immediately; 204 with `allow_empty=True` returns `{}` |

Network stays blocked by `tests/conftest.py`; GitHub tests monkeypatch `request_json`.

## Verification

`gh` is not installed on this machine, so verification uses the REST API directly and the web UI.

1. `pytest -q` — all green, including the two files above.
2. `python run_cli.py --scenario ssh_bruteforce --check --no-cache` and `--scenario log4shell …` —
   both still CHECK PASSED. Regression guard: the feature does not touch the graph.
3. `python run_cli.py --scenario log4shell --github-dry-run` — prints one parent payload and N child
   payloads as rendered markdown, plus the five label payloads with **bare-hex** colours (no `#`),
   makes zero network calls, exits 0 with `GITHUB_ENABLED=false`.
4. `streamlit run app.py` → run a scenario → **File to GitHub** with `GITHUB_ENABLED=false` — the
   preview renders the markdown and the post button is disabled with a clear reason.
5. Against a scratch repo with `GITHUB_ENABLED=true`: a parent issue appears with the plan as
   readable markdown, N child issues carry `severity:*` and `soc-agent` labels, the parent shows a
   task list with progress, and each child shows "tracked by" the parent. Click again — nothing is
   duplicated and the UI reports "already filed".
6. The repo's Labels page shows five `severity:*` labels in the NVD ramp. Recolour one by hand in
   the GitHub UI, file again, and confirm the `PATCH` path re-syncs it — this exercises the 422
   `already_exists` branch that every run after the first depends on.
7. The findings table shows a coloured severity column and the per-finding expanders show coloured
   badges. Check specifically that `low` and `medium` rows are legible — those are the two light
   swatches — in both the light and dark Streamlit themes.
8. Set `GITHUB_TOKEN` to a wrong value — the failure surfaces on the first attempt with GitHub's own
   401 message, not after three retries. Point `GITHUB_REPO` at a nonexistent repo — the error says
   "not found or token lacks access", not a bare 404.
9. `curl -H "Authorization: Bearer $GITHUB_TOKEN" https://api.github.com/repos/<repo>/issues?labels=soc-agent`
   lists exactly the issues the run created.
10. `git status --short` shows only the intended files.

## Build order (≈2:15)

| # | Block | Time |
|---|---|---|
| 1 | `request_json` retry predicate + `allow_empty` + `"github"` rate bucket, extend `test_live_sources.py` | 0:30 |
| 2 | `src/integrations/github_issues.py` payload builders + task list + dedup + dry run + `ensure_labels` + `test_github_issues.py` | 1:00 |
| 3 | File to GitHub button, `run_cli.py` flags, severity badges + dataframe Styler, `.env.example`, README | 0:45 |

Block 1 gates block 2 — the filer is undebuggable without the retry-predicate fix, and
`ensure_labels` depends on 422 failing fast so it can branch to `PATCH`.

## Risks

- **Prompt injection.** Findings derive from uploaded logs and reach the issue body directly.
  Mitigation: finding text may populate only `title`, `body` and `labels`; every control field comes
  from config; `@mention` defusing prevents a log line from notifying a real person.
- **Noise in a real repo.** Filing against the project's own repo mixes SOC findings with
  development issues. Mitigation: `GITHUB_REPO` is explicit config, `GITHUB_MIN_SEVERITY` limits
  volume, the `soc-agent` label makes them filterable, and the docs recommend a scratch repo for
  demos.
- **Outbound data.** Findings contain slices of the user's logs — IPs, usernames, paths — and a
  public repo makes them public. Mitigation: the preview-and-confirm step is an explicit consent
  point, `GITHUB_ENABLED=false` is the default, and the README warns against public repos.
- **No way to fix a bad title before filing.** The analyst can accept or reject the model's wording,
  nothing in between, and an issue is harder to unfile than to not file. Mitigation for now: the
  preview shows the exact text and rejecting is free. Inline editing in that preview is the first
  follow-up.
- **GitHub instance variance.** Issues disabled on the repo (410), required templates, or org
  policies can reject payloads that are valid elsewhere. Mitigation: dry run shows the exact payload
  before any POST, and the 4xx fix surfaces GitHub's own error message.
- **Light-swatch legibility.** `low` (`#FFCB0D`) and `medium` (`#F9A009`) sit on light backgrounds,
  so anything rendering them with default white text makes two of the five levels unreadable —
  worse than no colour at all. Mitigation: `_text_on` picks text colour from background luminance;
  worth an eyeball check in both light and dark Streamlit themes, since the app does not pin one.

## Explicitly out of scope for Phase 4

Inline editing of issue text in the preview · analyst follow-up chat · GitHub App installation auth
(PAT only) · closing, commenting on, or transitioning issues after creation · GitHub Projects boards
· the sub-issues API · Jira, ServiceNow, PagerDuty, TheHive or Slack · supervisor routing changes ·
the approval gate · an eval harness · ATT&CK Navigator, SARIF or STIX export.
