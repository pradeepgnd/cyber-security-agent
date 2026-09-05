# Phase 2 Plan — Live threat-intel enrichment with a configurable TTL cache

## Context

Phase 1 runs entirely on a hand-authored local corpus (~15 CVE markdown records in a persistent
Chroma store). `PLAN.md` defers "live NVD" and "live NVD/OTX lookups" to Phase 2.

Phase 2 adds **live enrichment** for the CVE IDs and package coordinates the agents surface, drawn
from four keyless-or-trivially-keyed sources, behind a **cache-aside layer with configurable TTL**
so demo time never depends on the network.

### Decisions locked in

| Area | Choice |
|---|---|
| Integration pattern | **A1 — enrichment sidecar (hybrid).** Local Chroma retrieval is unchanged; live data augments findings via a deterministic pre-step, not the vector search |
| Sources | **OSV.dev, NVD 2.0 API, CISA KEV, EPSS** |
| Cache backend | **JSON files under `data/cache/live/`**, one file per `(source, key)`, with a `fetched_at` envelope |
| Demo path | `CACHE_MODE=frozen` — cache/fixtures only, never network |
| Vector store | Unchanged — local persistent Chroma (`E1`) |
| Deferred to Phase 3 | Scheduled ingestion into Chroma (A2), GHSA / ThreatFox / GreyNoise, Redis cache, hosted vector DB |

---

## Architecture

```
   findings so far ──► Threat Intel / Vuln Scanner pre-step
                              │  {cve_ids, packages, iocs}
                              ▼
                       src/live/enrich.py ──────────────┐
                              │ fan-out                  │ cache-aside (TTL)
             ┌────────┬───────┼────────┬─────────┐       ▼
             ▼        ▼       ▼        ▼         ▼   data/cache/live/<source>/<key>.json
           OSV      NVD     KEV     EPSS   (frozen fixtures fallback)
             └────────┴───────┴────────┴─────────┘       │
                              │ merge → LiveRecord[]     │
                              ▼                          │
              prompt "Live intel" block  ◄───────────────┘
              (citeable ids: nvd:… kev:… epss:… osv:…)
                              │
                     one LLM call (unchanged)
```

The sidecar sits **beside** local retrieval. An agent's prompt gets both the retrieved Chroma
chunks *and* a `Live intel` block; both are citeable, both are filtered against an allowed-id set.

---

## New module `src/live/`

```
src/live/
├── models.py       LiveRecord (pydantic): id, source, kind, cve_id, title, summary,
│                   data(dict), url, severity, refs[], fetched_at
├── cache.py        JSON file cache: get/set, TTL check, modes, negative caching, atomic write
├── policy.py       CachePolicy dataclass + resolve(scenario_meta) — mirrors RoutingPolicy
├── http.py         shared client: retry/backoff, per-source rate-limit bucket, honor Retry-After
├── enrich.py       orchestrator: enrich(cve_ids, packages, iocs, policy) -> list[LiveRecord]
└── sources/
    ├── base.py     LiveSource protocol: name, id_prefix, ttl_key, fetch(keys), to_records(raw)
    ├── osv.py      POST api.osv.dev/v1/query {package,version} ; GET /v1/vulns/{id}
    ├── nvd.py      GET services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-…
    ├── kev.py      GET cisa.gov/.../known_exploited_vulnerabilities.json  (whole catalog, 1 doc)
    └── epss.py     GET api.first.org/data/v1/epss?cve=CVE-…,CVE-…        (batched)
```

---

## Cache design (JSON files)

**Path:** `data/cache/live/<source>/<key>.json` — human-readable key when filesystem-safe
(`nvd/CVE-2021-44228.json`), else `sha1(key)`.

**Envelope:**
```json
{
  "source": "nvd",
  "key": "CVE-2021-44228",
  "fetched_at": "2026-09-05T12:00:00Z",
  "ttl_seconds": 86400,
  "status": "ok",
  "payload": { "...normalized LiveRecord dict..." }
}
```

- `get(source, key, ttl)` → `None` on miss; `(payload, fresh=True)` if `now - fetched_at < ttl`;
  `(payload, fresh=False)` if expired (caller decides per mode).
- `set(...)` → write `tmp` then `os.replace` (atomic).
- **Negative caching:** `status: "not_found"` / `"error"` written with `CACHE_TTL_NEGATIVE`
  (default 3600 s) so a missing CVE or a rate-limit response doesn't re-hit the API every run.
- `data/cache/` is already gitignored. Committed demo snapshot lives in a **separate**
  `data/fixtures/live/` (read-only fallback) so `data/cache/` stays purely ephemeral.

---

## TTL / mode configuration

`src/config.py` additions:

```
CACHE_MODE            env "CACHE_MODE"        default "frozen"   # live | swr | frozen | bypass
CACHE_DIR_LIVE        DATA_DIR/"cache"/"live"
CACHE_FIXTURES_LIVE   DATA_DIR/"fixtures"/"live"
CACHE_TTL_DEFAULT     env int, default 86400
CACHE_TTL_NEGATIVE    env int, default 3600
CACHE_TTL_OSV / _NVD / _KEV / _EPSS   defaults 86400 / 86400 / 21600 / 86400
NVD_API_KEY           env, optional — raises NVD rate limit to 50 req / 30 s
```

**`CachePolicy.resolve(scenario_meta)`** — same `pick()` pattern as `RoutingPolicy`:

```
scenario meta.json  {"cache": {"mode": "...", "ttl": {"nvd": 3600}}}
   → env per-source (CACHE_TTL_NVD)
   → env default (CACHE_TTL_DEFAULT)
   → built-in per-source default
```

**Modes:**

| Mode | Behaviour |
|---|---|
| `live` | fresh hit → use; miss/expired → fetch + write + use; fetch fails → fixture → local-only |
| `swr` | fresh **or stale** hit → use immediately; if stale, refresh in a background thread for next run. Never blocks the trace |
| `frozen` *(demo default)* | fresh or stale cache **or** committed fixture → use; **never network**. Miss → skip enrichment, emit `enrichment skipped (frozen, no cache)` |
| `bypass` | always fetch, still write cache |

---

## Enrichment flow (A1)

New shared pre-step used by two agents (same shape as `log_parse` / `depscan`):

1. **`threat_intel_node`** — after extracting `cve_ids` + `iocs` from prior findings, call
   `enrich(cve_ids, packages=[], iocs, policy)`.
2. **`vuln_scanner_node`** — after `depscan` + local `cve_match`, call
   `enrich(cve_ids=[h.cve_id …], packages=[Package …], iocs=[], policy)`.
3. **`enrich()` fan-out:**
   - **OSV** — `query` per `{ecosystem, name, version}` → vuln ids; `vulns/{id}` for detail on
     ids not already known. (`# java:` log4j entry → `{"ecosystem":"Maven","name":"org.apache.logging.log4j:log4j-core"}`; depscan already keeps that alias.)
   - **NVD** — `cves/2.0?cveId=` per CVE id → CVSS vector/score, description, CWE, references,
     published/modified.
   - **KEV** — fetch the whole catalog **once per run** (cached as one doc), membership-check
     each CVE id in memory → `in_kev`, `date_added`, `due_date`, `required_action`.
   - **EPSS** — one batched `?cve=id1,id2,…` → `{cve: {epss, percentile}}`.
4. **Merge** → one `LiveRecord` per CVE id combining NVD detail + KEV flag + EPSS score, plus
   `osv:*` records for package-range hits.
5. Records rendered into the prompt as a `Live intel` block next to the local chunks, each with a
   citeable id: `nvd:CVE-2021-44228`, `kev:CVE-2021-44228`, `epss:CVE-2021-44228`,
   `osv:GHSA-jfh8-c2jp-5v3q`.

---

## Citations & resolution

- `allowed_citation_ids()` (`src/agents/common.py`) extended to also accept the live-record ids
  handed to that agent for that turn.
- New `resolve_citation(id)` (or a branch in `resolve_chunk`): a known live prefix → read the
  cache/fixture JSON and render `title · summary · url · fetched_at`. Unknown id → `None`
  (dropped, as today).
- `run_cli.py --check` citation resolution then covers live ids too.

---

## Risk scoring uses the live signal

`incident_response.compute_risk_score` — optional blend when enrichment is present:
KEV membership → floor the finding at `high`; `epss.percentile > 0.9` → one severity bump.
Pure-severity path stays as the fallback when no live records exist.

---

## UI (`app.py`)

- **Sidebar "Live intel" panel** — `CACHE_MODE`, per-source cache age + record count, a
  **Warm cache** button (runs `warm_cache` for the selected scenario), a **Freeze snapshot**
  button (`data/cache/live/` → `data/fixtures/live/`).
- **Trace** — enrichment emits its own `emit_trace` lines before the LLM call:
  `OSV: 2 vulns for commons-text@1.9` · `KEV: CVE-2021-44228 is known-exploited` · `EPSS 0.975`.
- **Findings expander** — provenance chips: NVD CVSS, KEV badge, EPSS percentile.

---

## Scripts

- `scripts/warm_cache.py --scenario log4shell [--all] [--mode live]` — runs the enrichment
  pre-steps for a scenario's CVE ids / packages and populates `data/cache/live/`. **Run before a demo.**
- `scripts/freeze_cache.py` — copy `data/cache/live/` → `data/fixtures/live/`, write a manifest
  (`source`, `key`, `fetched_at`) so snapshot age is visible.

---

## Config / `.env.example` additions

```
# Live enrichment cache. frozen = cache/fixtures only, never network (demo default).
CACHE_MODE=frozen
CACHE_TTL_DEFAULT=86400
CACHE_TTL_KEV=21600
CACHE_TTL_NEGATIVE=3600

# Optional — raises the NVD 2.0 rate limit from 5 to 50 requests / 30 s.
NVD_API_KEY=
```

## `requirements.txt` additions

- `httpx>=0.27` (or keep `requests`) for the shared client.
- Dev only: `respx` (httpx) or `responses` (requests) for record/replay tests.
- No heavy deps. Backoff hand-rolled in `http.py` (no `tenacity` needed).

---

## Testing (all offline)

| File | Covers |
|---|---|
| `tests/test_live_cache.py` | TTL fresh/stale/expired with a fake clock; negative caching; atomic write; mode matrix (live/swr/frozen/bypass) against a fake source |
| `tests/test_live_policy.py` | `CachePolicy.resolve` order: scenario meta → env per-source → env default → built-in; malformed values fall back |
| `tests/test_live_sources.py` | each source's `to_records()` against a captured JSON fixture; id/prefix stability; NVD parse with/without CVSS v3 |
| `tests/test_enrich.py` | merge: NVD+KEV+EPSS for one CVE collapse to one `LiveRecord`; a missing source degrades gracefully; OSV Maven coordinate mapping |
| `tests/test_citations_live.py` | `resolve_citation("kev:CVE-2021-44228")` returns fixture text; `--check` accepts live ids |

Any real-network test marked `@pytest.mark.live` and skipped by default.

---

## Verification (parallels `PLAN.md` §Verification)

1. `CACHE_MODE=live python scripts/warm_cache.py --all` → populates
   `data/cache/live/{osv,nvd,kev,epss}/`, prints per-source counts.
2. `python scripts/freeze_cache.py` → `data/fixtures/live/` snapshot + manifest, committed.
3. `CACHE_MODE=frozen python run_cli.py --scenario log4shell --check --no-cache` → **no network**;
   Threat Intel finding cites `nvd:CVE-2021-44228` and `kev:CVE-2021-44228`; `--check` passes;
   every live citation resolves.
4. `CACHE_MODE=frozen` with an **empty** cache and no fixtures → run still completes on the local
   KB alone; trace shows `enrichment skipped`.
5. TTL: `CACHE_TTL_NVD=1`, mode `live`, run twice 2 s apart → second run re-fetches
   (`fetched_at` changes). Mode `swr` → second run serves stale instantly, refreshes in background.
6. Outage sim (`respx` 503 / 429) → backoff → negative-cache → fixture fallback; the graph never
   crashes.
7. NVD with and without `NVD_API_KEY` both complete.
8. `ssh_bruteforce` (no CVE ids, IOC only) → enrichment is a no-op for OSV/NVD/EPSS, KEV catalog
   still cached; run unaffected.

---

## Build order (≈5:45)

| # | Block | Time |
|---|---|---|
| 1 | `src/live/cache.py` + `models.py` + `policy.py`; fake-clock + mode-matrix tests | 1:15 |
| 2 | `http.py` — session, backoff, per-source rate-limit bucket, `Retry-After` | 0:45 |
| 3 | Sources OSV / NVD / KEV / EPSS + `to_records()` + captured fixtures + per-source tests | 1:30 |
| 4 | `enrich.py` merge + wire into `threat_intel` & `vuln_scanner` pre-steps + trace lines | 1:00 |
| 5 | Citations: `allowed_citation_ids` + `resolve_citation` + `--check` path | 0:30 |
| 6 | `warm_cache.py`, `freeze_cache.py`, frozen snapshot, `.env.example`, README | 0:45 |
| 7 | UI sidebar panel + findings provenance chips | 0:45 |

Block 1 is the gate — if the cache/TTL/mode contract isn't solid, every source integration
wobbles.

---

## Risks

- **NVD latency & rate limit** — ~0.6–2 s per CVE, 5 req/30 s unkeyed. Mitigation: `warm_cache`
  is mandatory before a demo; `frozen` is the default mode; negative-cache rate-limit responses.
- **Frozen-snapshot staleness** — committed fixtures age. Mitigation: manifest carries
  `fetched_at`; README says re-run `warm_cache` + `freeze_cache` before judging; UI shows age.
- **KEV catalog size** (~1.5 MB) — cache as a single doc, membership-check in memory; never fan
  out per-CVE.
- **OSV ecosystem mapping** — Python deps → `PyPI`, the `# java:` log4j entry → `Maven`. Only
  these two ecosystems appear in the Phase 1 scenarios; anything else → skip OSV, log it.
- **Prompt size** — a `Live intel` block per CVE can be large. Cap each `LiveRecord.summary`
  (~600 chars) and cap the number of live records fed per agent (e.g. top 5 by severity/EPSS).
- **Citation trust** — a live id in the cache but absent from this turn's allowed set must still
  be dropped, exactly like a hallucinated chunk id today.

---

## Explicitly out of scope for Phase 2

Scheduled ingestion / re-embedding into Chroma (A2) · GHSA, ThreatFox, URLhaus, GreyNoise, Shodan
· Redis or shared cache · hosted vector DB · multi-user · auth on the cache · live IOC reputation
in the SSH scenario (KEV/EPSS/NVD/OSV only).
