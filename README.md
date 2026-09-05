# Cybersecurity Multi-Agent SOC

Hackathon demo of an AI-powered SOC: a supervisor routes five specialist agents over a local RAG knowledge base. Every finding carries a citation that resolves to a real chunk. The graph is model-agnostic — structured output is parsed from text, so swapping `OPENROUTER_MODEL` changes quality, not whether the run completes.

## What you get

- **Supervisor** chooses the next specialist (or FINISH), with a code-enforced loop policy
- **Log Monitor · Threat Intel · Vuln Scanner · Policy Checker · Incident Response**
- Local Chroma index (CVE, ATT&CK, NIST/SOC2, runbooks, detections)
- Two synthetic scenarios: SSH brute force → lateral movement, and Log4Shell on a public API
- Streamlit dashboard with a live agent trace and a token-streamed remediation plan
- Headless CLI for the same stream (`run_cli.py`)

Nothing phones home at demo time except OpenRouter (and LangSmith, if you opt in).

## Setup

Python 3.12. No `uv` required.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# put your OpenRouter key in .env
```

Build the knowledge base (downloads the ~80 MB ONNX MiniLM once):

```bash
python scripts/build_kb.py --smoke
```

You should see non-zero doc/chunk counts for all five collections, `CVE-2021-44228` as a top hit for `log4j jndi rce`, and a brute-force detection for `repeated failed password`.

## 3-minute demo script

1. `streamlit run app.py` — sidebar shows the model, KB chunk counts, LangSmith on/off.
2. Select **ssh_bruteforce**. Click **Run analysis**.
   - Status chips flip idle → running → done.
   - Supervisor reason types out; Log Monitor prints parse counts in well under a second.
   - Incident Response writes a contain → eradicate → recover → harden plan live.
3. Open **Findings**. Expand a row — evidence is a log line, citation expands to KB text.
4. Open **Compliance** for the NIST / SOC 2 gap table.
5. Switch to **log4shell** and run again.
   - Threat Intel names **CVE-2021-44228**.
   - Vuln Scanner flags `log4j-core@2.14.1` from `requirements.txt` / the Dockerfile.
6. Re-select a scenario: the disk cache replays instantly. Tick **Ignore disk cache** only if you want a live rerun.

Headless equivalent (useful if Streamlit is being fussy on stage):

```bash
python run_cli.py --scenario ssh_bruteforce --check --no-cache
python run_cli.py --scenario log4shell --check --no-cache
```

`--check` asserts `meta.json` expected keywords, a non-empty plan, and that every citation id resolves to a real chunk.

## Live threat-intel enrichment (Phase 2)

Threat Intel and Vuln Scanner run a deterministic pre-step that resolves the CVE ids /
package coordinates they already hold against **OSV, NVD, CISA KEV, and EPSS**, behind a
JSON file cache with a configurable TTL. Retrieval from the local Chroma KB is unchanged —
live records are an extra, citeable `Live intel` block (`nvd:CVE-…`, `kev:CVE-…`, …).

`CACHE_MODE` governs whether the sidecar may touch the network:

| Mode | Behaviour |
|---|---|
| `frozen` *(default)* | cache + committed `data/fixtures/live/` only, never the network — the demo path |
| `live` | fetch on miss/expiry, then cache |
| `swr` | serve stale immediately, refresh in the background |
| `bypass` | always fetch |

Scenario `meta.json` can override it: `"cache": { "mode": "frozen", "ttl": { "nvd": 3600 } }`.

Before a demo, warm the cache and freeze a snapshot:

```bash
CACHE_MODE=live python scripts/warm_cache.py --all
python scripts/freeze_cache.py   # data/cache/live/ -> data/fixtures/live/ + MANIFEST.json
```

With no cache and no fixtures, `frozen` mode simply skips enrichment — the run still
completes on the local KB.

## Configuration

| Env | Role |
|---|---|
| `OPENROUTER_API_KEY` / `OPENROUTER_MODEL` | Required. Any OpenRouter chat model. |
| `LANGSMITH_TRACING` / `LANGSMITH_API_KEY` / `LANGSMITH_PROJECT` | Optional. Unset them and the app is unchanged. |
| `USE_NATIVE_STRUCTURED_OUTPUT` | Off. Do not enable on the demo path. |
| `SUPERVISOR_MAX_ITERATIONS` | Default 8, hard-capped at 12. Scenario `meta.json` wins over env. |
| `CACHE_MODE` | `frozen` (default) / `live` / `swr` / `bypass`. Scenario `meta.json` wins. |
| `CACHE_TTL_*` / `NVD_API_KEY` | Per-source TTL seconds; optional NVD key raises its rate limit. |
| `OSV_API_URL` / `NVD_API_URL` / `KEV_FEED_URL` / `EPSS_API_URL` | Source base URLs; override for mirrors / offline. |

## Tests that do not need a key

```bash
pytest tests/test_parse_json.py tests/test_tools.py tests/test_routing_policy.py \
       tests/test_live_cache.py tests/test_live_policy.py \
       tests/test_live_sources.py tests/test_live_enrich.py
```

The live-enrichment tests never touch the network (`tests/conftest.py` blocks it and
redirects the cache to a tmp dir).

## Deploy on Render

The app is a long-running Streamlit process. Render is configured via [`render.yaml`](render.yaml). The Blueprint uses the **Free** plan (no persistent disk — Chroma rebuilds on each cold start). Add a payment method and switch to Starter + a `/data` disk if you need the index and run cache to survive deploys.

1. Push this repo to GitHub and open [Render Blueprints](https://dashboard.render.com/blueprints).
2. Connect the GitHub repo. Render prompts for `OPENROUTER_API_KEY` and `OPENROUTER_MODEL` — paste the same values as local `.env`. Do not commit `.env`.
3. First boot runs `scripts/start.sh`, which builds the knowledge base if `/data/chroma` is empty, then binds Streamlit to `$PORT`.
4. Later deploys skip ingest. Re-demos hit the disk run cache.

Free-tier web services cannot attach a disk and spin down when idle — every wake rebuilds Chroma. Starter is the demo-safe plan. If a live run is killed with OOM, bump the instance to Standard (2 GB).

```bash
# after the service exists, refresh secrets from local .env (never print them)
render env set OPENROUTER_API_KEY --value "$OPENROUTER_API_KEY"
```

## Layout

See `PLAN.md` for architecture and the locked decisions. Application code lives in `src/`, the corpus in `data/kb` and `data/scenarios`, the Streamlit entrypoint is `app.py`.

