"""Environment, paths, and model names. Importing this is side-effect free
except for loading `.env` if present — LangSmith is enabled purely by env."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

DATA_DIR = ROOT / "data"
KB_DIR = DATA_DIR / "kb"
CHROMA_DIR = DATA_DIR / "chroma"
SCENARIOS_DIR = DATA_DIR / "scenarios"
CACHE_DIR = DATA_DIR / "cache"

# --- Phase 2: live threat-intel enrichment -------------------------------------

LIVE_CACHE_DIR = CACHE_DIR / "live"
LIVE_FIXTURES_DIR = DATA_DIR / "fixtures" / "live"

# Cache mode governs whether the sidecar may touch the network at all.
#   live   — fetch on miss/expiry, then cache
#   swr    — serve stale immediately, refresh in the background
#   frozen — cache/fixtures only, never fetch (the demo default)
#   bypass — always fetch, still write cache
CACHE_MODE = os.getenv("CACHE_MODE", "frozen").strip().lower()
CACHE_MODES = ("live", "swr", "frozen", "bypass")

CACHE_TTL_DEFAULT = int(os.getenv("CACHE_TTL_DEFAULT", "86400"))
CACHE_TTL_NEGATIVE = int(os.getenv("CACHE_TTL_NEGATIVE", "3600"))

# Per-source base URLs. Overridable via env for mirrors / offline testing.
LIVE_SOURCE_URLS = {
    "osv": os.getenv("OSV_API_URL", "https://api.osv.dev"),
    "nvd": os.getenv(
        "NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    ),
    "kev": os.getenv(
        "KEV_FEED_URL",
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json",
    ),
    "epss": os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss"),
}

# Per-source TTL (seconds). KEV moves daily; the rest are effectively static.
LIVE_SOURCE_TTLS = {
    "osv": int(os.getenv("CACHE_TTL_OSV", str(CACHE_TTL_DEFAULT))),
    "nvd": int(os.getenv("CACHE_TTL_NVD", str(CACHE_TTL_DEFAULT))),
    "kev": int(os.getenv("CACHE_TTL_KEV", "21600")),
    "epss": int(os.getenv("CACHE_TTL_EPSS", str(CACHE_TTL_DEFAULT))),
}

LIVE_SOURCES = ("osv", "nvd", "kev", "epss")

# Optional — raises the NVD 2.0 rate limit from 5 to 50 requests / 30 s.
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

LIVE_HTTP_TIMEOUT = float(os.getenv("LIVE_HTTP_TIMEOUT", "10"))
LIVE_HTTP_RETRIES = int(os.getenv("LIVE_HTTP_RETRIES", "3"))
LIVE_MAX_CVES_PER_RUN = int(os.getenv("LIVE_MAX_CVES_PER_RUN", "8"))
# Cap on live records fed into a single agent prompt (highest priority kept).
LIVE_MAX_RECORDS_PER_AGENT = int(os.getenv("LIVE_MAX_RECORDS_PER_AGENT", "12"))
LIVE_SUMMARY_CHARS = int(os.getenv("LIVE_SUMMARY_CHARS", "600"))
LIVE_CITATION_PREFIXES = ("nvd", "kev", "epss", "osv", "live")

COLLECTIONS = ("cve", "mitre", "controls", "runbooks", "detections")

# NVD / CVSS ramp — leading # matches CHIP_COLORS. GitHub labels strip it.
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#CC0500",
    "high": "#DF3D03",
    "medium": "#F9A009",
    "low": "#FFCB0D",
    "info": "#6C757D",
}

# --- Phase 4: GitHub issue filing --------------------------------------------
GITHUB_ENABLED = os.getenv("GITHUB_ENABLED", "false").lower() in {"true", "1", "yes"}
GITHUB_API_URL = os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/")
GITHUB_REPO = os.getenv("GITHUB_REPO", "pradeepgnd/cyber-security-agent")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_MIN_SEVERITY = os.getenv("GITHUB_MIN_SEVERITY", "high").strip().lower() or "high"

OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini")
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

HTTP_REFERER = os.getenv(
    "OPENROUTER_HTTP_REFERER",
    "https://github.com/pradeepgnd/cyber-security-agent",
)
X_TITLE = os.getenv("OPENROUTER_X_TITLE", "Cybersecurity Multi-Agent SOC")

USE_NATIVE_STRUCTURED_OUTPUT = (
    os.getenv("USE_NATIVE_STRUCTURED_OUTPUT", "false").lower() == "true"
)

LANGSMITH_TRACING = os.getenv("LANGSMITH_TRACING", "").lower() in {"true", "1", "yes"}
LANGSMITH_PROJECT = os.getenv("LANGSMITH_PROJECT", "cyber-security-agent")

SUPERVISOR_DEFAULT_MAX_ITERATIONS = 8
SUPERVISOR_DEFAULT_MAX_VISITS = 1
SUPERVISOR_TERMINAL_AGENT = "incident_response"
SUPERVISOR_ABSOLUTE_MAX = min(int(os.getenv("SUPERVISOR_ABSOLUTE_MAX", "12")), 12)

AGENT_NAMES = (
    "log_monitor",
    "threat_intel",
    "vuln_scanner",
    "policy_checker",
    "incident_response",
)

AGENT_LABELS = {
    "log_monitor": "Log Monitor",
    "threat_intel": "Threat Intel",
    "vuln_scanner": "Vuln Scanner",
    "policy_checker": "Policy Checker",
    "incident_response": "Incident Response",
    "supervisor": "Supervisor",
}


def env_int(name: str) -> int | None:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return None
    return int(raw)
