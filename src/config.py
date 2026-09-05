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

COLLECTIONS = ("cve", "mitre", "controls", "runbooks", "detections")

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
