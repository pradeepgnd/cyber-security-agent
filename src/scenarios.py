"""Load local synthetic scenarios."""

from __future__ import annotations

import json

from src.config import SCENARIOS_DIR

LOG_NAMES = {"auth.log", "syslog", "nginx_access.log", "app.log", "secure"}


def list_scenarios() -> list[str]:
    if not SCENARIOS_DIR.exists():
        return []
    return sorted(p.name for p in SCENARIOS_DIR.iterdir() if p.is_dir() and (p / "meta.json").exists())


def load_scenario(scenario_id: str) -> dict:
    folder = SCENARIOS_DIR / scenario_id
    if not folder.exists():
        raise FileNotFoundError(f"unknown scenario {scenario_id!r}")
    meta = json.loads((folder / "meta.json").read_text())
    raw_logs: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    for path in sorted(folder.iterdir()):
        if path.name == "meta.json" or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        if path.name in LOG_NAMES or path.suffix == ".log":
            raw_logs[path.name] = text
        else:
            artifacts[path.name] = text
    return {
        "scenario_id": scenario_id,
        "meta": meta,
        "raw_logs": raw_logs,
        "artifacts": artifacts,
    }
