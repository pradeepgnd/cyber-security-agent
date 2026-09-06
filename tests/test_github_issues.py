from __future__ import annotations

import json
from typing import get_args

from src.config import SEVERITY_COLORS
from src.integrations import github_issues as gh
from src.live.http import LiveHTTPError
from src.state import Severity


def _finding(**kwargs) -> dict:
    base = {
        "id": "x",
        "agent": "log_monitor",
        "title": "SSH brute force",
        "description": "Many failures from 1.2.3.4. Notify @admin please.",
        "severity": "high",
        "confidence": 0.9,
        "evidence": ["Failed password from 1.2.3.4"],
        "citations": ["det-ssh-brute-force", "T1110"],
        "recommended_action": "Block the source IP",
    }
    base.update(kwargs)
    return base


def _result() -> dict:
    return {
        "scenario_id": "log4shell",
        "risk_score": 88,
        "final_plan": "## Contain\n- isolate\n",
        "findings": [
            _finding(),
            _finding(
                agent="vuln_scanner",
                title="Log4Shell",
                severity="critical",
                citations=["CVE-2021-44228"],
            ),
            _finding(agent="policy_checker", title="noise", severity="info"),
        ],
    }


def test_severity_colors_match_literals() -> None:
    assert set(SEVERITY_COLORS) == set(get_args(Severity))
    for hex_color in SEVERITY_COLORS.values():
        assert hex_color.startswith("#")
        assert len(hex_color) == 7


def test_text_on_contrast() -> None:
    dark = gh.text_on("#FFCB0D")
    assert dark.lower() == "#111827"
    light = gh.text_on("#CC0500")
    assert light.lower() == "#ffffff"


def test_label_payloads_bare_hex() -> None:
    for payload in gh.label_bootstrap_payloads():
        if payload["name"].startswith("severity:"):
            assert not payload["color"].startswith("#")
            assert len(payload["color"]) == 6


def test_parent_and_finding_payload_mapping() -> None:
    result = _result()
    parent = gh.build_parent_payload(result)
    assert "log4shell" in parent["title"]
    assert "88" in parent["title"]
    assert "## Contain" in parent["body"]
    assert "soc-agent-key:" in parent["body"]
    assert "assignees" not in parent
    assert "milestone" not in parent

    long_title = "T" * 300
    child = gh.build_finding_payload(
        _finding(title=long_title),
        41,
        run_id="log4shell",
    )
    assert len(child["title"]) <= 256
    assert child["title"].endswith("…")
    assert "severity:high" in child["labels"]
    assert "soc-agent" in child["labels"]
    assert "incident:log4shell" in child["labels"]
    assert "T1110" in child["labels"]
    assert "Part of #41" in child["body"]
    assert "soc-agent-key:" in child["body"]
    assert "assignees" not in child
    assert "milestone" not in child
    assert "`@admin`" in child["body"]


def test_mentions_defused() -> None:
    assert "`@admin`" in gh.defuse_mentions("ping @admin now")
    assert "assignees" not in gh.build_finding_payload(_finding(), 1, run_id="r")


def test_dedup_key_stable_and_agent_sensitive() -> None:
    a = _finding()
    k1 = gh.dedup_key("run1", a)
    k2 = gh.dedup_key("run1", dict(a))
    assert k1 == k2
    k3 = gh.dedup_key("run1", _finding(agent="threat_intel"))
    assert k3 != k1


def test_task_list() -> None:
    text = gh.build_task_list([41, 42])
    assert "- [ ] #41" in text
    assert "- [ ] #42" in text


def test_dry_run_issues_zero_posts(monkeypatch) -> None:
    calls: list = []

    def boom(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("network")

    monkeypatch.setattr(gh, "request_json", boom)
    gh.reset_label_cache()
    out = gh.file_incident(_result(), dry_run=True)
    assert out["dry_run"] is True
    assert out["posted"] is False
    assert calls == []
    assert out["labels"]
    assert all(
        not p["color"].startswith("#")
        for p in out["labels"]
        if p["name"].startswith("severity:")
    )


def test_second_file_incident_zero_posts(monkeypatch) -> None:
    result = _result()
    kids = gh.qualifying_findings(result)
    issues = {gh.dedup_key("log4shell", f): i for i, f in enumerate(kids, 10)}
    result["github"] = {"repo": "o/r", "parent": 41, "issues": issues}
    calls: list[str] = []

    def spy(source, method, url, **kwargs):
        calls.append(method.upper())
        return {"number": 99}

    monkeypatch.setattr(gh, "request_json", spy)
    gh.reset_label_cache()
    out = gh.file_incident(result, dry_run=False)
    assert out.get("skipped") is True
    assert calls == []


def test_ensure_labels_422_patches(monkeypatch) -> None:
    gh.reset_label_cache()
    calls: list[tuple] = []

    def fake(source, method, url, **kwargs):
        calls.append((method.upper(), url, kwargs.get("json_body")))
        if method.upper() == "POST":
            raise LiveHTTPError(
                "github: HTTP 422",
                status_code=422,
                body=json.dumps({"errors": [{"code": "already_exists"}]}),
            )
        return {}

    monkeypatch.setattr(gh, "request_json", fake)
    gh.ensure_labels(dry_run=False)
    posts = [c for c in calls if c[0] == "POST"]
    patches = [c for c in calls if c[0] == "PATCH"]
    assert posts
    assert len(patches) == len(posts)


def test_ensure_labels_dry_run_zero_requests(monkeypatch) -> None:
    gh.reset_label_cache()

    def boom(*_a, **_k):
        raise AssertionError("network")

    monkeypatch.setattr(gh, "request_json", boom)
    payloads = gh.ensure_labels(dry_run=True)
    assert payloads
