"""GitHub Issues post-run filer. Pure payload builders plus optional network."""

from __future__ import annotations

import hashlib
import re
from typing import get_args
from urllib.parse import quote

from src.config import (
    GITHUB_API_URL,
    GITHUB_ENABLED,
    GITHUB_MIN_SEVERITY,
    GITHUB_REPO,
    GITHUB_TOKEN,
    SEVERITY_COLORS,
)
from src.live.http import LiveHTTPError, LiveNotFound, request_json
from src.state import Severity

SOC_LABEL = "soc-agent"
MARKER_FMT = "<!-- soc-agent-key: {key} -->"
MITRE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
MENTION_RE = re.compile(r"(?<![`\w])@([A-Za-z0-9][A-Za-z0-9-]{0,38})")
SEVERITY_RANK = ("info", "low", "medium", "high", "critical")

_labels_ensured = False


def github_label_color(severity: str) -> str:
    return SEVERITY_COLORS.get(severity, SEVERITY_COLORS["info"]).lstrip("#")


def text_on(bg_hex: str) -> str:
    """Pick dark or light text from background luminance (WCAG-ish)."""
    h = bg_hex.lstrip("#")
    if len(h) != 6:
        return "#ffffff"
    r, g, b = (int(h[i : i + 2], 16) / 255.0 for i in (0, 2, 4))

    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    luminance = 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b)
    return "#111827" if luminance > 0.45 else "#ffffff"


def defuse_mentions(text: str) -> str:
    return MENTION_RE.sub(r"`@\1`", text or "")


def dedup_key(run_id: str, finding: dict) -> str:
    blob = f"{run_id}|{finding.get('title', '')}|{finding.get('agent', '')}"
    return hashlib.sha1(blob.encode("utf-8")).hexdigest()[:12]


def _meets_min_severity(severity: str, minimum: str) -> bool:
    try:
        return SEVERITY_RANK.index(severity) >= SEVERITY_RANK.index(minimum)
    except ValueError:
        return False


def qualifying_findings(
    result: dict, *, min_severity: str | None = None
) -> list[dict]:
    floor = (min_severity or GITHUB_MIN_SEVERITY).lower()
    out: list[dict] = []
    for finding in result.get("findings") or []:
        sev = str(finding.get("severity") or "info").lower()
        if _meets_min_severity(sev, floor):
            out.append(finding)
    return out


def _mitre_labels(finding: dict) -> list[str]:
    blob = " ".join(
        [
            str(finding.get("title") or ""),
            str(finding.get("description") or ""),
            " ".join(finding.get("citations") or []),
            " ".join(finding.get("evidence") or []),
        ]
    )
    return sorted(set(MITRE_RE.findall(blob)))


def _run_id(result: dict) -> str:
    return str(result.get("scenario_id") or result.get("run_id") or "run")


def _truncate_title(title: str, limit: int = 256) -> str:
    title = (title or "untitled").replace("\n", " ").strip()
    if len(title) <= limit:
        return title
    return title[: limit - 1] + "…"


def build_parent_payload(result: dict) -> dict:
    run_id = _run_id(result)
    risk = result.get("risk_score") or 0
    key = hashlib.sha1(f"{run_id}|parent".encode()).hexdigest()[:12]
    plan = defuse_mentions(result.get("final_plan") or "_No plan._")
    body = (
        f"{plan.rstrip()}\n\n"
        f"{MARKER_FMT.format(key=key)}\n"
    )
    return {
        "title": _truncate_title(f"SOC incident {run_id} (risk {risk})"),
        "body": body,
        "labels": [SOC_LABEL, f"incident:{run_id}"],
        "_key": key,
    }


def build_finding_payload(finding: dict, parent_number: int | None, *, run_id: str) -> dict:
    key = dedup_key(run_id, finding)
    sev = str(finding.get("severity") or "info").lower()
    evidence = finding.get("evidence") or []
    citations = finding.get("citations") or []
    evidence_md = "\n".join(f"- `{defuse_mentions(str(e))}`" for e in evidence[:12]) or "_none_"
    cites_md = ", ".join(f"`{c}`" for c in citations) or "_none_"
    desc = defuse_mentions(str(finding.get("description") or ""))
    action = defuse_mentions(str(finding.get("recommended_action") or ""))
    parent_line = f"Part of #{parent_number}\n\n" if parent_number else ""
    body = (
        f"{parent_line}"
        f"**Agent:** `{finding.get('agent', '')}`  \n"
        f"**Severity:** `{sev}`  \n"
        f"**Confidence:** `{finding.get('confidence', '')}`\n\n"
        f"{desc}\n\n"
        f"### Evidence\n{evidence_md}\n\n"
        f"### Recommended action\n{action or '_none_'}\n\n"
        f"### Citations\n{cites_md}\n\n"
        f"{MARKER_FMT.format(key=key)}\n"
    )
    labels = [SOC_LABEL, f"incident:{run_id}", f"severity:{sev}", *_mitre_labels(finding)]
    payload = {
        "title": _truncate_title(str(finding.get("title") or "finding")),
        "body": body,
        "labels": labels,
        "_key": key,
    }
    assert "assignees" not in payload
    assert "milestone" not in payload
    return payload


def build_task_list(child_numbers: list[int]) -> str:
    return "\n".join(f"- [ ] #{n}" for n in child_numbers)


def label_bootstrap_payloads() -> list[dict]:
    payloads = [
        {
            "name": SOC_LABEL,
            "color": "1F6FEB",
            "description": "Filed by the SOC multi-agent",
        }
    ]
    for sev, hex_color in SEVERITY_COLORS.items():
        payloads.append(
            {
                "name": f"severity:{sev}",
                "color": hex_color.lstrip("#"),
                "description": "SOC agent severity",
            }
        )
    return payloads


def _headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {GITHUB_TOKEN}"
    return headers


def _repo_url(path: str) -> str:
    return f"{GITHUB_API_URL}/repos/{GITHUB_REPO}{path}"


def ensure_labels(*, dry_run: bool = False) -> list[dict]:
    """Create or re-sync severity labels. Dry run returns payloads only."""
    global _labels_ensured
    payloads = label_bootstrap_payloads()
    if dry_run:
        return payloads
    if _labels_ensured:
        return payloads
    for payload in payloads:
        name = payload["name"]
        try:
            request_json(
                "github",
                "POST",
                _repo_url("/labels"),
                json_body={
                    "name": name,
                    "color": payload["color"],
                    "description": payload["description"],
                },
                headers=_headers(),
            )
        except LiveHTTPError as exc:
            if exc.status_code == 422 and "already_exists" in (exc.body or ""):
                request_json(
                    "github",
                    "PATCH",
                    _repo_url(f"/labels/{quote(name, safe='')}"),
                    json_body={
                        "new_name": name,
                        "color": payload["color"],
                        "description": payload["description"],
                    },
                    headers=_headers(),
                )
            else:
                raise
    _labels_ensured = True
    return payloads


def preview_incident(result: dict) -> dict:
    return file_incident(result, dry_run=True)


def file_incident(result: dict, *, dry_run: bool = False) -> dict:
    """File parent + child issues, or return payloads when dry_run=True.

    Never raises into the UI/CLI — failures are returned on the dict.
    Mutates `result["github"]` on success so a re-file is idempotent.
    """
    run_id = _run_id(result)
    parent_payload = build_parent_payload(result)
    children_src = qualifying_findings(result)
    child_payloads = [
        build_finding_payload(f, None, run_id=run_id) for f in children_src
    ]
    labels = label_bootstrap_payloads()

    if dry_run:
        return {
            "dry_run": True,
            "posted": False,
            "repo": GITHUB_REPO,
            "parent": parent_payload,
            "children": child_payloads,
            "labels": labels,
            "count": {"parent": 1, "children": len(child_payloads)},
        }

    existing = dict(result.get("github") or {})
    existing.setdefault("issues", {})
    already = existing.get("issues") or {}
    pending_keys = [p["_key"] for p in child_payloads if p["_key"] not in already]
    if existing.get("parent") and not pending_keys:
        return {
            "ok": True,
            "skipped": True,
            "reason": "already filed",
            "repo": existing.get("repo") or GITHUB_REPO,
            "parent": existing.get("parent"),
            "issues": already,
        }

    if not GITHUB_ENABLED:
        return {
            "ok": False,
            "posted": False,
            "error": "GITHUB_ENABLED=false — posting disabled. Dry-run still works.",
            "repo": GITHUB_REPO,
            "parent": parent_payload,
            "children": child_payloads,
            "labels": labels,
        }
    if not GITHUB_TOKEN:
        return {
            "ok": False,
            "posted": False,
            "error": "GITHUB_TOKEN is empty",
            "repo": GITHUB_REPO,
        }

    errors: list[str] = []
    try:
        ensure_labels(dry_run=False)
    except LiveNotFound as exc:
        return {"ok": False, "error": str(exc), "repo": GITHUB_REPO}
    except LiveHTTPError as exc:
        return {"ok": False, "error": str(exc), "repo": GITHUB_REPO, "status_code": exc.status_code}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "repo": GITHUB_REPO}

    parent_number = existing.get("parent")
    try:
        if not parent_number:
            created = request_json(
                "github",
                "POST",
                _repo_url("/issues"),
                json_body={
                    "title": parent_payload["title"],
                    "body": parent_payload["body"],
                    "labels": parent_payload["labels"],
                },
                headers=_headers(),
            )
            parent_number = int(created["number"])
            existing["parent"] = parent_number
            existing["repo"] = GITHUB_REPO
            existing.setdefault("issues", {})
            result["github"] = existing
    except LiveNotFound as exc:
        return {"ok": False, "error": str(exc), "repo": GITHUB_REPO, "github": existing}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc), "repo": GITHUB_REPO, "github": existing}

    created_children: list[int] = list(already.values()) if isinstance(already, dict) else []
    for finding, payload in zip(children_src, child_payloads):
        key = payload["_key"]
        if key in already:
            continue
        child = build_finding_payload(finding, parent_number, run_id=run_id)
        try:
            created = request_json(
                "github",
                "POST",
                _repo_url("/issues"),
                json_body={
                    "title": child["title"],
                    "body": child["body"],
                    "labels": child["labels"],
                },
                headers=_headers(),
            )
            num = int(created["number"])
            already[key] = num
            created_children.append(num)
            existing["issues"] = already
            existing["parent"] = parent_number
            existing["repo"] = GITHUB_REPO
            result["github"] = existing
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{key}: {exc}")

    child_numbers = [already[p["_key"]] for p in child_payloads if p["_key"] in already]
    if parent_number and child_numbers:
        task_list = build_task_list(child_numbers)
        try:
            request_json(
                "github",
                "PATCH",
                _repo_url(f"/issues/{parent_number}"),
                json_body={"body": parent_payload["body"].rstrip() + "\n\n## Findings\n" + task_list + "\n"},
                headers=_headers(),
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"parent patch: {exc}")

    result["github"] = existing
    return {
        "ok": not errors,
        "posted": True,
        "skipped": False,
        "repo": GITHUB_REPO,
        "parent": parent_number,
        "issues": already,
        "errors": errors,
    }


def reset_label_cache() -> None:
    global _labels_ensured
    _labels_ensured = False


# Re-export for tests that check Severity coverage
assert set(SEVERITY_COLORS) == set(get_args(Severity))
