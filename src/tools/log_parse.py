"""Deterministic parsers for auth.log, syslog, nginx access, and app logs."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

FAILED_RE = re.compile(
    r"(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+).*(?:Failed password|Invalid user) "
    r"for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
ACCEPTED_RE = re.compile(
    r"(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+).*Accepted (?:password|publickey) "
    r"for (?P<user>\S+) from (?P<ip>\S+)",
    re.IGNORECASE,
)
SUDO_RE = re.compile(
    r"(?P<ts>\w+\s+\d+\s+\d+:\d+:\d+).*sudo:\s+(?P<user>\S+)\s+:.*"
    r"COMMAND=(?P<cmd>.+)",
    re.IGNORECASE,
)
USERADD_RE = re.compile(r"useradd|adduser|new user", re.IGNORECASE)
SSH_LATERAL_RE = re.compile(
    r"ssh\s+\S+@(?P<host>\S+)|Accepted .+ from (?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
NGINX_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+) '
    r'(?P<proto>[^"]+)" (?P<status>\d+)'
)
JNDI_RE = re.compile(r"\$\{jndi:|/jndi:|jndi:ldap|jndi:rmi|jndi:dns", re.IGNORECASE)
TRAVERSAL_RE = re.compile(r"\.\./|\.\.\\|%2e%2e", re.IGNORECASE)
GEO_HINT_RE = re.compile(r"new.?geo|unfamiliar (?:country|location)|geo[- ]anomaly", re.IGNORECASE)

BRUTE_FORCE_THRESHOLD = 8


@dataclass
class ParsedEvent:
    kind: str
    source: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


def parse_logs(raw_logs: dict[str, str]) -> list[ParsedEvent]:
    events: list[ParsedEvent] = []
    failed_by_ip: dict[str, list[str]] = defaultdict(list)
    failed_users: Counter[str] = Counter()
    accepted: list[tuple[str, str, str, str]] = []

    for name, text in raw_logs.items():
        lower = name.lower()
        matched = False
        if "auth" in lower or lower == "syslog" or "secure" in lower:
            events.extend(_parse_auth(name, text, failed_by_ip, failed_users, accepted))
            matched = True
        if "nginx" in lower or "access" in lower:
            events.extend(_parse_nginx(name, text))
            matched = True
        if "app" in lower or lower.endswith(".log"):
            events.extend(_parse_app(name, text))
            matched = True
        if not matched:
            # Uploaded names like mylog.txt / messages.txt: try every parser.
            events.extend(_parse_auth(name, text, failed_by_ip, failed_users, accepted))
            events.extend(_parse_nginx(name, text))
            events.extend(_parse_app(name, text))

    for ip, lines in failed_by_ip.items():
        if len(lines) >= BRUTE_FORCE_THRESHOLD:
            users = sorted({FAILED_RE.search(ln).group("user") for ln in lines if FAILED_RE.search(ln)})  # type: ignore[union-attr]
            events.append(
                ParsedEvent(
                    kind="brute_force",
                    source="auth",
                    summary=(
                        f"{len(lines)} failed logins from {ip} "
                        f"(threshold {BRUTE_FORCE_THRESHOLD}) targeting {', '.join(users) or 'unknown'}"
                    ),
                    evidence=lines[:12],
                    iocs=[ip],
                    tags=["T1110", "ssh", "brute_force"],
                )
            )
            for ts, user, aip, line in accepted:
                if aip == ip:
                    events.append(
                        ParsedEvent(
                            kind="success_after_failures",
                            source="auth",
                            summary=f"Successful login for {user} from {ip} after {len(lines)} failures",
                            evidence=[line, *lines[:4]],
                            iocs=[ip, user],
                            tags=["T1110", "T1078", "new_geo"],
                        )
                    )

    return _dedupe(events)


def _parse_auth(
    name: str,
    text: str,
    failed_by_ip: dict[str, list[str]],
    failed_users: Counter[str],
    accepted: list[tuple[str, str, str, str]],
) -> list[ParsedEvent]:
    events: list[ParsedEvent] = []
    last_accept_user: str | None = None
    last_accept_line: str | None = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if m := FAILED_RE.search(line):
            failed_by_ip[m.group("ip")].append(line)
            failed_users[m.group("user")] += 1
            continue
        if m := ACCEPTED_RE.search(line):
            accepted.append((m.group("ts"), m.group("user"), m.group("ip"), line))
            last_accept_user = m.group("user")
            last_accept_line = line
            continue
        if USERADD_RE.search(line) and last_accept_user:
            events.append(
                ParsedEvent(
                    kind="account_create",
                    source=name,
                    summary=f"Account creation shortly after login by {last_accept_user}",
                    evidence=[last_accept_line or "", line],
                    iocs=[last_accept_user],
                    tags=["T1136", "T1078.003"],
                )
            )
        if m := SUDO_RE.search(line):
            events.append(
                ParsedEvent(
                    kind="sudo",
                    source=name,
                    summary=f"sudo by {m.group('user')}: {m.group('cmd').strip()}",
                    evidence=[line],
                    iocs=[m.group("user")],
                    tags=["T1059.004", "privilege"],
                )
            )
        if "10.0.2." in line and ("ssh" in line.lower() or "accepted" in line.lower()):
            events.append(
                ParsedEvent(
                    kind="lateral_movement",
                    source=name,
                    summary="Possible SSH lateral movement toward an internal host",
                    evidence=[line],
                    iocs=re.findall(r"\d+\.\d+\.\d+\.\d+", line),
                    tags=["T1021.004", "T1021"],
                )
            )
        if GEO_HINT_RE.search(line):
            events.append(
                ParsedEvent(
                    kind="new_geo",
                    source=name,
                    summary="New-geo / unfamiliar-location hint in logs",
                    evidence=[line],
                    tags=["T1078", "new_geo"],
                )
            )
    return events


def _parse_nginx(name: str, text: str) -> list[ParsedEvent]:
    events: list[ParsedEvent] = []
    for line in text.splitlines():
        if JNDI_RE.search(line):
            ip = _ip(line)
            events.append(
                ParsedEvent(
                    kind="jndi_exploit",
                    source=name,
                    summary="JNDI / Log4Shell-style payload in HTTP request",
                    evidence=[line],
                    iocs=[ip] if ip else [],
                    tags=["T1190", "cve-2021-44228", "jndi", "rce"],
                )
            )
        elif TRAVERSAL_RE.search(line):
            events.append(
                ParsedEvent(
                    kind="path_traversal",
                    source=name,
                    summary="Path-traversal payload in HTTP request",
                    evidence=[line],
                    iocs=[_ip(line)] if _ip(line) else [],
                    tags=["T1190", "traversal"],
                )
            )
    return events


def _parse_app(name: str, text: str) -> list[ParsedEvent]:
    events: list[ParsedEvent] = []
    if name.lower() in {"auth.log", "syslog"} or "nginx" in name.lower() or "access" in name.lower():
        # already handled by a more specific parser
        if "auth" in name.lower() or name.lower() == "syslog" or "nginx" in name.lower() or "access" in name.lower():
            return events
    for line in text.splitlines():
        if JNDI_RE.search(line) or "javax.naming" in line or "JndiLookup" in line:
            events.append(
                ParsedEvent(
                    kind="jndi_lookup",
                    source=name,
                    summary="Application performed or logged a JNDI lookup — possible RCE",
                    evidence=[line],
                    tags=["T1190", "cve-2021-44228", "rce"],
                )
            )
        if TRAVERSAL_RE.search(line) and "app" in name.lower():
            events.append(
                ParsedEvent(
                    kind="path_traversal",
                    source=name,
                    summary="Path-traversal pattern in application log",
                    evidence=[line],
                    tags=["T1190", "traversal"],
                )
            )
    return events


def _ip(line: str) -> str:
    m = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
    return m.group(1) if m else ""


def _dedupe(events: list[ParsedEvent]) -> list[ParsedEvent]:
    seen: set[tuple[str, str]] = set()
    out: list[ParsedEvent] = []
    for ev in events:
        key = (ev.kind, ev.summary)
        if key in seen:
            continue
        seen.add(key)
        out.append(ev)
    return out


def events_as_text(events: list[ParsedEvent]) -> str:
    if not events:
        return "(no suspicious events from deterministic parse)"
    lines: list[str] = []
    for i, ev in enumerate(events, 1):
        lines.append(
            f"{i}. [{ev.kind}] {ev.summary}\n"
            f"   tags={','.join(ev.tags)} iocs={','.join(ev.iocs) or '-'}\n"
            f"   evidence: {ev.evidence[0][:240] if ev.evidence else '-'}"
        )
    return "\n".join(lines)
