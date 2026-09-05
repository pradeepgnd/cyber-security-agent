"""Extract package@version from requirements.txt, pom.xml, and Dockerfiles."""

from __future__ import annotations

import re
from dataclasses import dataclass

REQ_RE = re.compile(
    r"^\s*(?:#\s*(?:java:\s*)?)?"
    r"(?P<name>[A-Za-z0-9_.\-:][A-Za-z0-9_.\-/:]*)"
    r"\s*(?:==|>=|<=|~=|!=|===|:)\s*"
    r"(?P<version>[A-Za-z0-9_.\-]+)",
)
JAR_RE = re.compile(
    r"(?P<name>[A-Za-z0-9_.\-]+)-(?P<version>\d+[A-Za-z0-9_.\-]*)\.jar",
    re.IGNORECASE,
)
POM_RE = re.compile(
    r"<dependency>\s*"
    r"<groupId>(?P<group>[^<]+)</groupId>\s*"
    r"<artifactId>(?P<artifact>[^<]+)</artifactId>\s*"
    r"<version>(?P<version>[^<]+)</version>",
    re.IGNORECASE | re.DOTALL,
)


@dataclass
class Package:
    name: str
    version: str
    source: str
    extras: list[str]

    def key(self) -> str:
        return f"{self.name}@{self.version}"


def scan_artifacts(artifacts: dict[str, str]) -> list[Package]:
    found: list[Package] = []
    for name, text in artifacts.items():
        lower = name.lower()
        if lower.endswith("requirements.txt") or lower == "requirements.txt":
            found.extend(_from_requirements(name, text))
        elif lower.endswith("pom.xml") or lower == "pom.xml":
            found.extend(_from_pom(name, text))
        elif "dockerfile" in lower:
            found.extend(_from_dockerfile(name, text))
        else:
            found.extend(_from_requirements(name, text))
            found.extend(_from_dockerfile(name, text))
    return _dedupe(found)


def _from_requirements(source: str, text: str) -> list[Package]:
    pkgs: list[Package] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") and ":" not in stripped and "==" not in stripped:
            continue
        if m := REQ_RE.match(stripped):
            raw_name = m.group("name")
            extras = [raw_name]
            short = raw_name.split(":")[-1]
            extras.append(short)
            pkgs.append(Package(name=short, version=m.group("version"), source=source, extras=extras))
    return pkgs


def _from_pom(source: str, text: str) -> list[Package]:
    pkgs: list[Package] = []
    for m in POM_RE.finditer(text):
        artifact = m.group("artifact").strip()
        group = m.group("group").strip()
        pkgs.append(
            Package(
                name=artifact,
                version=m.group("version").strip(),
                source=source,
                extras=[artifact, f"{group}:{artifact}"],
            )
        )
    return pkgs


def _from_dockerfile(source: str, text: str) -> list[Package]:
    pkgs: list[Package] = []
    for m in JAR_RE.finditer(text):
        pkgs.append(
            Package(
                name=m.group("name"),
                version=m.group("version"),
                source=source,
                extras=[m.group("name")],
            )
        )
    for line in text.splitlines():
        if m := REQ_RE.match(line.strip().lstrip("#").strip()):
            pkgs.append(
                Package(
                    name=m.group("name").split(":")[-1],
                    version=m.group("version"),
                    source=source,
                    extras=[m.group("name")],
                )
            )
    return pkgs


def _dedupe(pkgs: list[Package]) -> list[Package]:
    seen: set[str] = set()
    out: list[Package] = []
    for p in pkgs:
        k = p.key()
        if k in seen:
            continue
        seen.add(k)
        out.append(p)
    return out


def packages_as_text(pkgs: list[Package]) -> str:
    if not pkgs:
        return "(no packages found in artifacts)"
    return "\n".join(f"- {p.name}@{p.version}  (from {p.source})" for p in pkgs)
