"""Deterministic package+version → local CVE records (no network)."""

from __future__ import annotations

from dataclasses import dataclass

import frontmatter
from packaging.version import InvalidVersion, Version

from src.config import KB_DIR
from src.tools.depscan import Package


@dataclass
class CveHit:
    cve_id: str
    title: str
    package: str
    version: str
    fixed_version: str
    severity: str


def _version(raw: str) -> Version | None:
    try:
        return Version(raw)
    except InvalidVersion:
        return None


def _in_range(ver: Version, introduced: str | None, fixed: str | None) -> bool:
    if introduced:
        iv = _version(introduced)
        if iv is not None and ver < iv:
            return False
    if fixed:
        fv = _version(fixed)
        if fv is not None and ver >= fv:
            return False
    return True


def load_cve_records() -> list[dict]:
    records: list[dict] = []
    cve_dir = KB_DIR / "cve"
    if not cve_dir.exists():
        return records
    for path in sorted(cve_dir.glob("*.md")):
        post = frontmatter.load(path)
        meta = dict(post.metadata)
        meta["body"] = post.content
        records.append(meta)
    return records


def match_cves(packages: list[Package], records: list[dict] | None = None) -> list[CveHit]:
    records = records if records is not None else load_cve_records()
    hits: list[CveHit] = []
    for pkg in packages:
        names = {pkg.name.lower(), *(e.lower() for e in pkg.extras)}
        ver = _version(pkg.version)
        if ver is None:
            continue
        for rec in records:
            aliases = [str(rec.get("id", "")).lower()]
            for item in rec.get("packages") or []:
                if isinstance(item, str):
                    aliases.append(item.lower())
                elif isinstance(item, dict):
                    aliases.append(str(item.get("name", "")).lower())
                    for a in item.get("aliases") or []:
                        aliases.append(str(a).lower())
            if not names.intersection(aliases):
                continue
            introduced = None
            fixed = rec.get("fixed_version")
            packages_meta = rec.get("packages") or []
            for item in packages_meta:
                if isinstance(item, dict):
                    item_names = {str(item.get("name", "")).lower(), *(str(a).lower() for a in item.get("aliases") or [])}
                    if names.intersection(item_names):
                        introduced = item.get("introduced")
                        fixed = item.get("fixed") or fixed
            if _in_range(ver, introduced, str(fixed) if fixed else None):
                hits.append(
                    CveHit(
                        cve_id=str(rec.get("id", "unknown")),
                        title=str(rec.get("title", rec.get("id", ""))),
                        package=pkg.name,
                        version=pkg.version,
                        fixed_version=str(fixed or ""),
                        severity=str(rec.get("severity", "high")),
                    )
                )
    return hits


def hits_as_text(hits: list[CveHit]) -> str:
    if not hits:
        return "(no deterministic CVE version matches)"
    return "\n".join(
        f"- {h.cve_id} hits {h.package}@{h.version} (fixed in {h.fixed_version or '?'}) [{h.severity}]"
        for h in hits
    )
