"""Normalized shape for every live-source record.

One `LiveRecord` per (source, citeable id). Sources emit these; `enrich` merges
and de-duplicates them; agents render them into the prompt and may cite the id.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from src.config import LIVE_SUMMARY_CHARS

RecordKind = str  # cve | advisory | score | exploited


class LiveRecord(BaseModel):
    id: str  # citeable id, e.g. "nvd:CVE-2021-44228", "osv:GHSA-jfh8-c2jp-5v3q"
    source: str  # osv | nvd | kev | epss
    kind: RecordKind = "cve"
    cve_id: str = ""
    title: str = ""
    summary: str = ""
    url: str = ""
    severity: str = ""
    refs: list[str] = Field(default_factory=list)
    data: dict[str, Any] = Field(default_factory=dict)
    fetched_at: str = ""

    def as_context_block(self) -> str:
        head = f"[{self.id}] {self.title or self.cve_id}".strip()
        lines = [head]
        if self.severity:
            lines.append(f"severity: {self.severity}")
        if self.summary:
            lines.append(self.summary[:LIVE_SUMMARY_CHARS])
        if self.url:
            lines.append(f"ref: {self.url}")
        return "\n".join(lines)

    def as_citation_text(self) -> str:
        """Rendered when a finding cites this id (`--check`, UI expander)."""
        parts = [self.title or self.cve_id or self.id]
        if self.severity:
            parts.append(f"[{self.severity}]")
        body = self.summary or ""
        prov = f"(source: {self.source}, fetched {self.fetched_at or 'unknown'})"
        return f"{' '.join(parts)}\n{body}\n{prov}".strip()


def format_live_records(records: list[LiveRecord]) -> str:
    if not records:
        return "(no live intel available)"
    return "\n\n".join(r.as_context_block() for r in records)
