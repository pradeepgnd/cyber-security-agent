"""Phase 2 — live threat-intel enrichment sidecar.

Sits beside the local Chroma retrieval: a deterministic pre-step resolves the
CVE ids / package coordinates an agent already has, fans out to OSV / NVD /
CISA KEV / EPSS behind a JSON file cache with configurable TTL, and hands the
agent an extra `Live intel` context block whose ids are citeable.

Import `enrich` from `src.live.enrich` directly — re-exporting it here would
shadow the `src.live.enrich` submodule.
"""

from src.live.models import LiveRecord

__all__ = ["LiveRecord"]
