"""Cache policy resolution — mirrors `supervisor.RoutingPolicy`.

Order: scenario meta.json  →  per-source env  →  default env  →  built-in.

meta.json shape:
    "cache": { "mode": "frozen", "ttl": { "nvd": 3600, "kev": 900 } }
"""

from __future__ import annotations

from dataclasses import dataclass, field

from src.config import (
    CACHE_MODE,
    CACHE_MODES,
    CACHE_TTL_DEFAULT,
    CACHE_TTL_NEGATIVE,
    LIVE_SOURCE_TTLS,
)


@dataclass(frozen=True)
class CachePolicy:
    mode: str
    ttls: dict[str, int] = field(default_factory=dict)
    negative_ttl: int = CACHE_TTL_NEGATIVE

    @classmethod
    def resolve(cls, scenario_meta: dict | None) -> "CachePolicy":
        meta = scenario_meta or {}
        cache_meta = meta.get("cache") if isinstance(meta.get("cache"), dict) else {}

        mode = str(cache_meta.get("mode") or CACHE_MODE).strip().lower()
        if mode not in CACHE_MODES:
            mode = "frozen"

        ttl_over = cache_meta.get("ttl") if isinstance(cache_meta.get("ttl"), dict) else {}
        ttls: dict[str, int] = {}
        for src, built_in in LIVE_SOURCE_TTLS.items():
            if src in ttl_over:
                try:
                    ttls[src] = max(0, int(ttl_over[src]))
                    continue
                except (TypeError, ValueError):
                    pass
            ttls[src] = built_in

        neg = cache_meta.get("negative_ttl", CACHE_TTL_NEGATIVE)
        try:
            neg = max(0, int(neg))
        except (TypeError, ValueError):
            neg = CACHE_TTL_NEGATIVE

        return cls(mode=mode, ttls=ttls, negative_ttl=neg)

    def ttl(self, source: str) -> int:
        return self.ttls.get(source, CACHE_TTL_DEFAULT)

    @property
    def may_fetch(self) -> bool:
        """False when the sidecar must not touch the network."""
        return self.mode in ("live", "swr", "bypass")

    @property
    def force_fetch(self) -> bool:
        return self.mode == "bypass"

    @property
    def serve_stale(self) -> bool:
        """Accept an expired cache entry as a usable hit."""
        return self.mode in ("swr", "frozen")
