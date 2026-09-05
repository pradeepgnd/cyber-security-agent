"""Shared plumbing for live sources: the seed bundle and the cache-aside wrapper."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from src.live import cache
from src.live.http import LiveHTTPError, LiveNotFound
from src.live.policy import CachePolicy
from src.tools.depscan import Package


@dataclass
class Seeds:
    """Deterministic inputs to enrichment — never LLM-derived on the demo path."""

    cve_ids: list[str] = field(default_factory=list)
    packages: list[Package] = field(default_factory=list)
    iocs: list[str] = field(default_factory=list)


@dataclass
class Fetched:
    payload: Any
    status: str  # ok | not_found | error | skipped | stale
    origin: str  # cache | fixture | network | none


def _spawn_refresh(source: str, key: str, ttl: int, fetch: Callable[[], Any]) -> None:
    def _run() -> None:
        try:
            payload = fetch()
            cache.write(source, key, payload, status="ok", ttl_seconds=ttl)
        except LiveNotFound:
            cache.write(source, key, None, status="not_found", ttl_seconds=ttl)
        except Exception:  # noqa: BLE001 — background best effort
            pass

    threading.Thread(target=_run, name=f"swr-{source}-{key}", daemon=True).start()


def cached_fetch(
    source: str,
    key: str,
    policy: CachePolicy,
    fetch: Callable[[], Any],
) -> Fetched:
    """Cache-aside read honoring the resolved cache mode.

    `fetch` performs the network call and returns a JSON-serializable payload,
    or raises `LiveNotFound` / `LiveHTTPError`.
    """
    ttl = policy.ttl(source)
    entry = cache.read(source, key, ttl)

    if entry is not None and entry.fresh and not policy.force_fetch:
        return Fetched(entry.payload, entry.status, entry.origin)

    if not policy.may_fetch:
        # frozen: a stale entry (cache or fixture) is the best we can do
        if entry is not None and policy.serve_stale:
            return Fetched(entry.payload, "stale", entry.origin)
        return Fetched(None, "skipped", "none")

    if policy.mode == "swr" and entry is not None:
        _spawn_refresh(source, key, ttl, fetch)
        return Fetched(entry.payload, "stale", entry.origin)

    try:
        payload = fetch()
    except LiveNotFound:
        cache.write(source, key, None, status="not_found", ttl_seconds=policy.negative_ttl)
        return Fetched(None, "not_found", "network")
    except (LiveHTTPError, Exception) as exc:  # noqa: BLE001
        cache.write(source, key, None, status="error", ttl_seconds=policy.negative_ttl)
        if entry is not None:
            return Fetched(entry.payload, "stale", entry.origin)
        return Fetched(None, "error", "none")

    cache.write(source, key, payload, status="ok", ttl_seconds=ttl)
    return Fetched(payload, "ok", "network")


def norm_cve(raw: str) -> str:
    return str(raw).strip().upper()
