"""Shared HTTP client for the live sources.

Per-source rate-limit bucket, bounded ret/backoff, honors `Retry-After`. Never
called in `frozen` mode — the cache layer gates that.
"""

from __future__ import annotations

import time

import requests

from src.config import LIVE_HTTP_RETRIES, LIVE_HTTP_TIMEOUT, NVD_API_KEY

# Minimum seconds between requests to one source. NVD unkeyed is 5 req / 30 s;
# a key raises it to 50 / 30 s.
_RATE_INTERVALS = {
    "nvd": 0.7 if NVD_API_KEY else 6.5,
    "osv": 0.1,
    "epss": 0.3,
    "kev": 0.0,
}

_last_call: dict[str, float] = {}


class LiveHTTPError(Exception):
    """Transient/server-side failure after retries are exhausted."""


class LiveNotFound(Exception):
    """The source answered, authoritatively, that the key does not exist."""


def _throttle(source: str) -> None:
    interval = _RATE_INTERVALS.get(source, 0.2)
    if interval <= 0:
        return
    last = _last_call.get(source, 0.0)
    wait = interval - (time.monotonic() - last)
    if wait > 0:
        time.sleep(wait)


def _backoff(attempt: int, retry_after: str | None) -> None:
    if retry_after:
        try:
            time.sleep(min(30.0, float(retry_after)))
            return
        except ValueError:
            pass
    time.sleep(min(15.0, 0.5 * (2**attempt)))


def request_json(
    source: str,
    method: str,
    url: str,
    *,
    params: dict | None = None,
    json_body: dict | None = None,
    headers: dict | None = None,
) -> dict:
    last_exc: Exception | None = None
    for attempt in range(max(1, LIVE_HTTP_RETRIES)):
        _throttle(source)
        _last_call[source] = time.monotonic()
        try:
            resp = requests.request(
                method,
                url,
                params=params,
                json=json_body,
                headers=headers,
                timeout=LIVE_HTTP_TIMEOUT,
            )
        except requests.RequestException as exc:
            last_exc = exc
            _backoff(attempt, None)
            continue

        if resp.status_code == 404:
            raise LiveNotFound(f"{source}: 404 for {url}")
        if resp.status_code == 429 or resp.status_code >= 500:
            last_exc = LiveHTTPError(f"{source}: HTTP {resp.status_code}")
            _backoff(attempt, resp.headers.get("Retry-After"))
            continue
        try:
            resp.raise_for_status()
            return resp.json()
        except (requests.RequestException, ValueError) as exc:
            last_exc = exc
            _backoff(attempt, None)

    raise LiveHTTPError(f"{source}: request failed") from last_exc
