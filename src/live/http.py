"""Shared HTTP client for the live sources and GitHub.

Per-source rate-limit bucket, bounded retry/backoff, honors `Retry-After`.
Permanent 4xx fail immediately (except a rate-limited 403).
"""

from __future__ import annotations

import time

import requests

from src.config import LIVE_HTTP_RETRIES, LIVE_HTTP_TIMEOUT, NVD_API_KEY

# Minimum seconds between requests to one source. NVD unkeyed is 5 req / 30 s;
# a key raises it to 50 / 30 s. GitHub asks ~1 s between mutative calls.
_RATE_INTERVALS = {
    "nvd": 0.7 if NVD_API_KEY else 6.5,
    "osv": 0.1,
    "epss": 0.3,
    "kev": 0.0,
    "github": 1.0,
}

_last_call: dict[str, float] = {}


class LiveHTTPError(Exception):
    """HTTP failure. Permanent 4xx are not retried; 5xx/429/408 are."""

    def __init__(self, message: str, status_code: int | None = None, body: str = ""):
        super().__init__(message)
        self.status_code = status_code
        self.body = body


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


def _rate_limited(resp: requests.Response) -> bool:
    if resp.headers.get("Retry-After"):
        return True
    remaining = resp.headers.get("X-RateLimit-Remaining") or resp.headers.get(
        "x-ratelimit-remaining"
    )
    if remaining is None:
        return False
    try:
        return int(remaining) == 0
    except ValueError:
        return False


def _should_retry(status: int, resp: requests.Response) -> bool:
    if status in {408, 429} or status >= 500:
        return True
    if status == 403 and _rate_limited(resp):
        return True
    return False


def _body_snip(resp: requests.Response) -> str:
    return (resp.text or "").strip()[:800]


def request_json(
    source: str,
    method: str,
    url: str,
    *,
    params: dict | None = None,
    json_body: dict | None = None,
    headers: dict | None = None,
    allow_empty: bool = False,
) -> dict:
    last_exc: Exception | None = None
    attempts = max(1, LIVE_HTTP_RETRIES)
    for attempt in range(attempts):
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

        if resp.status_code == 204:
            if allow_empty:
                return {}
            raise LiveHTTPError(
                f"{source}: HTTP 204 empty body",
                status_code=204,
                body="",
            )

        if resp.status_code == 404:
            if source == "github":
                raise LiveNotFound("repo not found, or the token lacks access")
            raise LiveNotFound(f"{source}: 404 for {url}")

        if _should_retry(resp.status_code, resp):
            last_exc = LiveHTTPError(
                f"{source}: HTTP {resp.status_code}: {_body_snip(resp)}",
                status_code=resp.status_code,
                body=resp.text or "",
            )
            if attempt + 1 >= attempts:
                break
            _backoff(attempt, resp.headers.get("Retry-After"))
            continue

        if resp.status_code >= 400:
            raise LiveHTTPError(
                f"{source}: HTTP {resp.status_code}: {_body_snip(resp)}",
                status_code=resp.status_code,
                body=resp.text or "",
            )

        if not (resp.text or "").strip():
            if allow_empty:
                return {}
            raise LiveHTTPError(
                f"{source}: empty response body",
                status_code=resp.status_code,
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise LiveHTTPError(
                f"{source}: invalid JSON: {exc}",
                status_code=resp.status_code,
                body=resp.text or "",
            ) from exc
        if not isinstance(data, dict):
            # list endpoints are unused; wrap so callers always get a dict
            return {"_items": data} if isinstance(data, list) else {"value": data}
        return data

    raise LiveHTTPError(f"{source}: request failed") from last_exc
