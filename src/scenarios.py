"""Load local synthetic scenarios and analyst-uploaded files."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from typing import Any, Literal

from src.config import SCENARIOS_DIR

LOG_NAMES = {"auth.log", "syslog", "nginx_access.log", "app.log", "secure"}

MANIFEST_NAMES = {
    "requirements.txt",
    "pom.xml",
    "package.json",
    "go.mod",
    "gemfile",
    "pipfile",
    "build.gradle",
    "cargo.toml",
}
MANIFEST_SUFFIXES = {".csproj", ".gradle"}

MAX_UPLOAD_FILES = 10
MAX_UPLOAD_BYTES = 2 * 1024 * 1024


class UploadError(ValueError):
    """Raised when an upload is rejected (count, size, or empty)."""


def list_scenarios() -> list[str]:
    if not SCENARIOS_DIR.exists():
        return []
    return sorted(
        p.name
        for p in SCENARIOS_DIR.iterdir()
        if p.is_dir() and (p / "meta.json").exists()
    )


def load_scenario(scenario_id: str) -> dict:
    folder = SCENARIOS_DIR / scenario_id
    if not folder.exists():
        raise FileNotFoundError(f"unknown scenario {scenario_id!r}")
    meta = json.loads((folder / "meta.json").read_text())
    raw_logs: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    for path in sorted(folder.iterdir()):
        if path.name == "meta.json" or not path.is_file():
            continue
        text = path.read_text(errors="replace")
        if path.name in LOG_NAMES or path.suffix == ".log":
            raw_logs[path.name] = text
        else:
            artifacts[path.name] = text
    return {
        "scenario_id": scenario_id,
        "meta": meta,
        "raw_logs": raw_logs,
        "artifacts": artifacts,
    }


def is_manifest(name: str) -> bool:
    low = name.lower().rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return (
        low in MANIFEST_NAMES
        or "dockerfile" in low
        or any(low.endswith(s) for s in MANIFEST_SUFFIXES)
    )


def classify_file(name: str) -> Literal["log", "artifact"]:
    return "artifact" if is_manifest(name) else "log"


def _file_bytes(item: Any) -> bytes:
    if hasattr(item, "getvalue"):
        data = item.getvalue()
    elif hasattr(item, "read"):
        data = item.read()
    elif isinstance(item, (bytes, bytearray)):
        data = bytes(item)
    else:
        raise UploadError(f"cannot read upload {getattr(item, 'name', item)!r}")
    if isinstance(data, str):
        return data.encode("utf-8")
    return bytes(data)


def _file_name(item: Any) -> str:
    name = getattr(item, "name", None)
    if not name:
        raise UploadError("uploaded file is missing a name")
    return str(name).rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def load_uploaded(files: Iterable[Any]) -> dict:
    """Build the same bundle as `load_scenario` from in-memory uploads.

    Manifests (requirements, Dockerfiles, lockfiles, …) become artifacts;
    everything else is treated as a log. Uploads are never written under
    `data/scenarios/`.
    """
    items = list(files)
    if not items:
        raise UploadError("no files uploaded")
    if len(items) > MAX_UPLOAD_FILES:
        raise UploadError(
            f"too many files ({len(items)}). Maximum is {MAX_UPLOAD_FILES}."
        )

    decoded: list[tuple[str, bytes, str]] = []
    for item in items:
        name = _file_name(item)
        size_hint = getattr(item, "size", None)
        if isinstance(size_hint, int) and size_hint > MAX_UPLOAD_BYTES:
            raise UploadError(
                f"{name} is {size_hint} bytes; maximum is {MAX_UPLOAD_BYTES} (2 MB)."
            )
        raw = _file_bytes(item)
        if len(raw) > MAX_UPLOAD_BYTES:
            raise UploadError(
                f"{name} is {len(raw)} bytes; maximum is {MAX_UPLOAD_BYTES} (2 MB)."
            )
        text = raw.decode("utf-8", errors="replace")
        decoded.append((name, raw, text))

    digest = hashlib.sha1()
    for name, raw, _text in sorted(decoded, key=lambda row: (row[0], row[1])):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(raw)
        digest.update(b"\0")
    scenario_id = f"upload-{digest.hexdigest()[:8]}"

    names = [name for name, _raw, _text in decoded]
    raw_logs: dict[str, str] = {}
    artifacts: dict[str, str] = {}
    seen: dict[str, int] = {}
    for name, _raw, text in decoded:
        seen[name] = seen.get(name, 0) + 1
        key = name if seen[name] == 1 else f"{name}#{seen[name]}"
        if classify_file(name) == "artifact":
            artifacts[key] = text
        else:
            raw_logs[key] = text

    return {
        "scenario_id": scenario_id,
        "meta": {
            "summary": f"{len(decoded)} uploaded file(s): {', '.join(names)}",
        },
        "raw_logs": raw_logs,
        "artifacts": artifacts,
    }
