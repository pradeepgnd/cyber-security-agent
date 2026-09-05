from __future__ import annotations

from src.config import CACHE_DIR
from src.cache import cache_path
from src.scenarios import (
    MAX_UPLOAD_BYTES,
    MAX_UPLOAD_FILES,
    UploadError,
    classify_file,
    load_uploaded,
)


class FakeUpload:
    def __init__(self, name: str, content: bytes, *, size: int | None = None):
        self.name = name
        self._content = content
        if size is not None:
            self.size = size

    def getvalue(self) -> bytes:
        return self._content


def test_classify_manifest_vs_log() -> None:
    assert classify_file("Dockerfile.prod") == "artifact"
    assert classify_file("requirements.txt") == "artifact"
    assert classify_file("package.json") == "artifact"
    assert classify_file("app.csproj") == "artifact"
    assert classify_file("mylog.txt") == "log"
    assert classify_file("messages.txt") == "log"
    assert classify_file("auth.log") == "log"


def test_upload_id_deterministic_and_content_sensitive() -> None:
    a = load_uploaded([FakeUpload("mylog.txt", b"hello")])
    b = load_uploaded([FakeUpload("mylog.txt", b"hello")])
    c = load_uploaded([FakeUpload("mylog.txt", b"hello!")])
    assert a["scenario_id"] == b["scenario_id"]
    assert a["scenario_id"].startswith("upload-")
    assert len(a["scenario_id"]) == len("upload-") + 8
    assert c["scenario_id"] != a["scenario_id"]
    assert "mylog.txt" in a["raw_logs"]
    assert a["artifacts"] == {}
    assert "uploaded file(s)" in a["meta"]["summary"]


def test_dockerfile_and_requirements_are_artifacts() -> None:
    bundle = load_uploaded(
        [
            FakeUpload("Dockerfile.prod", b"FROM openjdk:11\n"),
            FakeUpload("requirements.txt", b"flask==2.2.2\n"),
        ]
    )
    assert "Dockerfile.prod" in bundle["artifacts"]
    assert "requirements.txt" in bundle["artifacts"]
    assert bundle["raw_logs"] == {}


def test_size_cap_rejects() -> None:
    blob = b"x" * (MAX_UPLOAD_BYTES + 1)
    try:
        load_uploaded([FakeUpload("big.txt", blob)])
    except UploadError as exc:
        assert "2 MB" in str(exc) or str(MAX_UPLOAD_BYTES) in str(exc)
    else:
        raise AssertionError("expected UploadError")


def test_count_cap_rejects() -> None:
    files = [FakeUpload(f"f{i}.txt", b"ok") for i in range(MAX_UPLOAD_FILES + 1)]
    try:
        load_uploaded(files)
    except UploadError as exc:
        assert "too many" in str(exc).lower()
    else:
        raise AssertionError("expected UploadError")


def test_cache_path_traversal_stays_inside_cache_dir() -> None:
    root = CACHE_DIR.resolve()
    path = cache_path("../../etc/passwd").resolve()
    assert path.parent == root
    assert ".." not in path.name
    sneaky = cache_path("foo/../../../etc/passwd").resolve()
    assert sneaky.parent == root
