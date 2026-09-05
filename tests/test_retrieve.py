"""Retrieval smoke tests — require `python scripts/build_kb.py` first."""

from __future__ import annotations

import pytest

from src.rag.retrievers import collection_stats, resolve_chunk, retrieve


@pytest.fixture(scope="module")
def kb_ready() -> None:
    stats = collection_stats()
    if not stats.get("cve") or not stats.get("detections"):
        pytest.skip("Chroma index is empty — run python scripts/build_kb.py")


def test_log4shell_is_top_cve_hit(kb_ready) -> None:
    hits = retrieve("cve", "log4j jndi rce", k=3)
    assert hits
    assert "CVE-2021-44228" in hits[0][1]


def test_brute_force_detection_retrieved(kb_ready) -> None:
    hits = retrieve("detections", "repeated failed password", k=3)
    ids = " ".join(cid for _, cid, _ in hits)
    assert "det-ssh-brute-force" in ids or "brute" in ids.lower()


def test_citation_resolves(kb_ready) -> None:
    text = resolve_chunk("CVE-2021-44228")
    assert text and "Log4Shell" in text
