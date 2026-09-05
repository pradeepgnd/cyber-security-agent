"""Per-collection retriever. Returns (text, chunk_id, score) triples."""

from __future__ import annotations

from functools import lru_cache

import chromadb

from src.config import CHROMA_DIR, COLLECTIONS
from src.rag.embeddings import chroma_embedding_function


@lru_cache(maxsize=1)
def _client() -> chromadb.PersistentClient:
    return chromadb.PersistentClient(path=str(CHROMA_DIR))


def reset_client() -> None:
    _client.cache_clear()


def get_collection(name: str):
    if name not in COLLECTIONS:
        raise ValueError(f"unknown collection {name!r}")
    return _client().get_or_create_collection(
        name=name,
        embedding_function=chroma_embedding_function(),
    )


def retrieve(collection: str, query: str, k: int = 4) -> list[tuple[str, str, float]]:
    """Return (text, chunk_id, score) triples. Score is distance (lower is better)."""
    if not query.strip():
        return []
    col = get_collection(collection)
    if col.count() == 0:
        return []
    result = col.query(query_texts=[query], n_results=min(k, max(col.count(), 1)))
    docs = (result.get("documents") or [[]])[0]
    metas = (result.get("metadatas") or [[]])[0]
    dists = (result.get("distances") or [[]])[0]
    ids = (result.get("ids") or [[]])[0]
    out: list[tuple[str, str, float]] = []
    for i, text in enumerate(docs):
        meta = metas[i] if i < len(metas) and metas[i] else {}
        chunk_id = str(meta.get("chunk_id") or (ids[i] if i < len(ids) else f"{collection}-{i}"))
        dist = float(dists[i]) if i < len(dists) else 1.0
        out.append((text or "", chunk_id, dist))
    return out


def retrieve_many(pairs: list[tuple[str, str]], k: int = 4) -> list[tuple[str, str, float]]:
    """Retrieve from several collections and merge, keeping the first k unique ids."""
    seen: set[str] = set()
    merged: list[tuple[str, str, float]] = []
    for collection, query in pairs:
        for triple in retrieve(collection, query, k=k):
            if triple[1] in seen:
                continue
            seen.add(triple[1])
            merged.append(triple)
    return merged


def collection_stats() -> dict[str, int]:
    stats: dict[str, int] = {}
    for name in COLLECTIONS:
        try:
            stats[name] = get_collection(name).count()
        except Exception:  # noqa: BLE001
            stats[name] = 0
    return stats


def resolve_chunk(chunk_id: str) -> str | None:
    """Return stored document text for a citation id, or None if unknown."""
    for name in COLLECTIONS:
        col = get_collection(name)
        try:
            got = col.get(ids=[chunk_id], include=["documents"])
            docs = got.get("documents") or []
            if docs and docs[0]:
                return docs[0]
        except Exception:  # noqa: BLE001
            pass
        try:
            got = col.get(where={"id": chunk_id}, include=["documents"])
            docs = got.get("documents") or []
            if docs and docs[0]:
                return docs[0]
        except Exception:  # noqa: BLE001
            pass
    return None


def format_retrieved(triples: list[tuple[str, str, float]]) -> str:
    if not triples:
        return "(no retrieved context)"
    blocks: list[str] = []
    for text, chunk_id, score in triples:
        blocks.append(f"[{chunk_id}] (score={score:.3f})\n{text[:900]}")
    return "\n\n".join(blocks)
