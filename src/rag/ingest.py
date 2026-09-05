"""Markdown + YAML frontmatter → chunks → five Chroma collections."""

from __future__ import annotations

from pathlib import Path

import chromadb
import frontmatter

from src.config import CHROMA_DIR, COLLECTIONS, KB_DIR
from src.rag.embeddings import chroma_embedding_function

CHUNK_SIZE = 800
CHUNK_OVERLAP = 100
META_KEYS = ("id", "title", "source", "type", "tags", "severity")


def chunk_text(text: str, size: int = CHUNK_SIZE, overlap: int = CHUNK_OVERLAP) -> list[str]:
    text = text.strip()
    if not text:
        return [""]
    if len(text) <= size:
        return [text]
    chunks: list[str] = []
    start = 0
    while start < len(text):
        end = min(len(text), start + size)
        chunks.append(text[start:end])
        if end == len(text):
            break
        start = max(0, end - overlap)
    return chunks


def _stringify_meta(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, list):
        return ",".join(str(v) for v in value)
    return str(value)


def load_kb_docs(collection: str) -> list[dict]:
    folder = KB_DIR / collection
    docs: list[dict] = []
    if not folder.exists():
        return docs
    for path in sorted(folder.glob("*.md")):
        post = frontmatter.load(path)
        meta = {k: post.metadata.get(k) for k in META_KEYS}
        meta["path"] = str(path.relative_to(KB_DIR))
        docs.append({"meta": meta, "text": post.content, "path": path})
    return docs


def get_client() -> chromadb.PersistentClient:
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)
    return chromadb.PersistentClient(path=str(CHROMA_DIR))


def rebuild_collections(wipe: bool = True) -> dict[str, dict[str, int]]:
    client = get_client()
    embed_fn = chroma_embedding_function()
    stats: dict[str, dict[str, int]] = {}
    for name in COLLECTIONS:
        if wipe:
            try:
                client.delete_collection(name)
            except Exception:  # noqa: BLE001 — collection may not exist
                pass
        collection = client.get_or_create_collection(
            name=name,
            embedding_function=embed_fn,
            metadata={"hnsw:space": "cosine"},
        )
        docs = load_kb_docs(name)
        ids: list[str] = []
        documents: list[str] = []
        metadatas: list[dict] = []
        for doc in docs:
            doc_id = str(doc["meta"].get("id") or Path(doc["path"]).stem)
            pieces = chunk_text(doc["text"])
            for i, piece in enumerate(pieces):
                chunk_id = doc_id if len(pieces) == 1 else f"{doc_id}#chunk-{i}"
                ids.append(chunk_id)
                documents.append(f"{doc['meta'].get('title', doc_id)}\n\n{piece}")
                metadatas.append(
                    {
                        "id": doc_id,
                        "chunk_id": chunk_id,
                        "title": _stringify_meta(doc["meta"].get("title")),
                        "source": _stringify_meta(doc["meta"].get("source")),
                        "type": _stringify_meta(doc["meta"].get("type") or name),
                        "tags": _stringify_meta(doc["meta"].get("tags")),
                        "severity": _stringify_meta(doc["meta"].get("severity")),
                    }
                )
        if ids:
            collection.add(ids=ids, documents=documents, metadatas=metadatas)
        stats[name] = {"docs": len(docs), "chunks": len(ids)}
    return stats
