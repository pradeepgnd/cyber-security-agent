"""Local ONNX MiniLM embeddings — chromadb DefaultEmbeddingFunction (~80 MB, no torch)."""

from __future__ import annotations

from functools import lru_cache

from chromadb.utils.embedding_functions import DefaultEmbeddingFunction
from langchain_core.embeddings import Embeddings


@lru_cache(maxsize=1)
def chroma_embedding_function() -> DefaultEmbeddingFunction:
    return DefaultEmbeddingFunction()


class ChromaDefaultEmbeddings(Embeddings):
    """Thin LangChain adapter around chromadb's ONNX MiniLM."""

    def __init__(self) -> None:
        self._fn = chroma_embedding_function()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return list(self._fn(texts))

    def embed_query(self, text: str) -> list[float]:
        return list(self._fn([text])[0])
