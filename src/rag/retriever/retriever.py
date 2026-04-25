"""Retriever factory and FAISS-backed retrieval component."""

from __future__ import annotations

from typing import Any

from haystack import component
from haystack.document_stores.in_memory import InMemoryDocumentStore
from loguru import logger

from rag.index.store import PersistentFaissDocumentStore


@component
class FaissEmbeddingRetriever:
  """A thin Haystack-compatible retriever backed by a persisted FAISS index."""

  def __init__(
    self,
    document_store: PersistentFaissDocumentStore,
    *,
    top_k: int = 5,
  ) -> None:
    self.document_store = document_store
    self.top_k = top_k

  @component.output_types(documents=list)
  def run(
    self,
    query_embedding: list[float],
  ) -> dict[str, Any]:
    documents = self.document_store.query_by_embedding(query_embedding, top_k=self.top_k)
    return {"documents": documents}


def create_retriever(
  document_store: InMemoryDocumentStore | PersistentFaissDocumentStore,
  config: dict[str, Any],
) -> Any:
  """Create the appropriate retriever for the configured store."""
  retriever_config = config.get("retriever", {})
  top_k = int(retriever_config.get("top_k", 5))

  if isinstance(document_store, PersistentFaissDocumentStore):
    retriever = FaissEmbeddingRetriever(document_store=document_store, top_k=top_k)
    logger.debug("Created FAISS retriever (top_k={})", top_k)
    return retriever

  from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever

  retriever = InMemoryEmbeddingRetriever(
    document_store=document_store,
    top_k=top_k,
  )
  logger.debug("Created in-memory retriever (top_k={})", top_k)
  return retriever
