"""Document store and writer helpers."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from haystack.components.writers import DocumentWriter
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.document_stores.types import DuplicatePolicy
from loguru import logger

from rag.index.store import PersistentFaissDocumentStore


def create_document_store(
  config: dict[str, Any] | None = None,
  *,
  index_dir: str | Path | None = None,
  manifest: dict[str, Any] | None = None,
  persist: bool = True,
) -> InMemoryDocumentStore | PersistentFaissDocumentStore:
  """Create either the in-memory store or the persisted FAISS-backed store."""
  config = config or {}
  backend = config.get("index", {}).get("backend", "in_memory")

  if backend == "faiss" and index_dir is not None:
    store = PersistentFaissDocumentStore(index_dir, manifest=manifest, persist=persist)
    logger.debug("Created persistent FAISS document store at {}", index_dir)
    return store

  store = InMemoryDocumentStore()
  logger.debug("Created in-memory document store")
  return store


def create_document_writer(
  document_store: InMemoryDocumentStore | PersistentFaissDocumentStore,
) -> DocumentWriter:
  """Create a document writer for the provided store."""
  writer = DocumentWriter(
    document_store=document_store,
    policy=DuplicatePolicy.OVERWRITE,
  )
  logger.debug("Created document writer")
  return writer
