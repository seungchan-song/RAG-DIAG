"""Persistent FAISS-backed document storage."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any

import faiss
import numpy as np
from haystack import Document
from haystack.document_stores.types import DuplicatePolicy
from loguru import logger

INDEX_FILENAME = "vectors.faiss"
DOCUMENTS_FILENAME = "documents.jsonl"
MANIFEST_FILENAME = "manifest.json"


@dataclass
class IndexArtifacts:
  """Paths for one persisted index."""

  root_dir: Path
  index_path: Path
  documents_path: Path
  manifest_path: Path


class PersistentFaissDocumentStore:
  """Store documents on disk as JSONL plus a FAISS inner-product index."""

  def __init__(
    self,
    root_dir: str | Path,
    *,
    manifest: dict[str, Any] | None = None,
    persist: bool = True,
  ) -> None:
    self.artifacts = IndexArtifacts(
      root_dir=Path(root_dir),
      index_path=Path(root_dir) / INDEX_FILENAME,
      documents_path=Path(root_dir) / DOCUMENTS_FILENAME,
      manifest_path=Path(root_dir) / MANIFEST_FILENAME,
    )
    self.persist = persist
    self.manifest = deepcopy(manifest or {})
    self._documents: dict[str, Document] = {}
    self._document_order: list[str] = []
    self._index: faiss.Index | None = None
    self._embedding_dim = 0
    self.artifacts.root_dir.mkdir(parents=True, exist_ok=True)

  @classmethod
  def load(
    cls,
    root_dir: str | Path,
    *,
    persist: bool = True,
  ) -> "PersistentFaissDocumentStore":
    artifacts = IndexArtifacts(
      root_dir=Path(root_dir),
      index_path=Path(root_dir) / INDEX_FILENAME,
      documents_path=Path(root_dir) / DOCUMENTS_FILENAME,
      manifest_path=Path(root_dir) / MANIFEST_FILENAME,
    )
    if not artifacts.manifest_path.exists():
      raise FileNotFoundError(f"Index manifest not found: {artifacts.manifest_path}")
    if not artifacts.documents_path.exists():
      raise FileNotFoundError(f"Index document payload not found: {artifacts.documents_path}")

    with open(artifacts.manifest_path, "r", encoding="utf-8") as file:
      manifest = json.load(file)

    store = cls(root_dir, manifest=manifest, persist=persist)
    with open(artifacts.documents_path, "r", encoding="utf-8") as file:
      for line in file:
        payload = line.strip()
        if not payload:
          continue
        document = Document.from_dict(json.loads(payload))
        store._documents[document.id] = document
        store._document_order.append(document.id)

    store._embedding_dim = int(manifest.get("embedding_dim", 0))
    if artifacts.index_path.exists():
      store._index = faiss.read_index(str(artifacts.index_path))
    elif store.count_documents() > 0:
      raise FileNotFoundError(f"FAISS index file not found: {artifacts.index_path}")
    else:
      store._index = None
    logger.info("Loaded persisted FAISS index from {}", artifacts.root_dir)
    return store

  def write_documents(
    self,
    documents: list[Document],
    policy: DuplicatePolicy = DuplicatePolicy.NONE,
  ) -> int:
    """Write documents and rebuild the FAISS index."""
    documents_written = 0
    normalized_policy = policy if policy != DuplicatePolicy.NONE else DuplicatePolicy.OVERWRITE

    for document in documents:
      if document.embedding is None:
        raise ValueError(f"Document '{document.id}' is missing an embedding")

      if document.id in self._documents:
        if normalized_policy == DuplicatePolicy.SKIP:
          continue
        if normalized_policy == DuplicatePolicy.FAIL:
          raise ValueError(f"Duplicate document id: {document.id}")
        if normalized_policy == DuplicatePolicy.OVERWRITE:
          self._documents[document.id] = _clone_document(document)
          documents_written += 1
          continue

      self._documents[document.id] = _clone_document(document)
      self._document_order.append(document.id)
      documents_written += 1

    self._rebuild_index()
    if self.persist:
      self.save()
    return documents_written

  def filter_documents(self) -> list[Document]:
    """Return all stored documents."""
    return [_clone_document(self._documents[doc_id]) for doc_id in self._document_order]

  def count_documents(self) -> int:
    """Return the number of stored documents."""
    return len(self._document_order)

  def delete_documents_by_doc_ids(self, doc_ids: list[str]) -> int:
    """Delete every chunk owned by the provided file-level doc_ids."""
    if not doc_ids:
      return 0

    target_doc_ids = {str(doc_id) for doc_id in doc_ids}
    retained_order: list[str] = []
    deleted_count = 0

    for document_id in self._document_order:
      document = self._documents[document_id]
      owner_doc_id = str(document.meta.get("doc_id") or document.id)
      if owner_doc_id in target_doc_ids:
        deleted_count += 1
        del self._documents[document_id]
        continue
      retained_order.append(document_id)

    if deleted_count == 0:
      return 0

    self._document_order = retained_order
    self._rebuild_index()
    if self.persist:
      self.save()
    return deleted_count

  def query_by_embedding(
    self,
    query_embedding: list[float],
    top_k: int = 5,
  ) -> list[Document]:
    """Return the top-k documents ranked by inner-product score."""
    if self._index is None or not self._document_order:
      return []

    query_array = np.asarray([query_embedding], dtype="float32")
    scores, indices = self._index.search(query_array, min(top_k, len(self._document_order)))

    results: list[Document] = []
    for score, index in zip(scores[0], indices[0]):
      if index < 0:
        continue
      doc_id = self._document_order[int(index)]
      document = replace(_clone_document(self._documents[doc_id]), score=float(score))
      results.append(document)
    return results

  def save(self) -> None:
    """Persist documents, FAISS vectors, and manifest to disk."""
    self.artifacts.root_dir.mkdir(parents=True, exist_ok=True)
    self._sync_manifest()

    with open(self.artifacts.documents_path, "w", encoding="utf-8") as file:
      for doc_id in self._document_order:
        document = self._documents[doc_id]
        file.write(json.dumps(document.to_dict(), ensure_ascii=False) + "\n")

    if self._index is not None:
      faiss.write_index(self._index, str(self.artifacts.index_path))
    elif self.artifacts.index_path.exists():
      self.artifacts.index_path.unlink()

    with open(self.artifacts.manifest_path, "w", encoding="utf-8") as file:
      json.dump(self.manifest, file, ensure_ascii=False, indent=2)

  def get_manifest(self) -> dict[str, Any]:
    """Return a copy of the current manifest."""
    self._sync_manifest()
    return deepcopy(self.manifest)

  def _sync_manifest(self) -> None:
    self.manifest["doc_count"] = self.count_documents()
    self.manifest["updated_at"] = datetime.now().isoformat()
    self.manifest["embedding_dim"] = self._embedding_dim
    self.manifest["documents_path"] = str(self.artifacts.documents_path)
    self.manifest["index_path"] = str(self.artifacts.index_path)

  def _rebuild_index(self) -> None:
    if not self._document_order:
      self._index = None
      self._embedding_dim = 0
      return

    embeddings = [
      self._documents[doc_id].embedding
      for doc_id in self._document_order
      if self._documents[doc_id].embedding is not None
    ]
    matrix = np.asarray(embeddings, dtype="float32")
    if matrix.ndim != 2:
      raise ValueError("Document embeddings must be a 2D matrix")

    self._embedding_dim = int(matrix.shape[1])
    index = faiss.IndexFlatIP(self._embedding_dim)
    index.add(matrix)
    self._index = index


def _clone_document(document: Document) -> Document:
  """Deep-copy a Haystack document through its dict representation."""
  return Document.from_dict(document.to_dict())
