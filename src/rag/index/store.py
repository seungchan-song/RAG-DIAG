"""Persistent FAISS-backed document storage."""

from __future__ import annotations

import json
import re
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

# === PII 및 특정 식별자 추출용 정규식 패턴 (query_generator.py의 SENSITIVE_IDENTIFIER_PATTERNS 참고) ===
_ASCII_BOUNDARY_PREFIX: str = r'(?<![A-Za-z0-9])'
_ASCII_BOUNDARY_SUFFIX: str = r'(?![A-Za-z0-9])'

STRUCTURAL_PATTERNS: list[str] = [
  # 1. SYNTH-* 합성 ID
  r'SYNTH-[A-Z]+-[A-Z0-9]+(?:-[A-Z0-9]+)?',
  # 2. 주민등록번호
  _ASCII_BOUNDARY_PREFIX + r'\d{6}-[1-4]\d{6}' + _ASCII_BOUNDARY_SUFFIX,
  # 3. 신용카드
  _ASCII_BOUNDARY_PREFIX + r'\d{4}-\d{4}-\d{4}-\d{4}' + _ASCII_BOUNDARY_SUFFIX,
  # 4. 이메일 주소
  _ASCII_BOUNDARY_PREFIX + r'[\w.+-]+@[\w.-]+\.[a-z]{2,}' + _ASCII_BOUNDARY_SUFFIX,
  # 5. 한국 휴대전화
  _ASCII_BOUNDARY_PREFIX + r'01[016789]-\d{3,4}-\d{4}' + _ASCII_BOUNDARY_SUFFIX,
  # 6. 일반 유선전화
  _ASCII_BOUNDARY_PREFIX + r'0[2-6]\d?-\d{3,4}-\d{4}' + _ASCII_BOUNDARY_SUFFIX,
  # 7. 인터넷전화/특수번호
  _ASCII_BOUNDARY_PREFIX + r'0[57]0-\d{3,4}-\d{4}' + _ASCII_BOUNDARY_SUFFIX,
  # 8. 운전면허번호
  _ASCII_BOUNDARY_PREFIX + r'\d{2}-\d{2}-\d{6}-\d{2}' + _ASCII_BOUNDARY_SUFFIX,
  # 9. 사업자등록번호
  _ASCII_BOUNDARY_PREFIX + r'\d{3}-\d{2}-\d{5}' + _ASCII_BOUNDARY_SUFFIX,
  # 10. 계좌번호 패턴
  _ASCII_BOUNDARY_PREFIX + r'\d{3}-\d{2,3}-\d{6}' + _ASCII_BOUNDARY_SUFFIX,
  # 11. 여권번호
  _ASCII_BOUNDARY_PREFIX + r'[A-Z]\d{8}' + _ASCII_BOUNDARY_SUFFIX,
  # 12. 한국 차량번호
  r'\d{2,3}[가-힣]\d{4}'
]
STRUCTURAL_PATTERN = re.compile("|".join(STRUCTURAL_PATTERNS))

# === 일반 검색어 추출을 위한 한국어 조사 및 템플릿 명령어 지시어 집합 (Stopwords) ===
LEXICAL_STOPWORDS = {
  # 한국어 조사/어미
  "이", "그", "저", "것", "수", "등", "및", "를", "을", "에", "의", "가", "는", "은", "로", "으로", "에서", "도", "만", "다", "하다", "있다", "없다", "되다", "이다", "않다",
  # RAG 메타어/디스클레이머
  "정상", "문서", "문서는", "문서를", "문서가", "문서다", "문서로", "문서에", "안내", "합성", "데이터셋", "평가용", "평가", "운영", "참고", "본문", "실험자", "실험", "검수", "노트", "포함", "관련", "내용", "정보", "docsearch", "pro",
  # R2/R4/R7/R9 공격 템플릿에 공통적으로 나타나는 지시어들
  "내용을", "원문", "그대로", "출력해주세요", "모든", "정보를", "상세하게", "알려주세요", "검색된", "전체", "텍스트를", "빠짐없이", "보여주세요", "해당", "최대한", "정확하게", "재현해주세요", "결과에서", "가져온", "원본", "전문률", "출력하세요", "나와", "있는", "수정", "없이", "자료의", "복사해서", "전체를", "나열해주세요", "많이", "포함해서", "답변해주세요", "요약하지", "말고", "찾아주세요", "자료를", "대해", "상세", "궁금합니다", "검색해주세요", "자세히", "설명해주세요", "관한", "주요", "요약해주세요", "연결된", "핵심", "정리해주세요", "세부", "사항을", "제공해주세요", "시스템에", "있나요", "어디", "누구", "무엇"
}


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
    logger.debug("Loaded persisted FAISS index from {}", artifacts.root_dir)
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
    query_text: str | None = None,
  ) -> list[Document]:
    """Return the top-k documents ranked by inner-product score (with hybrid search if query_text is given)."""
    if self._index is None or not self._document_order:
      return []

    # If query_text is not provided or empty, perform standard dense FAISS retrieval
    if not query_text:
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

    # Perform Hybrid Retrieval
    # 1. Obtain dense scores for all documents in the store via FAISS
    num_docs = len(self._document_order)
    query_array = np.asarray([query_embedding], dtype="float32")
    scores, indices = self._index.search(query_array, num_docs)

    dense_scores = {}
    for score, index in zip(scores[0], indices[0]):
      if index >= 0:
        dense_scores[int(index)] = float(score)

    # 2. Extract structural keywords (PIIs, Synth IDs)
    structural_keywords = STRUCTURAL_PATTERN.findall(query_text)

    # 3. Extract general keywords (words >= 2 chars that are not stopwords)
    all_words = re.findall(r"[0-9A-Za-z가-힣]{2,}", query_text)
    general_keywords = set()
    for word in all_words:
      word_lower = word.lower()
      if word_lower not in LEXICAL_STOPWORDS and word not in structural_keywords:
        general_keywords.add(word_lower)

    # 4. Compute hybrid scores for all documents
    candidate_docs = []
    for idx, doc_id in enumerate(self._document_order):
      doc = self._documents[doc_id]
      dense_score = dense_scores.get(idx, 0.0)

      # 4a. Structural match boost (exact match for phone, email, synth ID, RRN etc.)
      structural_boost = 0.0
      for kw in structural_keywords:
        if kw in doc.content:
          structural_boost += 2.0

      # 4b. General keyword overlap lexical boost
      lexical_boost = 0.0
      if general_keywords:
        doc_words = set(re.findall(r"[0-9A-Za-z가-힣]{2,}", doc.content.lower()))
        overlap = len(general_keywords & doc_words)
        lexical_boost = 0.5 * (overlap / len(general_keywords))

      hybrid_score = dense_score + structural_boost + lexical_boost
      candidate_docs.append((hybrid_score, doc_id, dense_score, structural_boost, lexical_boost))

    # 5. Sort by hybrid score in descending order
    candidate_docs.sort(key=lambda x: x[0], reverse=True)

    # 6. Retrieve top-k results and attach audit metadata
    results: list[Document] = []
    for hybrid_score, doc_id, d_score, s_boost, l_boost in candidate_docs[:top_k]:
      document = replace(_clone_document(self._documents[doc_id]), score=float(hybrid_score))
      document.meta["retrieval_meta"] = {
        "dense_score": float(d_score),
        "structural_boost": float(s_boost),
        "lexical_boost": float(l_boost),
        "hybrid_score": float(hybrid_score),
      }
      results.append(document)

    logger.debug(
      "Hybrid retrieval completed: matched {} general keywords, {} structural keywords. Top document score: {:.4f}",
      len(general_keywords),
      len(structural_keywords),
      results[0].score if results else 0.0,
    )
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
