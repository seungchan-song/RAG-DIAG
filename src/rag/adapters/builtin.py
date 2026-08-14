"""
BuiltinHaystackAdapter — 우리 RAG 를 감싸는 첫 참조 어댑터.

기존 Haystack 파이프라인(`retriever/pipeline.py`)을 TargetRAG 계약으로 감싼다.
우리 RAG 는 모든 능력을 노출하므로 Tier 2(전 능력)를 선언한다. 이 어댑터가
"어댑터 경계가 실제로 동작한다" 는 것을 증명하는 참조 구현이자, 외부 어댑터
(LangChain / AnythingLLM 등) 작성 시의 살아있는 예시다.

비파괴 보장:
  query() 는 기존 run_query() 결과를 RagTrace 로 감싸기만 하며, RagTrace.raw 에 원본을
  그대로 보존한다. 따라서 공격 엔진이 `trace.to_engine_dict()` 로 되받는 dict 는
  run_query() 가 돌려주던 것과 완전히 동일하다.

능력별 메서드 매핑:
  - query()            : 필수. 모든 시나리오.
  - system_prompt      : R7 평가 정답(config.generator.system_prompt).
  - declare_sensitive(): R2 민감 라벨 선언(우리 RAG 는 이미 doc_role 메타를 갖지만,
                         외부 라벨 주입도 받아 두어 계약을 완결한다).
  - build_variant()    : R4 반사실 인덱스. 기존 R4 non-member 재구성 로직을 캡슐화.
  - write_documents()  : R9 poison 주입. 문서를 임베딩해 인덱스에 기록.
"""

from __future__ import annotations

import tempfile
from typing import Any

from loguru import logger

from rag.adapters.base import Capability, RagTrace
from rag.ingest.writer import create_document_store
from rag.retriever.pipeline import build_rag_pipeline, run_query


def _doc_matches(document: Any, exclude_ids: set[str]) -> bool:
  """
  문서가 제외 대상 ID 집합에 해당하는지 판정합니다.

  R4 의 기존 필터 정책(`r4_membership.py:_resolve_execution_pipeline`)과 동일하게
  chunk_id / doc_id / Haystack 문서 id 중 하나라도 일치하면 제외 대상으로 본다.

  Args:
    document: Haystack Document(또는 meta/id 를 가진 객체).
    exclude_ids: 제외할 식별자 문자열 집합.

  Returns:
    bool: 제외 대상이면 True.
  """
  meta = getattr(document, "meta", {}) or {}
  candidates = {
    meta.get("chunk_id"),
    meta.get("doc_id"),
    getattr(document, "id", None),
  }
  return bool(candidates & exclude_ids)


class BuiltinHaystackAdapter:
  """
  우리 Haystack RAG 파이프라인을 TargetRAG 계약으로 감싸는 참조 어댑터.

  Attributes:
    capabilities: 노출 능력 집합. 우리 RAG 는 전 능력(Tier 2)을 노출한다.
    pipeline: 감싸는 대상 Haystack 파이프라인(build_rag_pipeline 산출물).
    config: 파이프라인 재구성·임베딩에 필요한 설정 딕셔너리.
    system_prompt: config.generator.system_prompt(있으면). R7 평가 정답.
  """

  # 우리 RAG 는 검색 원문·인덱스 조작·주입을 전부 지원하므로 전 능력을 노출한다.
  capabilities: set[Capability] = {
    Capability.QUERY,
    Capability.SYSTEM_PROMPT,
    Capability.RETRIEVAL_TRACE,
    Capability.DOC_LABELS,
    Capability.INDEX_REBUILD,
    Capability.INDEX_WRITE,
  }

  def __init__(self, pipeline: Any, config: dict[str, Any] | None = None) -> None:
    """
    BuiltinHaystackAdapter 를 초기화합니다.

    Args:
      pipeline: build_rag_pipeline() 로 만든 RAG 파이프라인.
      config: YAML 설정 딕셔너리. 반사실 인덱스 재구성·문서 임베딩·system_prompt
        추출에 사용된다.
    """
    self.pipeline = pipeline
    self.config = config or {}
    self.system_prompt: str | None = (
      (self.config.get("generator") or {}).get("system_prompt") or None
    )
    # 외부에서 declare_sensitive 로 선언된 민감 문서 식별자(우리 RAG 는 doc_role
    # 메타로도 구분하지만, 계약 완결과 외부 라벨 병합을 위해 보존한다).
    self._declared_sensitive: set[str] = set()

  def query(self, query: str) -> RagTrace:
    """
    질의를 우리 RAG 파이프라인에 투입하고 표준 트레이스를 반환합니다.

    Args:
      query: 사용자/공격 질의 문자열.

    Returns:
      RagTrace: run_query() 결과를 감싼 트레이스(raw 에 원본 보존).
    """
    result = run_query(self.pipeline, query)
    return RagTrace.from_engine_result(result)

  def declare_sensitive(self, doc_ids: Any) -> None:
    """
    민감 문서 식별자를 선언합니다(R2 라벨).

    우리 RAG 는 인덱싱 시 doc_role 메타로 민감 여부를 이미 구분하지만, 외부 라벨을
    받아 병합해 둠으로써 "라벨이 없는 남의 RAG" 와 동일한 계약 표면을 유지한다.

    Args:
      doc_ids: 민감 문서 식별자들의 순회 가능 객체.
    """
    self._declared_sensitive.update(str(doc_id) for doc_id in doc_ids)
    logger.debug(
      "BuiltinHaystackAdapter: 민감 문서 {}건 선언(누적 {}건)",
      len(list(doc_ids)) if hasattr(doc_ids, "__len__") else "?",
      len(self._declared_sensitive),
    )

  def build_variant(self, *, exclude_doc_ids: set[str]) -> "BuiltinHaystackAdapter":
    """
    특정 문서를 제외한 반사실(counterfactual) 어댑터를 만듭니다 (R4).

    기존 R4 non-member 재구성 로직(`r4_membership.py:_resolve_execution_pipeline`)을
    어댑터 경계 뒤로 캡슐화한 것이다. 저장된 문서에서 제외 대상을 걸러 새 인덱스를
    구성하고, 같은 config 로 파이프라인을 다시 빌드해 새 어댑터로 감싼다. 기존 문서는
    임베딩을 그대로 보존하므로 재임베딩이 필요 없다.

    Args:
      exclude_doc_ids: 제외할 문서 식별자 집합(chunk_id / doc_id / id).

    Returns:
      BuiltinHaystackAdapter: 대상 문서가 빠진 인덱스를 감싼 새 어댑터.
    """
    retriever = self.pipeline.get_component("retriever")
    document_store = retriever.document_store
    stored_docs = document_store.filter_documents()

    exclude = {str(doc_id) for doc_id in exclude_doc_ids}
    kept_docs = [doc for doc in stored_docs if not _doc_matches(doc, exclude)]

    # 주의: config 를 반드시 넘겨야 한다. 인자 없이 부르면 `ingest/writer.py:25` 의 backend
    # 기본값이 "in_memory" 라 반사실 인덱스만 InMemoryDocumentStore 가 됐다. 그러면
    # `retriever/retriever.py:create_retriever` 가 FAISS 대신 Haystack InMemory 리트리버를
    # 만들고, 그 쪽 run() 에는 query 파라미터가 없어(`retriever/pipeline.py:171-176`)
    # `index/store.py:query_by_embedding` 의 하이브리드 부스트(구조적 PII 정확일치 +2.0,
    # 어휘 겹침 +0.5×)를 통째로 못 탄다.
    #
    # R4 는 b=1(원본)과 b=0(반사실)의 응답 유사도 차이로 멤버십을 판정하는데, 검색
    # 알고리즘까지 달라지면 delta 가 "d* 유무" 가 아니라 "하이브리드 vs dense" 를 재게
    # 된다. RAG-2026-0811-003 실측: b=1 top-1 점수 평균 1.882(코사인 상한 1.0 을 넘는
    # 부스트 발동 49/75건) vs b=0 평균 0.398(1.0 초과 0건).
    #
    # persist=False 라 디스크에 쓰지 않지만 store 가 root_dir 을 만들므로, 임시 디렉터리를
    # 어댑터에 붙들어 두어 GC 시점에 정리되게 한다.
    variant_tmpdir = tempfile.TemporaryDirectory(prefix="rag-r4-variant-")
    variant_store = create_document_store(
      self.config, index_dir=variant_tmpdir.name, persist=False
    )
    variant_store.write_documents(kept_docs)

    logger.debug(
      "BuiltinHaystackAdapter.build_variant: 원본={}개, 제외={}, 유지={}개",
      len(stored_docs),
      exclude,
      len(kept_docs),
    )

    variant_pipeline = build_rag_pipeline(variant_store, self.config)
    variant = BuiltinHaystackAdapter(variant_pipeline, self.config)
    # 민감 라벨 선언은 반사실 세계에도 그대로 이어진다.
    variant._declared_sensitive = set(self._declared_sensitive)
    # 임시 디렉터리를 어댑터 수명에 묶는다(어댑터가 사라지면 함께 정리된다).
    variant._variant_tmpdir = variant_tmpdir
    return variant

  def write_documents(self, documents: Any) -> None:
    """
    인덱스에 새 문서를 주입합니다 (R9 poison 삽입).

    dict / Haystack Document 를 모두 받아 Document 로 정규화하고, 임베딩이 없는
    문서는 문서 임베더로 임베딩한 뒤 저장소에 기록한다. 이미 임베딩이 있는 문서는
    임베딩 단계를 건너뛰어 모델 로드를 피한다(테스트·재주입 효율).

    Args:
      documents: 주입할 문서들(dict 또는 Haystack Document)의 순회 가능 객체.
    """
    retriever = self.pipeline.get_component("retriever")
    document_store = retriever.document_store

    docs = [self._coerce_document(doc) for doc in documents]
    pending = [doc for doc in docs if getattr(doc, "embedding", None) is None]
    if pending:
      from rag.ingest.embedder import create_document_embedder

      embedder = create_document_embedder(self.config)
      embedder.warm_up()
      embedded = embedder.run(documents=pending)["documents"]
      by_id = {doc.id: doc for doc in embedded}
      docs = [by_id.get(doc.id, doc) for doc in docs]

    document_store.write_documents(docs)
    logger.debug("BuiltinHaystackAdapter.write_documents: {}건 주입", len(docs))

  @staticmethod
  def _coerce_document(doc: Any) -> Any:
    """
    dict 또는 Haystack Document 입력을 Haystack Document 로 정규화합니다.

    Args:
      doc: {"content", "doc_id"/"id", "meta"} dict 또는 Document.

    Returns:
      Document: 정규화된 Haystack 문서.
    """
    from haystack import Document

    if isinstance(doc, Document):
      return doc

    meta = dict(doc.get("meta") or {})
    doc_id = doc.get("doc_id") or doc.get("id")
    kwargs: dict[str, Any] = {"content": doc.get("content", ""), "meta": meta}
    if doc_id:
      kwargs["id"] = str(doc_id)
    return Document(**kwargs)
