"""
CapabilityGatedAdapter — 선언된 능력 밖의 출력을 차단하는 어댑터 래퍼.

목적: **degrade(축소 진단)를 truthful 하게** 만든다.

우리 참조 어댑터(BuiltinHaystackAdapter)는 실제로 검색 원문·인덱스 조작을 전부 줄 수
있다. 그래서 "이 대상 RAG 는 응답만 준다(블랙박스)" 라고 선언해도, 감싸지 않으면
여전히 검색 원문이 트레이스에 실려 R2 가 완전판처럼 채점돼 버린다 → degrade 가
말뿐이 된다.

이 래퍼는 안쪽 어댑터가 무엇을 주든, **선언한 능력에 없는 정보는 트레이스에서 제거**
하고 **능력 밖 메서드 호출은 막는다.** 그 결과:
  · RETRIEVAL_TRACE 미선언 → 검색 원문이 빈 목록이 되어 R2 가 응답 PII 유출만 측정(축소)
  · SYSTEM_PROMPT 미선언 → system_prompt 가 None 이 되어 R7 평가 정답이 사라짐
  · INDEX_REBUILD / INDEX_WRITE 미선언 → build_variant / write_documents 가 막힘

즉 "능력이 제한된 외부 RAG" 를 충실히 시뮬레이션한다. 실제 외부 어댑터(LangChain/
AnythingLLM 등)는 애초에 제한된 정보만 반환하므로 이 래퍼 없이도 같은 결과가 나온다.
이 래퍼는 그 상황을 우리 RAG 위에서 재현·검증하고, 외부 어댑터 주입 경로를 여는
공통 경계 역할을 한다.
"""

from __future__ import annotations

from typing import Any

from loguru import logger

from rag.adapters.base import Capability, RagTrace

# RETRIEVAL_TRACE 가 없을 때 트레이스에서 비워야 하는 검색 관련 필드들.
_RETRIEVAL_FIELDS = (
  "retrieved_documents",
  "raw_retrieved_documents",
  "thresholded_documents",
  "reranked_documents",
)


class UnsupportedCapabilityError(RuntimeError):
  """선언하지 않은 능력의 메서드를 호출했을 때 발생한다."""


class CapabilityGatedAdapter:
  """
  안쪽 어댑터를 감싸 선언 능력만큼으로 출력·동작을 제한하는 래퍼.

  Attributes:
    inner: 실제 질의를 수행하는 안쪽 어댑터(예: BuiltinHaystackAdapter).
    capabilities: 이 래퍼가 노출한다고 선언한 능력 집합(진단 개방 범위).
    system_prompt: SYSTEM_PROMPT 를 선언한 경우에만 inner 의 값을 노출한다.
  """

  def __init__(self, inner: Any, capabilities: set[Capability]) -> None:
    """
    CapabilityGatedAdapter 를 초기화합니다.

    Args:
      inner: 감쌀 안쪽 어댑터(TargetRAG 계약 구현).
      capabilities: 노출을 허용할 능력 집합. QUERY 는 최소 필수이므로 항상 포함된다.
    """
    self.inner = inner
    self.capabilities: set[Capability] = set(capabilities) | {Capability.QUERY}
    self.system_prompt: str | None = (
      getattr(inner, "system_prompt", None)
      if Capability.SYSTEM_PROMPT in self.capabilities
      else None
    )

  def query(self, query: str) -> RagTrace:
    """
    안쪽 어댑터로 질의한 뒤, 선언 능력 밖 정보를 트레이스에서 제거합니다.

    Args:
      query: 질의 문자열.

    Returns:
      RagTrace: 능력에 맞게 걸러진 트레이스.
    """
    trace = self.inner.query(query)

    if Capability.RETRIEVAL_TRACE not in self.capabilities:
      # 구조화 필드와 원본 dict(raw) 양쪽에서 검색 결과를 비운다. raw 가 있으면
      # to_engine_dict() 가 raw 를 그대로 돌려주므로 raw 도 함께 정리해야 실제로
      # 검색 원문이 하위(R2 evaluator)로 흘러가지 않는다.
      trace.retrieved_documents = []
      trace.raw_retrieved_documents = []
      trace.thresholded_documents = []
      trace.reranked_documents = []
      if trace.raw:
        for field_name in _RETRIEVAL_FIELDS:
          if field_name in trace.raw:
            trace.raw[field_name] = []
        retriever_block = trace.raw.get("retriever")
        if isinstance(retriever_block, dict):
          trace.raw["retriever"] = {**retriever_block, "documents": []}

    if Capability.SYSTEM_PROMPT not in self.capabilities:
      trace.system_prompt = None

    return trace

  def declare_sensitive(self, doc_ids: Any) -> None:
    """DOC_LABELS 를 선언한 경우에만 민감 문서 라벨을 안쪽에 전달합니다."""
    self._require(Capability.DOC_LABELS, "declare_sensitive")
    self.inner.declare_sensitive(doc_ids)

  def build_variant(self, *, exclude_doc_ids: set[str]) -> "CapabilityGatedAdapter":
    """
    INDEX_REBUILD 를 선언한 경우에만 반사실 어댑터를 만듭니다(R4).

    안쪽에서 만든 반사실 어댑터도 동일한 능력 집합으로 다시 감싸, 축소 진단이 반사실
    세계에도 그대로 이어지게 한다.
    """
    self._require(Capability.INDEX_REBUILD, "build_variant")
    inner_variant = self.inner.build_variant(exclude_doc_ids=exclude_doc_ids)
    return CapabilityGatedAdapter(inner_variant, self.capabilities)

  def write_documents(self, documents: Any) -> None:
    """INDEX_WRITE 를 선언한 경우에만 문서를 주입합니다(R9)."""
    self._require(Capability.INDEX_WRITE, "write_documents")
    self.inner.write_documents(documents)

  def _require(self, capability: Capability, method_name: str) -> None:
    """능력을 선언하지 않았으면 명확한 예외를 던집니다(방어용 안전망).

    정상 흐름에서는 능력 계획(plan_scenario_execution)이 필수 능력이 없는 시나리오를
    미리 skip 하므로 이 예외는 도달하지 않아야 한다. 잘못된 직접 호출을 조용히
    넘기지 않기 위한 방어선이다.
    """
    if capability not in self.capabilities:
      logger.warning(
        "CapabilityGatedAdapter: '{}' 는 능력 {} 미선언으로 차단됨",
        method_name,
        capability.value,
      )
      raise UnsupportedCapabilityError(
        f"{method_name} 는 능력 '{capability.value}' 을 요구하지만 선언되지 않았습니다."
      )
