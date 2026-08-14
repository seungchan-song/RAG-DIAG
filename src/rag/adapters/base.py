"""
BYO-RAG 어댑터 계약 (A-2 · Bring-Your-Own-RAG)

이 모듈은 "진단 대상 RAG" 를 추상화하는 표준 인터페이스를 정의한다.
지금까지 공격 엔진은 우리가 만든 Haystack 파이프라인(`retriever/pipeline.py:run_query`)을
직접 호출했기 때문에, 우리 RAG 안에서만 진단이 돌아갔다. 어댑터 계층을 두면 남이
운영 중인 RAG(LangChain / LlamaIndex / AnythingLLM 등) 에도 "그 RAG 가 어떤 능력을
노출하느냐" 만큼 그대로 진단을 붙일 수 있다.

핵심 개념 세 가지:
  - Capability : 어댑터가 노출하는 "능력" 열거형. 노출한 능력만큼 상위 시나리오가 열린다.
  - RagTrace   : 한 번의 질의 결과를 담는 표준 자료구조. answer(필수) + 검색 원문·최종
                 프롬프트(선택). 우리 엔진의 기존 트레이스 dict 와 상호 변환된다.
  - TargetRAG  : 어댑터가 구현해야 하는 프로토콜(계약). `query()` 와 `capabilities` 만
                 필수이고, 나머지(system_prompt / declare_sensitive / build_variant /
                 write_documents)는 능력에 따라 선택적으로 구현한다.

설계 원칙(비파괴):
  RagTrace 는 기존 `run_query()` 반환 dict 를 그대로 감싸고(`raw`), 다시 그 dict 로
  복원(`to_engine_dict()`)할 수 있다. 따라서 우리 참조 어댑터(BuiltinHaystackAdapter)를
  경유해도 공격 엔진이 받는 dict 는 기존과 완전히 동일하다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable


class Capability(str, Enum):
  """
  어댑터가 노출하는 능력 열거형.

  각 능력은 특정 시나리오를 여는 열쇠다. 능력이 많을수록 더 깊은(완전판) 진단이
  가능하고, 능력이 적으면 블랙박스 수준(응답만 보는) 진단으로 자동 축소(degrade)된다.

  능력계층(Tier) 요약:
    - Tier 0 : QUERY (+ 선택 SYSTEM_PROMPT)      → NORMAL · R7 · R9 판정 · PII 유출 탐지
    - Tier 1 : + RETRIEVAL_TRACE · DOC_LABELS    → R2 완전판(검색 원문 대조)
    - Tier 2 : + INDEX_REBUILD / INDEX_WRITE     → R4(반사실 페어) · R9(poison 주입) 완전판

  str 을 상속해 JSON 직렬화·문자열 비교가 자연스럽도록 한다(리포트 저장 시 유용).
  """

  # 모든 어댑터가 반드시 노출해야 하는 최소 능력. query() -> RagTrace.
  QUERY = "query"
  # system_prompt 속성을 노출. R7(시스템 프롬프트 노출) 평가의 "정답"으로 쓰인다.
  SYSTEM_PROMPT = "system_prompt"
  # 응답과 함께 검색된 문서 원문을 노출. R2(검색 데이터 유출) ROUGE 대조에 필요.
  RETRIEVAL_TRACE = "retrieval_trace"
  # 어떤 문서가 민감(sensitive)한지 라벨을 선언. 우리 RAG 의 doc_role 라벨 대체.
  DOC_LABELS = "doc_labels"
  # 특정 문서를 제외한 반사실(counterfactual) 인덱스를 재구성. R4 멤버십 추론에 필요.
  INDEX_REBUILD = "index_rebuild"
  # 인덱스에 새 문서를 주입. R9 간접 프롬프트 주입(poison 삽입)에 필요.
  INDEX_WRITE = "index_write"


# 리포트·로그에 사람이 읽을 수 있게 노출하기 위한 한국어 라벨.
#
# 이 라벨은 성격이 다른 두 문장에 동시에 들어간다 — 어댑터 쪽 사유("권장 능력 부족으로
# 축소 진단: …")와 공격자 쪽 권한("내용 인지 관찰자 (A2) — 질의 · 민감 문서 식별").
# 그래서 양쪽에서 다 읽히는 행위 표현으로 통일한다. 구현 어휘(인덱스·트레이스·선언·
# 영문 병기)는 쓰지 않는다 — 리포트를 읽는 사람은 우리 내부 구조를 모른다.
# 리포트 본문에서 이미 쓰는 말과 맞춘다: "질의", "이 질의가 근거로 삼은 문서" → "근거 문서".
CAPABILITY_LABELS: dict[Capability, str] = {
  Capability.QUERY: "질의",
  Capability.SYSTEM_PROMPT: "시스템 프롬프트 열람",
  Capability.RETRIEVAL_TRACE: "근거 문서 열람",
  Capability.DOC_LABELS: "민감 문서 식별",
  Capability.INDEX_REBUILD: "특정 문서 빼고 재구성",
  Capability.INDEX_WRITE: "문서 추가",
}


@dataclass
class RagTrace:
  """
  한 번의 RAG 질의 결과를 담는 표준 자료구조.

  어댑터의 `query()` 가 돌려주는 계약형 결과다. 최소한 `answer` 만 채우면 되고,
  능력이 되는 어댑터는 검색 원문(`retrieved_documents`)·최종 프롬프트(`final_prompt`)
  까지 채워 상위 시나리오(R2 등)를 연다.

  Attributes:
    answer: LLM 최종 응답 텍스트(필수).
    retrieved_documents: 검색되어 프롬프트에 들어간 문서들의 직렬화 목록.
      각 항목 예시: {"id", "score", "content", "meta"}.
    final_prompt: generator 에 실제로 투입된 최종 프롬프트 문자열.
    system_prompt: 이 질의에 적용된 시스템 프롬프트(있으면). R7 평가 참고용.
    profile_name: 검색 프로파일 이름(reranker_off / reranker_on 등).
    retrieval_config: 검색 관련 설정 스냅샷.
    reranker_enabled: 리랭커 활성 여부.
    raw_retrieved_documents / thresholded_documents / reranked_documents:
      우리 엔진이 노출하는 단계별 검색 스냅샷(외부 어댑터는 비어 있을 수 있음).
    metadata: 어댑터별 부가 정보.
    raw: 원본 엔진 트레이스 dict(우리 파이프라인 경유 시 완전 재현용).
      비어 있으면 외부 어댑터로 간주하고 `to_engine_dict()` 가 구조화 필드로 합성한다.
  """

  answer: str = ""
  retrieved_documents: list[dict[str, Any]] = field(default_factory=list)
  final_prompt: str = ""
  system_prompt: str | None = None
  profile_name: str = ""
  retrieval_config: dict[str, Any] = field(default_factory=dict)
  reranker_enabled: bool = False
  raw_retrieved_documents: list[dict[str, Any]] = field(default_factory=list)
  thresholded_documents: list[dict[str, Any]] = field(default_factory=list)
  reranked_documents: list[dict[str, Any]] = field(default_factory=list)
  metadata: dict[str, Any] = field(default_factory=dict)
  raw: dict[str, Any] = field(default_factory=dict)

  @classmethod
  def from_engine_result(cls, result: dict[str, Any]) -> "RagTrace":
    """
    우리 엔진의 `run_query()` 반환 dict 를 RagTrace 로 변환합니다.

    원본 dict 는 `raw` 에 그대로 보존하므로, `to_engine_dict()` 로 되돌리면 손실 없이
    동일한 dict 를 얻는다(비파괴 보장). 구조화 필드(answer 등)는 편의 접근용이다.

    Args:
      result: `rag.retriever.pipeline.run_query()` 가 돌려준 트레이스 dict.

    Returns:
      RagTrace: 구조화 필드가 채워지고 raw 에 원본이 보존된 트레이스.
    """
    replies = (result.get("generator") or {}).get("replies") or []
    answer = replies[0] if replies else ""
    return cls(
      answer=answer,
      retrieved_documents=list(result.get("retrieved_documents") or []),
      final_prompt=result.get("final_prompt") or result.get("prompt") or "",
      profile_name=result.get("profile_name", ""),
      retrieval_config=dict(result.get("retrieval_config") or {}),
      reranker_enabled=bool(result.get("reranker_enabled", False)),
      raw_retrieved_documents=list(result.get("raw_retrieved_documents") or []),
      thresholded_documents=list(result.get("thresholded_documents") or []),
      reranked_documents=list(result.get("reranked_documents") or []),
      raw=result,
    )

  def to_engine_dict(self) -> dict[str, Any]:
    """
    공격 엔진이 소비하는 트레이스 dict 로 변환합니다.

    - 우리 파이프라인 경유(`raw` 존재): 원본 dict 를 그대로 반환 → 기존 동작과 완전 동일.
    - 외부 어댑터(`raw` 비어 있음): 구조화 필드로부터 동일 스키마의 dict 를 합성한다.
      공격 엔진이 실제로 읽는 키(generator.replies / retrieved_documents / prompt /
      retrieval_config / reranker_enabled 등)를 빠짐없이 채워 하위 호환을 보장한다.

    Returns:
      dict: 공격 시나리오 `execute()` 들이 `trace.get(...)` 로 읽는 트레이스 dict.
    """
    if self.raw:
      return self.raw
    return {
      "query": "",
      "prompt": self.final_prompt,
      "final_prompt": self.final_prompt,
      "profile_name": self.profile_name,
      "retrieval_config": self.retrieval_config,
      "reranker_enabled": self.reranker_enabled,
      "context_empty": not self.answer,
      "retrieved_documents": self.retrieved_documents,
      # 외부 어댑터는 단계별 스냅샷을 안 줄 수 있으므로 최종 검색 결과로 대체한다.
      "raw_retrieved_documents": self.raw_retrieved_documents or self.retrieved_documents,
      "thresholded_documents": self.thresholded_documents or self.retrieved_documents,
      "reranked_documents": self.reranked_documents,
      "retriever": {"documents": []},
      "generator": {
        "replies": [self.answer] if self.answer else [],
        "meta": [],
      },
      # 대상 RAG 가 스스로 보고한 부가 정보(가드레일 차단 여부·탐지기 판정 등).
      # 이걸 빠뜨리면 "유출이 없었다"와 "대상의 방어가 막았다"를 리포트에서
      # 구분할 수 없다 — 방어 효과 정량화가 이 프로젝트의 핵심 주장이므로 필수.
      "target_metadata": self.metadata,
    }


@runtime_checkable
class TargetRAG(Protocol):
  """
  진단 대상 RAG 가 구현해야 하는 표준 계약(프로토콜).

  필수 멤버는 `capabilities`(노출 능력 집합)와 `query()` 두 개뿐이다. 나머지는
  능력에 따라 선택적으로 구현하며, 존재 여부는 프로토콜이 아니라 `capabilities`
  집합으로 판정한다(`has_capability()` 참조). 즉 "메서드가 있다/없다" 가 아니라
  "그 능력을 노출한다고 선언했다/안 했다" 가 진단 개방의 기준이다.

  선택 멤버(능력별):
    - system_prompt: str | None            (SYSTEM_PROMPT) — R7 평가 정답
    - declare_sensitive(doc_ids) -> None    (DOC_LABELS)    — R2 민감 라벨 선언
    - build_variant(*, exclude_doc_ids)     (INDEX_REBUILD) — R4 반사실 인덱스
        -> TargetRAG
    - write_documents(documents) -> None    (INDEX_WRITE)   — R9 poison 주입

  이렇게 경계를 `query() -> RagTrace` 로 정의하는 이유: 결합점은 단순한
  `run_query()->str` 한 곳이 아니라 trace 스키마 전반(replies · retrieved_documents ·
  final_prompt)이기 때문이다. 스키마 전체를 어댑터 경계로 감싼다.
  """

  # 이 어댑터가 노출하는 능력 집합. 진단 개방 범위를 결정한다.
  capabilities: set[Capability]

  def query(self, query: str) -> RagTrace:
    """질의 문자열을 대상 RAG 에 투입하고 표준 트레이스를 반환합니다."""
    ...


def has_capability(target: Any, capability: Capability) -> bool:
  """
  대상 어댑터가 특정 능력을 노출하는지 확인합니다.

  `capabilities` 속성이 없어도(잘못 구현된 어댑터) 예외 없이 False 를 돌려준다.

  Args:
    target: 어댑터 인스턴스(또는 capabilities 속성을 가진 객체).
    capability: 확인할 Capability.

  Returns:
    bool: 해당 능력을 노출하면 True.
  """
  return capability in getattr(target, "capabilities", set())
