"""Shared attack interfaces and result models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from haystack import Pipeline

if TYPE_CHECKING:
  from rag.adapters.base import TargetRAG


@dataclass
class AttackResult:
  """One evaluated attack execution."""

  scenario: str
  query: str
  response: str
  query_id: str = ""
  environment_type: str = ""
  profile_name: str = ""
  scenario_scope: str = ""
  dataset_scope: str = ""
  dataset_selection_mode: str = ""
  index_manifest_ref: str = ""
  suite_run_id: str = ""
  suite_cell_id: str = ""
  cell_environment: str = ""
  cell_profile_name: str = ""
  replayed_from_run_id: str = ""
  target_text: str = ""
  response_masked: str = ""
  masking_applied: bool = False
  pii_summary: dict[str, Any] = field(default_factory=dict)
  pii_findings: list[dict[str, Any]] = field(default_factory=list)
  # 정규식 구조는 PII 와 일치했으나 체크섬(mod11/Luhn) 검증을 통과하지 못해
  # 확정 목록에서 제외된 항목. 미탐(누락)이 아니라 의도적 제외임을 리포트에서
  # 구분해 보여주기 위해 사유와 함께 별도 트랙으로 보존한다. 위험도/탐지 건수
  # 집계에는 포함하지 않는 순수 설명용 메타데이터다.
  pii_rejected: list[dict[str, Any]] = field(default_factory=list)
  pii_runtime_status: dict[str, Any] = field(default_factory=dict)
  retrieved_documents: list[dict[str, Any]] = field(default_factory=list)
  raw_retrieved_documents: list[dict[str, Any]] = field(default_factory=list)
  thresholded_documents: list[dict[str, Any]] = field(default_factory=list)
  reranked_documents: list[dict[str, Any]] = field(default_factory=list)
  final_prompt: str = ""
  retrieval_config: dict[str, Any] = field(default_factory=dict)
  success: bool = False
  score: float = 0.0
  metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ExecutionFailureRecord:
  """One masked execution failure captured outside the scored result path."""

  scenario: str
  query_id: str = ""
  query_masked: str = ""
  stage: str = ""
  error_type: str = ""
  error_message_masked: str = ""
  attempt_index: int = 0
  environment_type: str = ""
  profile_name: str = ""
  scenario_scope: str = ""
  dataset_scope: str = ""
  index_manifest_ref: str = ""
  suite_run_id: str = ""
  suite_cell_id: str = ""
  replayed_from_run_id: str = ""
  failed_at: str = ""
  metadata: dict[str, Any] = field(default_factory=dict)


class BaseAttack(ABC):
  """Abstract base class for attack scenarios."""

  def __init__(
    self,
    config: dict[str, Any],
    attacker: str = "A2",
    env: str = "poisoned",
    target: "TargetRAG | None" = None,
  ) -> None:
    self.config = config
    self.attacker = (attacker or "A2").upper()
    # env는 R2에서 쿼리 타입을 결정합니다.
    # clean → q_i(앵커)만 사용(기준선), poisoned → q_i+q_c 복합 쿼리 사용(공격)
    self.env = (env or "poisoned").lower()
    # 진단 대상 어댑터(BYO-RAG). None 이면 execute() 에 전달된 Haystack 파이프라인을
    # 참조 어댑터(BuiltinHaystackAdapter)로 즉석에서 감싸 사용한다 → 기존 동작과 동일.
    # 외부 RAG 를 진단할 때만 여기에 해당 어댑터를 주입한다.
    self.target: "TargetRAG | None" = target

  @abstractmethod
  def generate_queries(self, target_docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Generate attack queries from the selected target documents."""

  @abstractmethod
  def execute(
    self,
    query_info: dict[str, Any],
    rag_pipeline: Pipeline,
  ) -> AttackResult:
    """Execute one attack query against the shared RAG pipeline."""

  def _run_rag_query(self, pipeline: Pipeline, query: str) -> dict[str, Any]:
    """Send a query through the shared RAG path and return its trace.

    질의는 항상 어댑터 경계(`TargetRAG.query`)를 경유한다. `self.target` 이 주입돼
    있으면 그 외부 어댑터를, 없으면 전달된 파이프라인을 참조 어댑터로 감싼다. 어느
    쪽이든 `RagTrace.to_engine_dict()` 로 기존과 동일한 트레이스 dict 를 돌려주므로
    호출부(각 시나리오 execute)는 변경 없이 그대로 동작한다(비파괴).
    """
    try:
      target = self.target
      if target is None:
        from rag.adapters.builtin import BuiltinHaystackAdapter

        target = BuiltinHaystackAdapter(pipeline, self.config)
      return target.query(query).to_engine_dict()
    except Exception as error:
      from loguru import logger

      logger.error(f"RAG query execution failed: {error}")
      return {
        "query": query,
        "prompt": "",
        "retrieved_documents": [],
        "raw_retrieved_documents": [],
        "thresholded_documents": [],
        "reranked_documents": [],
        "profile_name": self.config.get("profile_name", "default"),
        "retrieval_config": self.config.get("retrieval_config", {}),
        "reranker_enabled": bool(
          self.config.get("retrieval_config", {}).get("reranker", {}).get("enabled", False)
        ),
        "retriever": {"documents": []},
        "generator": {"replies": [], "meta": []},
      }
