"""Shared attack interfaces and result models."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from haystack import Pipeline


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
  ) -> None:
    self.config = config
    self.attacker = (attacker or "A2").upper()
    # env는 R2에서 쿼리 타입을 결정합니다.
    # clean → q_i(앵커)만 사용(기준선), poisoned → q_i+q_c 복합 쿼리 사용(공격)
    self.env = (env or "poisoned").lower()

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
    """Send a query through the shared RAG path and return its trace."""
    try:
      from rag.retriever.pipeline import run_query

      return run_query(pipeline, query)
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
