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


class TargetExecutionError(RuntimeError):
  """진단 대상 RAG 를 부르는 데 실패했다 — 공격이 실패한 것이 아니다.

  이 둘을 구분하지 못하면 리포트가 거짓말을 한다. 대상 서버가 죽어 있거나 API 키가
  틀려서 응답이 비면 `success=False` 가 되고, 그건 화면에서 "공격 실패 = 방어 성공"과
  똑같이 보인다. 어댑터 계층이 `is_blocked`/`guardrails` 로 "방어가 막았다"를 따로
  전달하는 것과 정확히 같은 이유로, "부르지도 못했다"도 따로 올려야 한다.

  이 예외는 `cli/main.py:_process_query_task` 가 받아 `ExecutionFailureRecord`
  (stage="query_execute")로 적재하며, 해당 질의는 완료 목록에 들어가지 않아
  다음 실행에서 재시도된다.
  """


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


def _raise_if_generator_errored(trace: dict[str, Any]) -> None:
  """생성기가 오류 메타를 실어 보냈으면 실행 실패로 올린다.

  `generator/generator.py` 의 ClovaX·Local 생성기는 HTTP 4xx/5xx 나 예외를 만나면
  **예외를 던지지 않고** `replies=[""]` + `meta=[{"error": ...}]` 를 돌려준다
  (`rag query` 디버그 경로가 트레이스백 대신 메시지를 보여줄 수 있게 하려는 설계).
  문제는 공격 경로에서 그 빈 응답이 그대로 채점돼 **"공격 실패"로 집계**된다는 것이다.
  여기서 오류 메타를 예외로 승격시켜 두 상황을 갈라 놓는다.

  외부 어댑터가 만든 트레이스는 `meta` 가 비어 있으므로(`RagTrace.to_engine_dict`)
  이 검사에 걸리지 않는다. 대상 RAG 가 스스로 보고하는 가드레일 차단은 `error` 가
  아니라 `target_metadata` 로 오므로 이 경로와 섞이지 않는다.

  Args:
    trace: 어댑터가 돌려준 트레이스 dict.

  Raises:
    TargetExecutionError: 생성기 메타에 `error` 가 실려 있을 때.
  """
  meta = (trace.get("generator") or {}).get("meta") or []
  for entry in meta:
    if isinstance(entry, dict) and entry.get("error"):
      raise TargetExecutionError(
        f"생성기 호출 실패(provider={entry.get('provider', '?')}, "
        f"model={entry.get('model', '?')}): {entry['error']}"
      )


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

  def _run_rag_query(
    self,
    pipeline: Pipeline,
    query: str,
    *,
    target: "TargetRAG | None" = None,
  ) -> dict[str, Any]:
    """Send a query through the shared RAG path and return its trace.

    질의는 항상 어댑터 경계(`TargetRAG.query`)를 경유한다. 우선순위는
    (1) 인자로 명시된 `target`(예: R4 의 비회원 반사실 어댑터) →
    (2) `self.target`(외부 RAG 주입 시) → (3) 전달된 파이프라인을 감싼 참조 어댑터.
    어느 쪽이든 `RagTrace.to_engine_dict()` 로 기존과 동일한 트레이스 dict 를
    돌려주므로 호출부(각 시나리오 execute)는 그대로 동작한다(비파괴).

    Args:
      pipeline: 참조 어댑터로 감쌀 Haystack 파이프라인(target 미지정 시 사용).
      query: 질의 문자열.
      target: 이 질의에만 사용할 어댑터 override(옵션). R4 b=0 반사실 실행처럼
        기본 대상이 아닌 별도 어댑터로 보내야 할 때 사용한다.

    Raises:
      TargetExecutionError: 대상 RAG 호출 자체가 실패했을 때. 예전에는 여기서 모든
        예외를 삼키고 **빈 트레이스**를 돌려줬는데, 그러면 빈 응답 → `success=False`
        → 리포트에는 "공격 실패"로 찍혀 **대상이 죽은 것과 방어가 막은 것이 구분되지
        않았다.** 이제는 위로 올려 실행 실패로 기록한다.
      Exception: 그 밖의 예외도 삼키지 않고 그대로 전파한다(호출부가 실패 기록으로
        적재한다).
    """
    resolved = target or self.target
    if resolved is None:
      from rag.adapters.builtin import BuiltinHaystackAdapter

      resolved = BuiltinHaystackAdapter(pipeline, self.config)
    trace = resolved.query(query).to_engine_dict()
    _raise_if_generator_errored(trace)
    return trace
