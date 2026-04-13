"""
공격 시나리오 베이스 클래스

모든 공격 시나리오(R2, R4, R9)가 상속하는 추상 베이스 클래스입니다.
공통 인터페이스를 정의하여 AttackRunner에서 일관되게 실행할 수 있습니다.

핵심 개념:
  - 각 공격 시나리오는 BaseAttack을 상속합니다
  - generate_queries(): 공격 쿼리를 생성합니다
  - execute(): 생성된 쿼리로 RAG에 공격을 실행합니다
  - AttackResult: 단일 공격 시행의 결과를 담는 데이터 클래스

사용 예시:
  class R2Attack(BaseAttack):
    def generate_queries(self) -> list[str]: ...
    def execute(self, query, pipeline) -> AttackResult: ...
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from haystack import Pipeline


@dataclass
class AttackResult:
  """
  단일 공격 시행의 결과를 나타내는 데이터 클래스입니다.

  Attributes:
    scenario: 공격 시나리오 (예: "R2", "R4", "R9")
    query: 사용된 공격 쿼리
    response: RAG 시스템의 응답 텍스트
    target_text: 공격 대상 텍스트 (R2: 유출 대상 문서, R4: 타깃 문서, R9: 트리거)
    success: 공격 성공 여부 (평가기에서 판정)
    score: 공격 점수 (R2: ROUGE-L, R4: hit_rate, R9: 0/1)
    metadata: 추가 메타데이터 (공격자 유형, 환경 등)
  """
  scenario: str
  query: str
  response: str
  target_text: str = ""
  success: bool = False
  score: float = 0.0
  metadata: dict[str, Any] = field(default_factory=dict)


class BaseAttack(ABC):
  """
  공격 시나리오의 추상 베이스 클래스입니다.

  모든 공격 시나리오(R2, R4, R9)는 이 클래스를 상속하고
  generate_queries()와 execute()를 구현해야 합니다.
  """

  def __init__(self, config: dict[str, Any]) -> None:
    """
    공격 시나리오를 초기화합니다.

    Args:
      config: YAML에서 로드한 설정 딕셔너리
    """
    self.config = config

  @abstractmethod
  def generate_queries(self, target_docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    공격 쿼리를 생성합니다.

    Args:
      target_docs: 공격 대상 문서 목록
        각 문서는 {"content": "...", "meta": {...}} 형태

    Returns:
      list[dict]: 생성된 공격 쿼리 목록
        각 쿼리는 {"query": "...", "target_text": "...", ...} 형태
    """
    ...

  @abstractmethod
  def execute(
    self,
    query_info: dict[str, Any],
    rag_pipeline: Pipeline,
  ) -> AttackResult:
    """
    단일 공격 쿼리를 RAG 파이프라인에 실행합니다.

    Args:
      query_info: generate_queries()에서 생성된 쿼리 정보
      rag_pipeline: 공격 대상 RAG 파이프라인

    Returns:
      AttackResult: 공격 실행 결과
    """
    ...

  def _run_rag_query(self, pipeline: Pipeline, query: str) -> str:
    """
    RAG 파이프라인에 쿼리를 보내고 응답 텍스트를 반환합니다.

    Args:
      pipeline: RAG 파이프라인
      query: 질의 텍스트

    Returns:
      str: LLM 응답 텍스트 (실패 시 빈 문자열)
    """
    try:
      result = pipeline.run({
        "query_embedder": {"text": query},
        "prompt_builder": {"query": query},
      })
      replies = result.get("generator", {}).get("replies", [])
      return replies[0] if replies else ""
    except Exception as e:
      from loguru import logger
      logger.error(f"RAG 쿼리 실행 실패: {e}")
      return ""
