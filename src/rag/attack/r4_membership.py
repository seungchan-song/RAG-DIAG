"""
R4 공격 시나리오: 멤버십 추론 (Document-Level Membership Inference Attack)

논문 Definition 2 기반 구현:
  "DL-MIA for RAG systems, where an adversary aims to determine
   whether a specific document d* was part of the private knowledge base D"

공격 방식 (챌린저-공격자 게임):
  1. 챌린저가 동전을 던집니다: b ∈ {0, 1}
     - b=1: D에 타깃 문서 d*를 포함시킵니다
     - b=0: D에서 타깃 문서 d*를 제외합니다
  2. 공격자가 쿼리 q를 제출합니다
  3. 챌린저가 D_q = R(q, D; k)를 계산하고, y = G(q, D_q)를 반환합니다
  4. 공격자가 (q, y, d*)를 보고 b̂를 추측합니다
  5. b̂ = b이면 공격 성공

판정 방법:
  응답 y와 타깃 문서 d*의 유사도를 비교합니다.
  유사도가 높으면 b̂=1 (포함), 낮으면 b̂=0 (미포함)으로 추측합니다.

사용 예시:
  attack = R4MembershipAttack(config)
  queries = attack.generate_queries(target_docs)
  result = attack.execute(queries[0], rag_pipeline)
"""

from typing import Any

from haystack import Pipeline
from loguru import logger

from rag.attack.base import AttackResult, BaseAttack
from rag.attack.query_generator import AttackQueryGenerator


class R4MembershipAttack(BaseAttack):
  """
  R4 멤버십 추론 공격을 수행하는 클래스입니다.

  특정 문서가 RAG 시스템의 knowledge base에 포함되어 있는지
  응답의 특성을 분석하여 추론합니다.
  """

  def __init__(self, config: dict[str, Any]) -> None:
    super().__init__(config)
    self.query_gen = AttackQueryGenerator(config)
    logger.debug("R4MembershipAttack 초기화 완료")

  def generate_queries(
    self, target_docs: list[dict[str, Any]]
  ) -> list[dict[str, Any]]:
    """
    R4 멤버십 추론 쿼리를 생성합니다.

    각 타깃 문서에 대해 탐색적 질문을 생성합니다.
    is_member 값은 실행 시 챌린저가 결정합니다.

    Args:
      target_docs: 멤버십 추론 대상 문서 목록

    Returns:
      list[dict]: R4 탐색 쿼리 목록
    """
    all_queries: list[dict[str, Any]] = []

    for doc in target_docs:
      # b=1 (포함) 시나리오 쿼리
      member_queries = self.query_gen.generate_r4_queries(doc, is_member=True)
      all_queries.extend(member_queries)

      # b=0 (미포함) 시나리오 쿼리
      non_member_queries = self.query_gen.generate_r4_queries(doc, is_member=False)
      all_queries.extend(non_member_queries)

    return all_queries

  def execute(
    self,
    query_info: dict[str, Any],
    rag_pipeline: Pipeline,
  ) -> AttackResult:
    """
    단일 R4 멤버십 추론 공격을 실행합니다.

    논문 공식:
      Adversary A submits q ∈ Q
      Challenger C computes D_q = R(q, D; k), y = G(q, D_q)
      C provides adversary with (q, y, d*)
      Adversary outputs b̂ ∈ {0, 1}
      Success: b̂ = b

    Args:
      query_info: generate_queries()에서 생성된 쿼리 정보
      rag_pipeline: 공격 대상 RAG 파이프라인

    Returns:
      AttackResult: 공격 결과
        - metadata["ground_truth_b"]: 실제 포함 여부 (1 또는 0)
        - metadata["predicted_b"]: 공격자의 추측 (평가기에서 채움)
    """
    query = query_info["query"]
    target_text = query_info["target_text"]
    ground_truth_b = query_info["ground_truth_b"]

    logger.debug(
      f"R4 공격 실행 (b={ground_truth_b}): {query[:50]}..."
    )

    # RAG 파이프라인에 탐색 쿼리 전달
    response = self._run_rag_query(rag_pipeline, query)

    return AttackResult(
      scenario="R4",
      query=query,
      response=response,
      target_text=target_text,
      metadata={
        "ground_truth_b": ground_truth_b,
        "target_doc_id": query_info.get("target_doc_id", ""),
      },
    )
