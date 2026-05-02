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
from rag.ingest.writer import create_document_store
from rag.retriever.pipeline import build_rag_pipeline


class R4MembershipAttack(BaseAttack):
  """
  R4 멤버십 추론 공격을 수행하는 클래스입니다.

  특정 문서가 RAG 시스템의 knowledge base에 포함되어 있는지
  응답의 특성을 분석하여 추론합니다.
  """

  def __init__(self, config: dict[str, Any], attacker: str = "A2", env: str = "poisoned") -> None:
    super().__init__(config, attacker=attacker, env=env)
    self.query_gen = AttackQueryGenerator(config, attacker=self.attacker)
    self._non_member_pipelines: dict[str, Pipeline] = {}
    logger.debug("R4MembershipAttack 초기화 완료 (attacker={})", self.attacker)

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

    execution_pipeline = self._resolve_execution_pipeline(query_info, rag_pipeline)
    trace = self._run_rag_query(execution_pipeline, query)
    replies = trace.get("generator", {}).get("replies", [])
    response = replies[0] if replies else ""

    return AttackResult(
      scenario="R4",
      query=query,
      response=response,
      query_id=query_info.get("query_id", ""),
      profile_name=trace.get("profile_name", ""),
      target_text=target_text,
      retrieved_documents=trace.get("retrieved_documents", []),
      raw_retrieved_documents=trace.get("raw_retrieved_documents", []),
      thresholded_documents=trace.get("thresholded_documents", []),
      reranked_documents=trace.get("reranked_documents", []),
      final_prompt=trace.get("prompt", ""),
      retrieval_config=trace.get("retrieval_config", {}),
      metadata={
        "ground_truth_b": ground_truth_b,
        "target_doc_id": query_info.get("target_doc_id", ""),
        "keyword": query_info.get("keyword", ""),
        "retrieval_mode": (
          "member"
          if ground_truth_b == 1
          else "non_member_excluded_index"
        ),
        "reranker_enabled": trace.get("reranker_enabled", False),
      },
    )

  def _resolve_execution_pipeline(
    self,
    query_info: dict[str, Any],
    rag_pipeline: Pipeline,
  ) -> Pipeline:
    """
    R4 b=0 실행에서는 타깃 문서를 제외한 검색 경로를 사용합니다.
    """
    if query_info.get("ground_truth_b", 0) == 1:
      return rag_pipeline

    target_doc_id = query_info.get("target_doc_id", "")
    if target_doc_id in self._non_member_pipelines:
      return self._non_member_pipelines[target_doc_id]

    retriever = rag_pipeline.get_component("retriever")
    document_store = retriever.document_store
    stored_docs = document_store.filter_documents()

    filtered_docs = [
      doc for doc in stored_docs
      if (
        doc.meta.get("chunk_id") != target_doc_id
        and doc.meta.get("doc_id") != target_doc_id
        and getattr(doc, "id", "") != target_doc_id
      )
    ]

    non_member_store = create_document_store()
    non_member_store.write_documents(filtered_docs)

    logger.debug(
      f"R4 non-member 경로 구성: "
      f"target_doc_id={target_doc_id}, "
      f"원본={len(stored_docs)}개, 제외후={len(filtered_docs)}개"
    )

    non_member_pipeline = build_rag_pipeline(non_member_store, self.config)
    self._non_member_pipelines[target_doc_id] = non_member_pipeline
    return non_member_pipeline
