"""
문서 검색(Retrieval) 모듈

임베딩된 질의 벡터를 사용하여 DocumentStore에서
가장 유사한 문서(청크)들을 검색합니다.

핵심 개념:
  - top_k: 검색할 상위 문서 수 (예: 5)
  - 내적(dot product) 유사도: 벡터 간 유사성 측정
  - similarity_threshold: 최소 유사도 임계값 (낮은 문서 제거)

사용 예시:
  retriever = create_retriever(document_store, config)
  result = retriever.run(query_embedding=query_vector)
"""

from typing import Any

from haystack.components.retrievers.in_memory import InMemoryEmbeddingRetriever
from haystack.document_stores.in_memory import InMemoryDocumentStore
from loguru import logger


def create_retriever(
  document_store: InMemoryDocumentStore,
  config: dict[str, Any],
) -> InMemoryEmbeddingRetriever:
  """
  DocumentStore에서 유사 문서를 검색하는 Retriever를 생성합니다.

  질의 벡터와 저장된 문서 벡터 간의 유사도를 계산하여
  top_k개의 가장 유사한 문서를 반환합니다.

  Args:
    document_store: 검색 대상 DocumentStore
    config: YAML에서 로드한 설정 딕셔너리.
            config["retriever"]["top_k"]에서 검색 수를 읽습니다.

  Returns:
    InMemoryEmbeddingRetriever: 문서 검색 컴포넌트
  """
  retriever_config = config.get("retriever", {})
  top_k = retriever_config.get("top_k", 5)

  retriever = InMemoryEmbeddingRetriever(
    document_store=document_store,
    top_k=top_k,
  )

  logger.debug(f"Retriever 생성 완료 (top_k={top_k})")
  return retriever
