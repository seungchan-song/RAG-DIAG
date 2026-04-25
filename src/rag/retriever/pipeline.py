"""
RAG 질의 파이프라인 통합 모듈

사용자 질문을 받아서 검색 → 프롬프트 구성 → LLM 응답 생성까지의
전체 RAG 파이프라인을 구성합니다.

전체 흐름:
  질문(query) → QueryEmbedder → Retriever → PromptBuilder → Generator → 답변

사용 예시:
  from rag.retriever.pipeline import build_rag_pipeline, run_query

  pipeline = build_rag_pipeline(document_store, config)
  answer = run_query(pipeline, "한국의 개인정보보호법에 대해 알려줘")
"""

from typing import Any

from haystack import Pipeline
from haystack.document_stores.in_memory import InMemoryDocumentStore
from loguru import logger

from rag.generator.generator import create_generator
from rag.index.store import PersistentFaissDocumentStore
from rag.retriever.prompt_builder import create_prompt_builder
from rag.retriever.query_embedder import create_query_embedder
from rag.retriever.reranker import create_reranker
from rag.retriever.retriever import create_retriever
from rag.utils.config import build_retrieval_config

NO_CONTEXT_RESPONSE = "제공된 문서에서 해당 정보를 찾을 수 없습니다"


def serialize_document(document: Any) -> dict[str, Any]:
  """
  결과 저장용으로 검색 문서를 직렬화합니다.
  """
  return {
    "id": getattr(document, "id", ""),
    "score": getattr(document, "score", None),
    "content": getattr(document, "content", ""),
    "meta": dict(getattr(document, "meta", {}) or {}),
  }


def apply_similarity_threshold(
  documents: list[Any],
  similarity_threshold: float,
) -> list[Any]:
  """
  점수 임계값 기준으로 검색 문서를 필터링합니다.
  """
  if similarity_threshold <= 0:
    return list(documents)

  filtered_documents = [
    document
    for document in documents
    if (getattr(document, "score", None) or 0.0) >= similarity_threshold
  ]
  logger.debug(
    f"similarity_threshold 적용: {len(documents)}개 -> "
    f"{len(filtered_documents)}개 (threshold={similarity_threshold})"
  )
  return filtered_documents


def build_rag_pipeline(
  document_store: InMemoryDocumentStore | PersistentFaissDocumentStore,
  config: dict[str, Any],
) -> Pipeline:
  """
  RAG 질의 파이프라인을 구성합니다.

  질문 → 임베딩 → 검색 → 프롬프트 구성 → LLM 답변 생성의
  전체 흐름을 하나의 Pipeline으로 만듭니다.

  Args:
    document_store: 검색할 문서가 저장된 DocumentStore
    config: YAML에서 로드한 설정 딕셔너리

  Returns:
    Pipeline: 구성 완료된 RAG 파이프라인

  파이프라인 구조:
    ┌───────────────┐
    │ QueryEmbedder │  ← 질문을 벡터로 변환
    └──────┬────────┘
    ┌──────▼────────┐
    │   Retriever   │  ← 유사 문서 검색
    └──────┬────────┘
    ┌──────▼────────┐
    │ PromptBuilder │  ← 검색 결과 + 질문 → 프롬프트
    └──────┬────────┘
    ┌──────▼────────┐
    │   Generator   │  ← LLM 답변 생성
    └───────────────┘
  """
  # === 1. 컴포넌트 생성 ===
  query_embedder = create_query_embedder(config)
  retriever = create_retriever(document_store, config)
  reranker = create_reranker(config)
  prompt_builder = create_prompt_builder()
  generator = create_generator(config)
  retrieval_config = build_retrieval_config(config)

  # === 2. Pipeline에 컴포넌트 등록 ===
  pipeline = Pipeline()
  pipeline.add_component("query_embedder", query_embedder)
  pipeline.add_component("retriever", retriever)
  pipeline.add_component("prompt_builder", prompt_builder)
  pipeline.add_component("generator", generator)

  # === 3. 컴포넌트 간 연결 ===
  # 질의 임베딩 → 검색
  pipeline.connect("query_embedder.embedding", "retriever.query_embedding")
  # 검색 결과 → 프롬프트 빌더
  pipeline.connect("retriever.documents", "prompt_builder.documents")
  # 프롬프트 → LLM 생성기
  pipeline.connect("prompt_builder.prompt", "generator.prompt")

  # query_embedder(SentenceTransformersTextEmbedder)는 run() 전에
  # warm_up()으로 모델을 로드해야 합니다.
  # 호출하지 않으면 쿼리 임베딩이 None이 되어 검색 결과가 0개 나옵니다.
  logger.info("RAG 질의 파이프라인 워밍업 시작 (임베딩 모델 로드)...")
  pipeline.warm_up()
  pipeline._rag_runtime = {
    "profile_name": config.get("profile_name", "default"),
    "retrieval_config": retrieval_config,
    "reranker": reranker,
  }
  logger.info("RAG 질의 파이프라인 구성 완료")
  return pipeline


def run_query(
  pipeline: Pipeline,
  query: str,
) -> dict[str, Any]:
  """
  RAG 파이프라인에 질문을 보내고 답변을 받습니다.

  Haystack v2의 pipeline.run()은 query를 query_embedder와 prompt_builder에
  동시에 넘길 경우, prompt_builder를 독립 브랜치로 판단하여 retriever를
  건너뛰는 버그가 있습니다. 이를 피하기 위해 컴포넌트를 직접 순차 호출합니다.

  Args:
    pipeline: build_rag_pipeline()으로 만든 RAG 파이프라인
    query: 사용자 질문 텍스트

  Returns:
    dict: 실행 결과. 주요 키:
      - "generator": {"replies": ["답변 텍스트"]}
      - "retriever": {"documents": [Document, ...]}

  사용 예시:
    result = run_query(pipeline, "개인정보보호법 제23조의 내용은?")
    answer = result["generator"]["replies"][0]
    sources = result["retriever"]["documents"]
  """
  logger.info(f"질의 실행: {query[:50]}...")

  # STEP 1: 질의를 벡터로 변환합니다
  query_embedder = pipeline.get_component("query_embedder")
  emb_result = query_embedder.run(text=query)
  query_embedding = emb_result["embedding"]

  # STEP 2: 벡터로 유사 문서를 검색합니다
  retriever = pipeline.get_component("retriever")
  ret_result = retriever.run(query_embedding=query_embedding)
  raw_documents = ret_result["documents"]
  logger.debug(f"검색된 원시 문서: {len(raw_documents)}개")

  runtime = getattr(pipeline, "_rag_runtime", {})
  retrieval_config = runtime.get("retrieval_config", {})
  profile_name = runtime.get("profile_name", "default")
  reranker = runtime.get("reranker")

  similarity_threshold = retrieval_config.get("similarity_threshold", 0.0)
  thresholded_documents = apply_similarity_threshold(
    raw_documents,
    similarity_threshold,
  )

  reranker_config = retrieval_config.get("reranker", {})
  reranker_enabled = bool(reranker_config.get("enabled", False))
  if reranker_enabled:
    if reranker is None:
      raise ValueError("reranker.enabled=true 이지만 리랭커가 초기화되지 않았습니다.")
    reranked_documents = reranker.rerank(
      query,
      thresholded_documents,
      top_k=reranker_config.get("top_k"),
    )
  else:
    reranked_documents = []

  final_documents = reranked_documents if reranked_documents else thresholded_documents

  # STEP 3: 검색된 문서와 질의를 결합하여 프롬프트를 만듭니다
  prompt_builder = pipeline.get_component("prompt_builder")
  pb_result = prompt_builder.run(documents=final_documents, query=query)
  prompt = pb_result["prompt"]

  # STEP 4: LLM이 프롬프트를 받아 답변을 생성합니다
  context_empty = len(final_documents) == 0
  if context_empty:
    gen_result = {
      "replies": [NO_CONTEXT_RESPONSE],
      "meta": [{"model": "no-context-fallback", "context_empty": True}],
    }
  else:
    generator = pipeline.get_component("generator")
    gen_result = generator.run(prompt=prompt)

  replies = gen_result.get("replies", [])
  if replies:
    logger.info(f"답변 생성 완료 (길이: {len(replies[0])}자)")
  else:
    logger.warning("답변이 생성되지 않았습니다")

  return {
    "query": query,
    "prompt": prompt,
    "final_prompt": prompt,
    "retriever": {**ret_result, "documents": final_documents},
    "profile_name": profile_name,
    "retrieval_config": retrieval_config,
    "reranker_enabled": reranker_enabled,
    "context_empty": context_empty,
    "retrieved_documents": [serialize_document(doc) for doc in final_documents],
    "raw_retrieved_documents": [serialize_document(doc) for doc in raw_documents],
    "thresholded_documents": [
      serialize_document(doc) for doc in thresholded_documents
    ],
    "reranked_documents": [serialize_document(doc) for doc in reranked_documents],
    "generator": gen_result,
  }
