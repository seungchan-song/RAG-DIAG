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
from rag.retriever.prompt_builder import create_prompt_builder
from rag.retriever.query_embedder import create_query_embedder
from rag.retriever.retriever import create_retriever


def build_rag_pipeline(
  document_store: InMemoryDocumentStore,
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
  prompt_builder = create_prompt_builder()
  generator = create_generator(config)

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

  logger.info("RAG 질의 파이프라인 구성 완료")
  return pipeline


def run_query(
  pipeline: Pipeline,
  query: str,
) -> dict[str, Any]:
  """
  RAG 파이프라인에 질문을 보내고 답변을 받습니다.

  Args:
    pipeline: build_rag_pipeline()으로 만든 RAG 파이프라인
    query: 사용자 질문 텍스트

  Returns:
    dict: 파이프라인 실행 결과. 주요 키:
      - "generator": {"replies": ["답변 텍스트"], "meta": [...]}
      - "retriever": {"documents": [Document, ...]}

  사용 예시:
    result = run_query(pipeline, "개인정보보호법 제23조의 내용은?")
    answer = result["generator"]["replies"][0]
    sources = result["retriever"]["documents"]
  """
  logger.info(f"질의 실행: {query[:50]}...")

  # 파이프라인에 질의를 입력합니다
  # query_embedder에는 text로, prompt_builder에는 query로 전달합니다
  result = pipeline.run({
    "query_embedder": {"text": query},
    "prompt_builder": {"query": query},
  })

  # 결과에서 답변을 추출합니다
  replies = result.get("generator", {}).get("replies", [])
  if replies:
    logger.info(f"답변 생성 완료 (길이: {len(replies[0])}자)")
  else:
    logger.warning("답변이 생성되지 않았습니다")

  return result
