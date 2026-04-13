"""
문서 인덱싱 파이프라인 통합 모듈

개별 컴포넌트(라우터, 변환기, 정제기, 분할기, 임베딩기, 저장기)를
하나의 Haystack Pipeline으로 연결합니다.

전체 흐름:
  파일 목록 → FileTypeRouter → PDF/TXT 변환기 → DocumentCleaner
  → DocumentSplitter → DocumentEmbedder → DocumentWriter → FAISS DB

사용 예시:
  from rag.ingest.pipeline import build_ingest_pipeline, run_ingest

  # 파이프라인 구성 + 실행
  store, docs_written = run_ingest("data/documents/", config)
"""

from pathlib import Path
from typing import Any

from haystack import Pipeline
from haystack.components.joiners import DocumentJoiner
from haystack.document_stores.in_memory import InMemoryDocumentStore
from loguru import logger

from rag.ingest.cleaner import create_document_cleaner
from rag.ingest.converter import create_pdf_converter, create_txt_converter
from rag.ingest.embedder import create_document_embedder
from rag.ingest.router import create_file_router
from rag.ingest.splitter import create_document_splitter
from rag.ingest.writer import create_document_store, create_document_writer


def build_ingest_pipeline(
  config: dict[str, Any],
  document_store: InMemoryDocumentStore | None = None,
) -> tuple[Pipeline, InMemoryDocumentStore]:
  """
  문서 인덱싱 파이프라인을 구성합니다.

  Haystack Pipeline에 컴포넌트를 등록하고 연결(connect)하여
  파일 → 벡터 DB 저장까지의 전체 흐름을 만듭니다.

  Args:
    config: YAML에서 로드한 설정 딕셔너리
    document_store: 기존 DocumentStore를 사용하려면 전달.
                    None이면 새로 생성합니다.

  Returns:
    tuple[Pipeline, InMemoryDocumentStore]:
      - pipeline: 구성 완료된 Haystack Pipeline
      - document_store: 문서가 저장될 DocumentStore

  파이프라인 구조:
    ┌─────────────┐
    │ FileTypeRouter │
    └──┬──────┬───┘
       │      │
    ┌──▼──┐ ┌─▼──────┐
    │ PDF │ │  TXT   │
    └──┬──┘ └──┬─────┘
       │       │
    ┌──▼───────▼──┐
    │ DocumentJoiner │  ← PDF/TXT 결과를 합침
    └──────┬──────┘
    ┌──────▼──────┐
    │  Cleaner    │  ← 텍스트 정제
    └──────┬──────┘
    ┌──────▼──────┐
    │  Splitter   │  ← 청크 분할
    └──────┬──────┘
    ┌──────▼──────┐
    │  Embedder   │  ← 벡터 변환
    └──────┬──────┘
    ┌──────▼──────┐
    │   Writer    │  ← DB 저장
    └─────────────┘
  """
  # === 1. DocumentStore 생성 ===
  if document_store is None:
    document_store = create_document_store()

  # === 2. 각 컴포넌트 생성 ===
  router = create_file_router()
  pdf_converter = create_pdf_converter()
  txt_converter = create_txt_converter()
  # DocumentJoiner: 여러 변환기의 출력을 하나로 합치는 컴포넌트
  joiner = DocumentJoiner()
  cleaner = create_document_cleaner()
  splitter = create_document_splitter(config)
  embedder = create_document_embedder(config)
  writer = create_document_writer(document_store)

  # === 3. Pipeline에 컴포넌트 등록 ===
  pipeline = Pipeline()
  pipeline.add_component("router", router)
  pipeline.add_component("pdf_converter", pdf_converter)
  pipeline.add_component("txt_converter", txt_converter)
  pipeline.add_component("joiner", joiner)
  pipeline.add_component("cleaner", cleaner)
  pipeline.add_component("splitter", splitter)
  pipeline.add_component("embedder", embedder)
  pipeline.add_component("writer", writer)

  # === 4. 컴포넌트 간 연결 ===
  # 라우터 → 변환기 (MIME 타입별 분기)
  pipeline.connect("router.application/pdf", "pdf_converter.sources")
  pipeline.connect("router.text/plain", "txt_converter.sources")

  # 변환기 → Joiner (결과 합치기)
  pipeline.connect("pdf_converter.documents", "joiner.documents")
  pipeline.connect("txt_converter.documents", "joiner.documents")

  # Joiner → Cleaner → Splitter → Embedder → Writer (순차 처리)
  pipeline.connect("joiner.documents", "cleaner.documents")
  pipeline.connect("cleaner.documents", "splitter.documents")
  pipeline.connect("splitter.documents", "embedder.documents")
  pipeline.connect("embedder.documents", "writer.documents")

  logger.info("인덱싱 파이프라인 구성 완료")
  return pipeline, document_store


def run_ingest(
  doc_path: str,
  config: dict[str, Any],
  document_store: InMemoryDocumentStore | None = None,
) -> tuple[InMemoryDocumentStore, int]:
  """
  지정된 경로의 문서를 읽어서 벡터 DB에 저장합니다.

  이 함수는 파이프라인 구성부터 실행까지 한 번에 처리합니다.

  Args:
    doc_path: 문서가 있는 디렉토리 경로 (예: "data/documents/")
    config: YAML에서 로드한 설정 딕셔너리
    document_store: 기존 DocumentStore. None이면 새로 생성.

  Returns:
    tuple[InMemoryDocumentStore, int]:
      - document_store: 문서가 저장된 DocumentStore
      - docs_written: 저장된 문서(청크) 수

  Raises:
    FileNotFoundError: 지정된 경로가 존재하지 않을 때
    ValueError: 지원하는 파일이 하나도 없을 때
  """
  # === 1. 문서 파일 수집 ===
  doc_dir = Path(doc_path)
  if not doc_dir.exists():
    raise FileNotFoundError(f"문서 디렉토리를 찾을 수 없습니다: {doc_dir}")

  # 지원하는 확장자의 파일 목록을 수집합니다
  supported_extensions = {".pdf", ".txt", ".md"}
  file_paths = [
    str(f) for f in doc_dir.rglob("*")
    if f.is_file() and f.suffix.lower() in supported_extensions
  ]

  if not file_paths:
    raise ValueError(
      f"지원하는 문서 파일(.pdf, .txt, .md)이 없습니다: {doc_dir}"
    )

  logger.info(f"문서 {len(file_paths)}개 발견: {doc_dir}")
  for fp in file_paths:
    logger.debug(f"  - {fp}")

  # === 2. 파이프라인 구성 ===
  pipeline, document_store = build_ingest_pipeline(config, document_store)

  # === 3. 임베딩 모델 워밍업 ===
  # SentenceTransformersDocumentEmbedder는 최초 실행 전에 warm_up()이 필요합니다
  pipeline.warm_up()

  # === 4. 파이프라인 실행 ===
  logger.info("인덱싱 파이프라인 실행 시작...")
  result = pipeline.run({"router": {"sources": file_paths}})

  # === 5. 결과 확인 ===
  docs_written = result.get("writer", {}).get("documents_written", 0)
  logger.info(
    f"인덱싱 완료: {docs_written}개 청크가 DocumentStore에 저장되었습니다"
  )

  return document_store, docs_written
