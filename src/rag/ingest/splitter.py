"""
문서 분할(Splitting) 모듈

정제된 문서를 작은 청크(chunk)로 분할합니다.
RAG에서는 문서 전체를 임베딩하면 정보가 희석되기 때문에,
적절한 크기로 나누어 각 청크를 독립적으로 임베딩합니다.

핵심 개념:
  - chunk_size: 각 청크의 최대 단어/문장 수
  - chunk_overlap: 인접 청크 간 겹치는 부분 (문맥 유지용)
  - split_by: 분할 기준 ("sentence", "word", "passage")

사용 예시:
  splitter = create_document_splitter(config)
  result = splitter.run(documents=documents)
"""

from typing import Any

from haystack.components.preprocessors import DocumentSplitter
from loguru import logger


def create_document_splitter(config: dict[str, Any]) -> DocumentSplitter:
  """
  설정에 따라 문서를 청크로 분할하는 컴포넌트를 생성합니다.

  config["ingest"] 아래의 chunk_size, chunk_overlap, split_by 를 사용합니다.
  단위는 split_by 가 정합니다 — "sentence" 면 chunk_size 512 가 512 문장을 뜻합니다.
  """
  ingest_config = config.get("ingest", {})
  chunk_size = ingest_config.get("chunk_size", 512)
  chunk_overlap = ingest_config.get("chunk_overlap", 64)
  split_by = ingest_config.get("split_by", "sentence")

  splitter = DocumentSplitter(
    split_by=split_by,
    split_length=chunk_size,
    split_overlap=chunk_overlap,
  )

  logger.debug(
    f"문서 분할기(Splitter) 생성 완료 "
    f"(split_by={split_by}, size={chunk_size}, overlap={chunk_overlap})"
  )
  return splitter
