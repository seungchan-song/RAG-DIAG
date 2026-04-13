"""
문서 저장(Writer) 모듈

임베딩이 완료된 Document들을 FAISS 벡터 DB에 저장합니다.
Haystack의 InMemoryDocumentStore를 FAISS 기반 저장소로 사용합니다.

핵심 개념:
  - DocumentStore: Haystack에서 문서를 저장하고 검색하는 추상 계층
  - DocumentWriter: Document 객체를 DocumentStore에 기록하는 컴포넌트
  - DuplicatePolicy: 중복 문서 처리 방식 (OVERWRITE, SKIP, FAIL)

사용 예시:
  store = create_document_store()
  writer = create_document_writer(store)
  writer.run(documents=embedded_documents)
"""

from haystack.components.writers import DocumentWriter
from haystack.document_stores.in_memory import InMemoryDocumentStore
from haystack.document_stores.types import DuplicatePolicy
from loguru import logger


def create_document_store() -> InMemoryDocumentStore:
  """
  문서를 저장할 InMemoryDocumentStore를 생성합니다.

  InMemoryDocumentStore는 메모리에 문서를 저장하며,
  임베딩 벡터의 유사도 검색을 지원합니다.
  실험 목적으로 충분하며, FAISS와 유사한 내적(dot product) 검색을 수행합니다.

  Returns:
    InMemoryDocumentStore: 문서 저장소 인스턴스
  """
  store = InMemoryDocumentStore()
  logger.debug("InMemoryDocumentStore 생성 완료")
  return store


def create_document_writer(document_store: InMemoryDocumentStore) -> DocumentWriter:
  """
  Document 객체를 DocumentStore에 기록하는 Writer를 생성합니다.

  Args:
    document_store: 문서를 저장할 DocumentStore 인스턴스

  Returns:
    DocumentWriter: 문서 저장 컴포넌트
  """
  writer = DocumentWriter(
    document_store=document_store,
    # 같은 ID의 문서가 이미 있으면 덮어씁니다
    policy=DuplicatePolicy.OVERWRITE,
  )

  logger.debug("DocumentWriter 생성 완료")
  return writer
