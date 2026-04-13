"""
문서 정제(Cleaning) 모듈

변환된 Document에서 불필요한 공백, 빈 줄, 특수문자 등을 제거합니다.
깨끗한 텍스트를 만들어야 이후 청킹과 임베딩의 품질이 좋아집니다.

사용 예시:
  cleaner = create_document_cleaner()
  result = cleaner.run(documents=documents)
"""

from haystack.components.preprocessors import DocumentCleaner
from loguru import logger


def create_document_cleaner() -> DocumentCleaner:
  """
  문서 텍스트를 정제하는 컴포넌트를 생성합니다.

  DocumentCleaner가 수행하는 작업:
    1. 연속된 빈 줄을 하나로 합칩니다
    2. 앞뒤 공백을 제거합니다
    3. 머리글/바닥글 등 반복되는 텍스트를 제거합니다 (옵션)

  Returns:
    DocumentCleaner: 문서 정제 컴포넌트
  """
  cleaner = DocumentCleaner(
    # 연속된 빈 줄을 제거합니다
    remove_empty_lines=True,
    # 각 줄의 앞뒤 공백을 제거합니다
    remove_extra_whitespaces=True,
  )

  logger.debug("문서 정제기(Cleaner) 생성 완료")
  return cleaner
