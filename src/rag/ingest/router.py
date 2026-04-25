"""
파일 타입 라우터 모듈

입력 디렉토리의 파일들을 확장자별로 분류하여
각각에 맞는 변환기(Converter)로 보내주는 역할을 합니다.

지원하는 파일 형식:
  - .pdf  → PDF 변환기
  - .txt  → 텍스트 변환기
  - .md   → 마크다운 변환기

사용 예시:
  router = create_file_router()
  result = router.run(sources=["data/documents/sample.pdf"])
"""

from haystack.components.routers import FileTypeRouter
from loguru import logger


def create_file_router() -> FileTypeRouter:
  """
  파일 확장자에 따라 문서를 분류하는 라우터를 생성합니다.

  Haystack의 FileTypeRouter는 파일의 MIME 타입을 확인하여
  적절한 출력 포트로 라우팅합니다.

  Returns:
    FileTypeRouter: 설정이 완료된 파일 라우터 컴포넌트

  동작 원리:
    - .pdf 파일 → "application/pdf" 출력 포트
    - .txt 파일 → "text/plain" 출력 포트
    - .md 파일  → "text/markdown" 출력 포트 (text/plain으로 처리)
  """
  # MIME 타입 목록을 지정하여 라우터를 생성합니다
  # 각 MIME 타입은 라우터의 출력 포트 이름이 됩니다
  router = FileTypeRouter(
    mime_types=[
      "application/pdf",   # PDF 파일
      "text/plain",        # TXT, MD 파일
      "text/markdown",     # Markdown 파일
    ]
  )

  logger.debug("파일 타입 라우터 생성 완료")
  return router
