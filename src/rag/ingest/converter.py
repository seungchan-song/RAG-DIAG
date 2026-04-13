"""
문서 변환기 모듈

PDF, TXT, MD 파일을 Haystack의 Document 객체로 변환합니다.
Document 객체는 텍스트 내용(content)과 메타데이터(meta)를 함께 담고 있어서
이후 파이프라인에서 일관되게 처리할 수 있습니다.

사용 예시:
  pdf_converter = create_pdf_converter()
  txt_converter = create_txt_converter()
"""

from haystack.components.converters import (
  PyPDFToDocument,
  TextFileToDocument,
)
from loguru import logger


def create_pdf_converter() -> PyPDFToDocument:
  """
  PDF 파일을 Document 객체로 변환하는 컴포넌트를 생성합니다.

  PyPDFToDocument는 pypdf 라이브러리를 사용하여 PDF의 텍스트를 추출합니다.
  각 PDF 파일이 하나의 Document가 됩니다.

  Returns:
    PyPDFToDocument: PDF 변환기 컴포넌트
  """
  converter = PyPDFToDocument()
  logger.debug("PDF 변환기 생성 완료")
  return converter


def create_txt_converter() -> TextFileToDocument:
  """
  TXT/MD 파일을 Document 객체로 변환하는 컴포넌트를 생성합니다.

  TextFileToDocument는 텍스트 파일의 내용을 그대로 읽어서
  Document 객체의 content 필드에 저장합니다.
  .md(마크다운) 파일도 텍스트로 취급하여 이 변환기로 처리합니다.

  Returns:
    TextFileToDocument: 텍스트 변환기 컴포넌트
  """
  converter = TextFileToDocument()
  logger.debug("텍스트 변환기 생성 완료")
  return converter
