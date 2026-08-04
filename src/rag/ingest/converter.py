"""
문서 변환기 모듈

PDF, TXT, MD 파일을 Haystack의 Document 객체로 변환합니다.
Document 객체는 텍스트 내용(content)과 메타데이터(meta)를 함께 담고 있어서
이후 파이프라인에서 일관되게 처리할 수 있습니다.

사용 예시:
  pdf_converter = create_pdf_converter()
  txt_converter = create_txt_converter()
"""

import html
from dataclasses import replace
from pathlib import Path
from typing import Any
from haystack import Document, component
from haystack.components.converters import TextFileToDocument
from haystack.dataclasses import ByteStream
from haystack_integrations.components.converters.docling import DoclingConverter, ExportType
from loguru import logger


@component
class SafeDoclingConverter(DoclingConverter):
  """
  Windows 환경에서 비-ASCII(한글 등) 경로가 포함된 경우
  C++ 기반 파서(pdfium 등)에서 파일 접근 에러가 발생하지 않도록
  파일을 바이너리 스트림(ByteStream)으로 읽어서 변환을 수행하는 안전한 변환기입니다.
  """
  @component.output_types(documents=list[Document])
  def run(
    self,
    sources: list[str | Path | ByteStream],
    meta: dict[str, Any] | list[dict[str, Any]] | None = None,
  ):
    safe_sources = []
    for src in sources:
      if isinstance(src, (str, Path)):
        p = Path(src)
        with open(p, "rb") as f:
          data = f.read()
        safe_sources.append(
          ByteStream(data=data, meta={"file_path": str(p.resolve())})
        )
      else:
        safe_sources.append(src)
    result = DoclingConverter.run(self, sources=safe_sources, meta=meta)

    # docling 의 마크다운 내보내기는 본문의 `<`, `>`, `&` 를 HTML 엔티티로 바꾼다.
    # 그대로 두면 "이예린 <a@b.com>" 이 인덱스·응답·리포트까지 "&lt;a@b.com&gt;" 으로
    # 흘러가고, 화면에서는 엔티티 문자가 그대로 보인다(TXT 로 들어온 같은 문장은
    # 멀쩡히 나와서 한 화면에 두 표기가 섞인다). 변환 직후 한 번만 되돌린다.
    # Document 를 제자리에서 고치면 Haystack 이 경고한다(같은 인스턴스를 다른 컴포넌트가
    # 공유할 수 있어서). 바꿀 게 있는 것만 replace 로 새로 만든다.
    docs = result.get("documents", []) or []
    result["documents"] = [
      replace(doc, content=html.unescape(doc.content))
      if doc.content and "&" in doc.content
      else doc
      for doc in docs
    ]
    return result


def create_pdf_converter() -> DoclingConverter:
  """
  PDF 파일을 Document 객체로 변환하는 컴포넌트를 생성합니다.

  DoclingConverter를 사용하여 PDF의 레이아웃과 도표 구조를 보존한 채
  마크다운 형식의 텍스트로 변환합니다.

  Returns:
    DoclingConverter: PDF 변환기 컴포넌트
  """
  converter = SafeDoclingConverter(export_type=ExportType.MARKDOWN)
  logger.debug("Docling PDF 변환기 생성 완료")
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
