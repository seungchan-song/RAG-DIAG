"""
프롬프트 빌더 모듈

검색된 문서(컨텍스트)와 사용자 질문을 결합하여
LLM에게 전달할 프롬프트를 구성합니다.

핵심 개념:
  - RAG 프롬프트: "다음 문서를 참고하여 질문에 답하세요" 형태
  - 컨텍스트: 검색된 문서들의 내용
  - Jinja2 템플릿: 프롬프트에 변수를 삽입하는 템플릿 엔진

사용 예시:
  builder = create_prompt_builder()
  result = builder.run(query="질문", documents=retrieved_docs)
"""

from haystack.components.builders import PromptBuilder
from loguru import logger

# RAG 프롬프트 템플릿 (Jinja2 문법)
# {{ documents }}와 {{ query }}에 실제 값이 삽입됩니다
RAG_PROMPT_TEMPLATE = """
아래의 참고 문서들을 바탕으로 질문에 답변해주세요.
참고 문서에 없는 내용은 "제공된 문서에서 해당 정보를 찾을 수 없습니다"라고 답해주세요.

## 참고 문서
{% for doc in documents %}
--- 문서 {{ loop.index }} ---
{{ doc.content }}
{% endfor %}

## 질문
{{ query }}

## 답변
""".strip()


def create_prompt_builder(template: str | None = None) -> PromptBuilder:
  """
  검색 결과와 질문을 결합하여 LLM 프롬프트를 만드는 컴포넌트를 생성합니다.

  Haystack의 PromptBuilder는 Jinja2 템플릿을 사용하여
  동적으로 프롬프트를 구성합니다.

  Args:
    template: 커스텀 프롬프트 템플릿.
              None이면 기본 RAG 템플릿(RAG_PROMPT_TEMPLATE)을 사용합니다.

  Returns:
    PromptBuilder: 프롬프트 빌더 컴포넌트
  """
  if template is None:
    template = RAG_PROMPT_TEMPLATE

  # required_variables=["documents"]를 설정해야 합니다.
  # 설정하지 않으면 Haystack이 documents를 선택적(optional)으로 처리하여
  # retriever를 기다리지 않고 prompt_builder를 즉시 실행합니다.
  # 그 결과 검색 결과가 항상 0개인 버그가 발생합니다.
  builder = PromptBuilder(template=template, required_variables=["documents"])

  logger.debug("프롬프트 빌더 생성 완료")
  return builder
