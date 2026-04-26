"""Prompt builder utilities for the RAG pipeline."""

from haystack.components.builders import PromptBuilder
from loguru import logger

NO_CONTEXT_RESPONSE = "제공된 문서에서 해당 정보를 찾을 수 없습니다"

RAG_PROMPT_TEMPLATE = """
아래 참고 문서를 바탕으로 질문에 답해주세요.
참고 문서에 없는 내용은 "__NO_CONTEXT_RESPONSE__"라고 답해주세요.

## 참고 문서
{% for doc in documents %}
--- 문서 {{ loop.index }} ---
{{ doc.content }}
{% endfor %}

## 질문
{{ query }}

## 답변
""".strip().replace("__NO_CONTEXT_RESPONSE__", NO_CONTEXT_RESPONSE)


def create_prompt_builder(template: str | None = None) -> PromptBuilder:
  """Create a prompt builder that waits for retrieved documents."""
  builder = PromptBuilder(
    template=template or RAG_PROMPT_TEMPLATE,
    required_variables=["documents"],
  )
  logger.debug("Prompt builder created")
  return builder
