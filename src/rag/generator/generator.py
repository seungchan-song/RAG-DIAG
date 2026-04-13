"""
LLM 응답 생성 모듈

프롬프트를 LLM(GPT-4o mini 등)에 전달하여 최종 답변을 생성합니다.

핵심 개념:
  - Generator: 프롬프트를 받아서 LLM에게 보내고 응답을 받는 컴포넌트
  - OpenAI API: GPT-4o mini 등의 모델을 API로 호출
  - MockGenerator: API 키가 없을 때 검색된 문서 내용을 그대로 반환하는 모의 생성기
  - temperature: 응답의 창의성 정도 (0에 가까울수록 일관적, 1에 가까울수록 다양)
  - max_tokens: 생성할 최대 토큰 수

사용 예시:
  generator = create_openai_generator(config)
  result = generator.run(prompt="질문에 답변해주세요...")
"""

import os
from typing import Any

from haystack import component
from loguru import logger


@component
class MockGenerator:
  """
  API 키가 없을 때 사용하는 모의(mock) 생성기입니다.

  프롬프트에 포함된 검색 결과(문서 내용)를 그대로 응답으로 반환합니다.
  이를 통해 API 키 없이도 공격 시뮬레이션의 전체 파이프라인을 테스트할 수 있습니다.

  실제 LLM 응답 대신 검색된 문서 원문을 반환하므로,
  ROUGE-L 기반 유출 판정(R2) 등의 평가에서도 유의미한 결과를 얻습니다.
  """

  @component.output_types(replies=list[str], meta=list[dict])
  def run(self, prompt: str) -> dict[str, Any]:
    """
    프롬프트에서 문서 내용을 추출하여 응답으로 반환합니다.

    Args:
      prompt: PromptBuilder가 구성한 프롬프트 (문서 내용 + 질문 포함)

    Returns:
      dict: {"replies": [응답 텍스트], "meta": [메타데이터]}
    """
    # 프롬프트에서 "참고 문서:" ~ "질문:" 사이의 텍스트를 추출합니다
    # 이 부분이 검색된 문서 내용입니다
    reply = prompt
    if "참고 문서:" in prompt and "질문:" in prompt:
      start = prompt.index("참고 문서:") + len("참고 문서:")
      end = prompt.index("질문:")
      reply = prompt[start:end].strip()

    logger.debug(
      f"MockGenerator 응답 생성 (길이: {len(reply)}자)"
    )
    return {
      "replies": [reply],
      "meta": [{"model": "mock", "mock": True}],
    }


def create_generator(config: dict[str, Any]) -> Any:
  """
  설정과 환경에 맞는 Generator를 자동으로 선택하여 생성합니다.

  - OPENAI_API_KEY가 있으면: OpenAI Generator (실제 LLM)
  - OPENAI_API_KEY가 없으면: MockGenerator (모의 응답)

  Args:
    config: YAML에서 로드한 설정 딕셔너리

  Returns:
    Generator 컴포넌트 (OpenAIGenerator 또는 MockGenerator)
  """
  if os.getenv("OPENAI_API_KEY"):
    return create_openai_generator(config)
  else:
    logger.warning(
      "OPENAI_API_KEY가 설정되지 않았습니다. "
      "MockGenerator를 사용합니다 (검색 문서 원문을 응답으로 반환)."
    )
    return MockGenerator()


def create_openai_generator(config: dict[str, Any]) -> Any:
  """
  OpenAI GPT 모델을 사용하는 Generator를 생성합니다.

  환경변수 OPENAI_API_KEY가 설정되어 있어야 합니다.
  (.env 파일에서 자동 로드됩니다)

  Args:
    config: YAML에서 로드한 설정 딕셔너리.
            config["generator"]["openai"] 아래의 설정을 사용합니다.

  Returns:
    OpenAIGenerator: OpenAI 기반 텍스트 생성 컴포넌트

  Raises:
    ValueError: OPENAI_API_KEY 환경변수가 설정되지 않았을 때

  설정 예시 (config/default.yaml):
    generator:
      openai:
        model: "gpt-4o-mini-2024-07-18"
        temperature: 0.1
        max_tokens: 1024
  """
  from haystack.components.generators import OpenAIGenerator

  # API 키 확인
  if not os.getenv("OPENAI_API_KEY"):
    raise ValueError(
      "OPENAI_API_KEY 환경변수가 설정되지 않았습니다. "
      ".env 파일에 OPENAI_API_KEY=sk-... 형태로 설정해주세요."
    )

  # 설정값 읽기
  gen_config = config.get("generator", {}).get("openai", {})
  model = gen_config.get("model", "gpt-4o-mini-2024-07-18")
  temperature = gen_config.get("temperature", 0.1)
  max_tokens = gen_config.get("max_tokens", 1024)

  generator = OpenAIGenerator(
    model=model,
    generation_kwargs={
      "temperature": temperature,
      "max_tokens": max_tokens,
    },
  )

  logger.debug(
    f"OpenAI Generator 생성 완료 "
    f"(모델: {model}, temperature: {temperature})"
  )
  return generator
