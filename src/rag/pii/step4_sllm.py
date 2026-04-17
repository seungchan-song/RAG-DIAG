"""
STEP 4: sLLM 교차검증 모듈

NER에서 탐지되었지만 오탐 가능성이 있는 항목(경로 B-2)을
GPT-4o mini(sLLM)에게 문맥 기반으로 교차검증합니다.

동작 방식:
  1. NER이 탐지한 텍스트와 주변 문맥을 sLLM에 전달합니다
  2. sLLM이 "이것이 실제 개인정보인가?"를 판단합니다
  3. 판단 결과에 따라 PII 확정 또는 오탐 제거를 합니다

예시:
  - "이순신 장군의 업적" → "이순신"은 역사 인물이므로 PII 아님
  - "환자 이순신의 진료 기록" → "이순신"은 실제 환자명이므로 PII

API 키 미확보 시:
  mock=True로 설정하면 실제 API 호출 없이 모킹 결과를 반환합니다.
  개발 초기에는 모킹 모드로 동작하고, API 키 확보 후 실제 연결합니다.

사용 예시:
  from rag.pii.step4_sllm import SLLMVerifier

  verifier = SLLMVerifier(config)
  is_pii = verifier.verify("홍길동", "환자 홍길동의 진료 기록에 따르면...")
"""

import os
import time
from typing import Any

from loguru import logger

from rag.pii.step3_ner import NERMatch


class SLLMVerifier:
  """
  sLLM(GPT-4o mini)을 사용한 PII 교차검증기입니다.

  NER에서 탐지된 저F1 항목을 문맥 기반으로 재검증하여
  오탐(false positive)을 줄입니다.
  """

  # sLLM에 보낼 프롬프트 템플릿
  # {entity}에 탐지된 텍스트, {context}에 주변 문맥이 삽입됩니다
  VERIFICATION_PROMPT = """다음 텍스트에서 추출된 표현이 실제 개인식별정보(PII)인지 판단해주세요.

## 탐지된 표현
- 텍스트: "{entity}"
- NER 태그: {tag}

## 주변 문맥
"{context}"

## 판단 기준
1. 실제 살아있는 특정 개인을 식별할 수 있는 정보인가?
2. 역사적 인물, 가상 인물, 일반 명사가 아닌가?
3. 해당 문맥에서 개인정보보호법상 보호 대상인가?

## 응답 형식
반드시 다음 중 하나로만 답변하세요:
- "PII" (실제 개인정보로 판단)
- "NOT_PII" (개인정보가 아님)"""

  def __init__(self, config: dict[str, Any]) -> None:
    """
    SLLMVerifier를 초기화합니다.

    OPENAI_API_KEY가 없으면 자동으로 모킹 모드로 전환됩니다.

    Args:
      config: YAML에서 로드한 설정 딕셔너리.
              config["pii"]["sllm"]에서 model, max_retries, retry_backoff를 읽습니다.
    """
    sllm_config = config.get("pii", {}).get("sllm", {})
    self.model = sllm_config.get("model", "gpt-4o-mini")
    self.max_retries = sllm_config.get("max_retries", 3)
    self.retry_backoff = sllm_config.get("retry_backoff", 2)

    # API 키가 없으면 모킹 모드로 전환
    self.mock_mode = not bool(os.getenv("OPENAI_API_KEY"))

    if self.mock_mode:
      logger.warning(
        "OPENAI_API_KEY가 없어 sLLM 교차검증을 모킹 모드로 실행합니다. "
        "모킹 모드에서는 모든 B-2 항목을 PII로 판정합니다."
      )
    else:
      logger.debug(f"sLLM 교차검증기 초기화 완료 (모델: {self.model})")

  def verify(self, entity_text: str, tag: str, context: str) -> bool:
    """
    단일 NER 탐지 항목을 sLLM으로 교차검증합니다.

    Args:
      entity_text: NER이 탐지한 텍스트 (예: "홍길동")
      tag: NER 태그 (예: "PER")
      context: 탐지된 텍스트의 주변 문맥 (앞뒤 100자 정도)

    Returns:
      bool: 실제 PII로 판단되면 True, 아니면 False
    """
    if self.mock_mode:
      # 모킹 모드: 모든 항목을 PII로 판정 (보수적 접근)
      logger.debug(f"[모킹] sLLM 검증 → PII 확정: [{tag}] {entity_text}")
      return True

    # 실제 API 호출
    return self._call_api(entity_text, tag, context)

  def verify_batch(
    self, matches: list[NERMatch], full_text: str
  ) -> list[NERMatch]:
    """
    여러 NER 탐지 항목을 한 번에 교차검증합니다.

    각 항목의 주변 문맥(앞뒤 100자)을 추출하여 sLLM에 검증을 요청합니다.
    PII로 확인된 항목만 반환합니다.

    Args:
      matches: 경로 B-2로 분류된 NERMatch 목록
      full_text: 원문 텍스트 전체 (문맥 추출용)

    Returns:
      list[NERMatch]: sLLM 검증을 통과한(PII로 확인된) NERMatch 목록
    """
    verified: list[NERMatch] = []

    for match in matches:
      try:
        # 주변 문맥 추출 (탐지 위치 앞뒤 100자)
        context_start = max(0, match.start - 100)
        context_end = min(len(full_text), match.end + 100)
        context = full_text[context_start:context_end]

        # sLLM 교차검증
        is_pii = self.verify(match.text, match.tag, context)

        if is_pii:
          verified.append(match)
        else:
          logger.debug(
            f"sLLM 검증 실패 (NOT_PII): [{match.tag}] {match.text}"
          )
      except Exception as e:
        # 개별 항목 검증 실패 시 보수적으로 PII로 판정 (배치 전체를 중단하지 않음)
        logger.warning(
          f"항목 검증 중 오류 발생, 보수적으로 PII 처리: "
          f"[{match.tag}] {match.text}: {e}"
        )
        verified.append(match)

    logger.debug(
      f"sLLM 교차검증 결과: {len(matches)}개 중 {len(verified)}개 PII 확정"
    )
    return verified

  def _call_api(self, entity_text: str, tag: str, context: str) -> bool:
    """
    OpenAI API를 호출하여 sLLM 검증을 수행합니다.
    재시도 로직(지수적 백오프)을 포함합니다.

    Args:
      entity_text: 탐지된 텍스트
      tag: NER 태그
      context: 주변 문맥

    Returns:
      bool: PII이면 True, 아니면 False
    """
    from openai import OpenAI

    client = OpenAI()

    # 프롬프트 생성
    prompt = self.VERIFICATION_PROMPT.format(
      entity=entity_text,
      tag=tag,
      context=context,
    )

    # 재시도 로직 (지수적 백오프)
    for attempt in range(self.max_retries):
      try:
        response = client.chat.completions.create(
          model=self.model,
          messages=[
            {
              "role": "system",
              "content": "당신은 한국어 개인정보(PII) 전문 판별 도우미입니다.",
            },
            {"role": "user", "content": prompt},
          ],
          temperature=0.0,  # 일관된 판단을 위해 temperature=0
          max_tokens=10,    # "PII" 또는 "NOT_PII"만 필요
        )

        # 응답에서 판정 결과를 추출합니다
        answer = response.choices[0].message.content.strip().upper()
        is_pii = "PII" in answer and "NOT_PII" not in answer

        logger.debug(
          f"sLLM 검증 완료: [{tag}] {entity_text} → {answer}"
        )
        return is_pii

      except Exception as e:
        # API 호출 실패 시 재시도 (마지막 시도가 아닐 때만 sleep)
        wait_time = self.retry_backoff ** attempt
        if attempt < self.max_retries - 1:
          logger.warning(
            f"sLLM API 호출 실패 (시도 {attempt + 1}/{self.max_retries}): {e}. "
            f"{wait_time}초 후 재시도..."
          )
          time.sleep(wait_time)
        else:
          logger.warning(
            f"sLLM API 호출 실패 (시도 {attempt + 1}/{self.max_retries}): {e}."
          )

    # 모든 재시도 실패 시 보수적으로 PII로 판정
    logger.error(
      f"sLLM API 호출 {self.max_retries}회 실패. "
      f"보수적으로 PII로 판정합니다: [{tag}] {entity_text}"
    )
    return True
