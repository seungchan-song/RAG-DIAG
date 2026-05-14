"""Step 4 sLLM verification for ambiguous NER findings.

Step 3 NER이 추출한 후보 중 F1 신뢰도가 낮은 항목(B-2 경로)을
GPT-4o-mini 등 외부 sLLM에 문맥과 함께 보내 PII 여부를 최종 판정한다.

성능 고려사항:
  - 각 NER 후보당 1번의 API 호출이 필요해 동기 순차 호출 시
    "후보 수 × 평균 응답시간"만큼의 시간이 누적된다.
  - 동기 인터페이스(verify_batch)는 그대로 유지하면서 내부에서만
    asyncio + AsyncOpenAI 로 병렬 호출하여 wall-clock 시간을
    대폭 단축한다.
  - 동시 호출 수는 ``pii.sllm.concurrency`` 설정으로 제어하며,
    rate-limit 초과를 막기 위해 asyncio.Semaphore 로 상한을 둔다.
"""

from __future__ import annotations

import asyncio
import os
import time
from typing import Any

from loguru import logger

from rag.pii.step3_ner import NERMatch


class SLLMVerifier:
  """sLLM을 이용해 Step 3 저신뢰 후보(B-2 경로)를 교차검증한다."""

  VERIFICATION_PROMPT = """Decide whether the extracted span below is real personal information.

Entity: "{entity}"
NER tag: {tag}
Context: "{context}"

Reply with exactly one token:
- PII
- NOT_PII
"""

  def __init__(self, config: dict[str, Any]) -> None:
    """설정 딕셔너리에서 sLLM 옵션을 읽어 검증기를 초기화한다.

    Args:
      config: 전체 설정 딕셔너리. ``pii.sllm`` 하위 키를 사용한다.

    주요 설정 키:
      - ``pii.runtime.enable_step4``: Step 4 활성화 여부
      - ``pii.sllm.model``: 호출할 OpenAI 모델명
      - ``pii.sllm.max_retries``: API 호출 재시도 횟수
      - ``pii.sllm.retry_backoff``: 지수 백오프 베이스(초)
      - ``pii.sllm.concurrency``: 동시 API 호출 상한
        (rate-limit 보호용; 기본 8)
    """
    pii_config = config.get("pii", {})
    runtime_config = pii_config.get("runtime", {})
    sllm_config = pii_config.get("sllm", {})

    self.enabled = bool(runtime_config.get("enable_step4", True))
    self.model = sllm_config.get("model", "gpt-4o-mini")
    self.max_retries = int(sllm_config.get("max_retries", 3))
    self.retry_backoff = int(sllm_config.get("retry_backoff", 2))
    # 동시 호출 수 상한 (1 이상 정수). 너무 크면 rate-limit, 너무 작으면 직렬화.
    self.concurrency = max(1, int(sllm_config.get("concurrency", 8)))
    self.mock_mode = self.enabled and not bool(os.getenv("OPENAI_API_KEY"))
    self.error_message = ""

    if not self.enabled:
      self.mode = "disabled"
    elif self.mock_mode:
      self.mode = "mock_conservative"
    else:
      self.mode = "api"

  # ---------------------------------------------------------------------
  # 외부 동기 인터페이스 (기존 호출자와의 호환을 보장한다)
  # ---------------------------------------------------------------------

  def verify(self, entity_text: str, tag: str, context: str) -> bool:
    """단일 NER 후보 1건을 동기적으로 검증한다.

    Args:
      entity_text: 검증할 개체 문자열
      tag: NER 태그(PER, LOC 등)
      context: 개체 주변 문맥(앞뒤 약 100자)

    Returns:
      bool: PII로 판정되면 True, 아니면 False.
        - Step 4 비활성 상태이면 항상 False
        - mock 모드이면 보수적으로 항상 True
        - API 호출이 모두 실패하면 보수적으로 True 폴백

    Notes:
      현재 호출자는 verify_batch를 사용하므로 이 메서드는 사실상
      단위 테스트/디버깅 용도다. 단건 호출이 잦지 않으므로
      이벤트 루프 1회 생성 비용은 무시한다.
    """
    if not self.enabled:
      return False

    if self.mock_mode:
      logger.debug("Step 4 mock-conservative accept: [{}] {}", tag, entity_text)
      return True

    return asyncio.run(self._verify_single_with_new_client(entity_text, tag, context))

  def verify_batch(self, matches: list[NERMatch], full_text: str) -> list[NERMatch]:
    """저신뢰 NER 후보 목록을 병렬 검증하여 PII로 판정된 것만 반환한다.

    내부적으로 동시 호출 수를 ``concurrency`` 로 제한한 채 asyncio.gather
    로 병렬 호출한다. 외부에서 보기에는 기존과 동일한 동기 함수다.

    Args:
      matches: NER이 추출한 저신뢰 후보 리스트
      full_text: 원문 전체. 각 후보의 start/end 인덱스 주변 문맥
        100자를 잘라 검증 프롬프트에 첨부한다.

    Returns:
      list[NERMatch]: 입력 순서를 보존한 채 PII로 판정된 매치들만 담은 리스트.
    """
    if not self.enabled or not matches:
      return []

    if self.mock_mode:
      # mock 모드는 보수적으로 모두 PII로 인정 (기존 동작과 동일)
      logger.debug("Step 4 mock-conservative accept (batch size={})", len(matches))
      return list(matches)

    try:
      return asyncio.run(self._verify_batch_async(matches, full_text))
    except RuntimeError as exc:
      # 호출 컨텍스트에 이미 실행 중인 이벤트 루프가 있는 경우 발생.
      # 현재 코드베이스(CLI/Haystack 동기 파이프라인)에서는 발생하지 않지만,
      # Jupyter 등에서 호출될 가능성에 대비해 동기 폴백을 제공한다.
      logger.warning(
        "Step 4 async 실행 불가({}). 동기 폴백으로 전환합니다.",
        exc,
      )
      return self._verify_batch_sync_fallback(matches, full_text)

  # ---------------------------------------------------------------------
  # 내부 async 구현
  # ---------------------------------------------------------------------

  async def _verify_batch_async(
    self,
    matches: list[NERMatch],
    full_text: str,
  ) -> list[NERMatch]:
    """병렬 API 호출 코어. 단일 AsyncOpenAI 클라이언트를 공유한다."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI()
    semaphore = asyncio.Semaphore(self.concurrency)

    try:
      tasks = [
        self._verify_one_async(client, semaphore, match, full_text)
        for match in matches
      ]
      # return_exceptions=True: 한 호출의 예외가 gather 전체를 깨지 않도록 함.
      results = await asyncio.gather(*tasks, return_exceptions=True)
    finally:
      # AsyncOpenAI는 내부적으로 httpx 클라이언트를 점유하므로 명시적으로 닫는다.
      await client.close()

    verified: list[NERMatch] = []
    for match, result in zip(matches, results):
      if isinstance(result, Exception):
        # 호출 실패 시 보수적으로 PII로 인정 (기존 verify_batch 폴백과 동일).
        self.error_message = str(result)
        logger.warning(
          "Step 4 verification failed for [{}] {}: {}. Falling back conservatively.",
          match.tag,
          match.text,
          result,
        )
        verified.append(match)
      elif result:
        verified.append(match)
    return verified

  async def _verify_one_async(
    self,
    client: Any,
    semaphore: asyncio.Semaphore,
    match: NERMatch,
    full_text: str,
  ) -> bool:
    """단일 후보 1건을 비동기로 검증한다. 세마포어로 동시성 상한을 지킨다."""
    async with semaphore:
      context_start = max(0, match.start - 100)
      context_end = min(len(full_text), match.end + 100)
      context = full_text[context_start:context_end]
      return await self._call_api_async(client, match.text, match.tag, context)

  async def _call_api_async(
    self,
    client: Any,
    entity_text: str,
    tag: str,
    context: str,
  ) -> bool:
    """공유된 AsyncOpenAI 클라이언트로 단일 검증 API 호출을 수행한다.

    재시도 정책은 기존 동기 _call_api 와 동일하다:
      - max_retries 회까지 재시도
      - 매 시도 사이에 retry_backoff ** attempt 초 대기 (asyncio.sleep)
      - 모두 실패하면 보수적으로 True(PII 인정) 반환
    """
    prompt = self.VERIFICATION_PROMPT.format(
      entity=entity_text,
      tag=tag,
      context=context,
    )

    for attempt in range(self.max_retries):
      try:
        response = await client.chat.completions.create(
          model=self.model,
          messages=[
            {
              "role": "system",
              "content": "You are validating whether a span is personal information.",
            },
            {"role": "user", "content": prompt},
          ],
          temperature=0.0,
          max_tokens=10,
        )
        answer = (response.choices[0].message.content or "").strip().upper()
        self.error_message = ""
        return "PII" in answer and "NOT_PII" not in answer
      except Exception as error:
        self.error_message = str(error)
        if attempt < self.max_retries - 1:
          wait_time = self.retry_backoff ** attempt
          logger.warning(
            "Step 4 API call failed on attempt {} of {}: {}. Retrying in {}s.",
            attempt + 1,
            self.max_retries,
            error,
            wait_time,
          )
          await asyncio.sleep(wait_time)
        else:
          logger.warning(
            "Step 4 API call failed on attempt {} of {}: {}.",
            attempt + 1,
            self.max_retries,
            error,
          )

    logger.error(
      "Step 4 API exhausted retries. Falling back conservatively for [{}] {}.",
      tag,
      entity_text,
    )
    return True

  async def _verify_single_with_new_client(
    self,
    entity_text: str,
    tag: str,
    context: str,
  ) -> bool:
    """단건 verify() 용. 임시 AsyncOpenAI 클라이언트를 1회만 사용한다."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI()
    try:
      return await self._call_api_async(client, entity_text, tag, context)
    finally:
      await client.close()

  # ---------------------------------------------------------------------
  # 동기 폴백 (asyncio.run 사용 불가 환경 대비)
  # ---------------------------------------------------------------------

  def _verify_batch_sync_fallback(
    self,
    matches: list[NERMatch],
    full_text: str,
  ) -> list[NERMatch]:
    """이벤트 루프가 이미 실행 중인 환경에서 사용하는 직렬 폴백 경로."""
    verified: list[NERMatch] = []
    for match in matches:
      try:
        context_start = max(0, match.start - 100)
        context_end = min(len(full_text), match.end + 100)
        context = full_text[context_start:context_end]
        if self._call_api_sync(match.text, match.tag, context):
          verified.append(match)
      except Exception as error:
        self.error_message = str(error)
        logger.warning(
          "Step 4 sync fallback failed for [{}] {}: {}. Accepting conservatively.",
          match.tag,
          match.text,
          error,
        )
        verified.append(match)
    return verified

  def _call_api_sync(self, entity_text: str, tag: str, context: str) -> bool:
    """동기 OpenAI 클라이언트를 사용한 단건 검증. 폴백 경로에서만 호출된다."""
    from openai import OpenAI

    client = OpenAI()
    prompt = self.VERIFICATION_PROMPT.format(
      entity=entity_text,
      tag=tag,
      context=context,
    )

    for attempt in range(self.max_retries):
      try:
        response = client.chat.completions.create(
          model=self.model,
          messages=[
            {
              "role": "system",
              "content": "You are validating whether a span is personal information.",
            },
            {"role": "user", "content": prompt},
          ],
          temperature=0.0,
          max_tokens=10,
        )
        answer = (response.choices[0].message.content or "").strip().upper()
        self.error_message = ""
        return "PII" in answer and "NOT_PII" not in answer
      except Exception as error:
        self.error_message = str(error)
        if attempt < self.max_retries - 1:
          wait_time = self.retry_backoff ** attempt
          logger.warning(
            "Step 4 API call failed on attempt {} of {}: {}. Retrying in {}s.",
            attempt + 1,
            self.max_retries,
            error,
            wait_time,
          )
          time.sleep(wait_time)
        else:
          logger.warning(
            "Step 4 API call failed on attempt {} of {}: {}.",
            attempt + 1,
            self.max_retries,
            error,
          )

    logger.error(
      "Step 4 API exhausted retries. Falling back conservatively for [{}] {}.",
      tag,
      entity_text,
    )
    return True

  # ---------------------------------------------------------------------
  # 런타임 상태 보고
  # ---------------------------------------------------------------------

  def get_runtime_status(
    self,
    *,
    candidate_count: int = 0,
    verified_count: int = 0,
    reason: str = "",
  ) -> dict[str, Any]:
    """리포트/디버그용 Step 4 런타임 스냅샷을 반환한다."""
    status = "skipped"
    if self.enabled and candidate_count > 0:
      status = "ready"
    elif self.enabled and self.mode == "mock_conservative":
      status = "ready"
    elif not self.enabled:
      status = "skipped"

    return {
      "enabled": self.enabled,
      "mode": self.mode,
      "status": status,
      "reason": reason,
      "model": self.model,
      "concurrency": self.concurrency,
      "candidate_count": candidate_count,
      "verified_count": verified_count,
      "error": self.error_message,
    }
