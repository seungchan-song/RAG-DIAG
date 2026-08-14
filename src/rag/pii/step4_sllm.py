"""Step 4 sLLM 교차검증 (B-2 경로 NER 후보 대상).

Step 3 NER 후보 중 태그만으로 확정할 수 없는 항목을 sLLM 에 문맥과 함께 보내 PII 여부를
최종 판정한다. 기본 대상은 로컬 Ollama 이며(``pii.sllm.base_url``), 이 값을 비우면
OpenAI GPT-4o-mini 로 되돌아간다.

후보 하나당 호출 1번이라 순차 처리하면 "후보 수 × 응답시간"이 그대로 누적된다. 동기
인터페이스(verify_batch)는 유지한 채 내부에서만 asyncio 로 병렬 호출하며, 동시 호출
상한은 ``pii.sllm.concurrency`` 가 Semaphore 로 건다.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from typing import Any

from loguru import logger

from rag.pii.step3_ner import NER_LABEL_MAP, NERMatch

# 내부 태그 → 33종 원본 라벨 역번역표
# STEP 3 은 모델 라벨(NAME·WORKPLACE…)을 내부 태그(PER·ORG…)로 접어서 넘긴다.
# 로컬 sLLM 어댑터는 33종 원본 라벨로 학습됐으므로 되돌려서 보내야 한다.
# NER_LABEL_MAP 을 뒤집되(먼저 선언된 라벨이 이김) 아래 예외만 손으로 잡는다.
_ADAPTER_TAG_OVERRIDES: dict[str, str] = {
  # ORG 는 DEPARTMENT/WORKPLACE/SCHOOL 3개가 합쳐진 태그라 복원이 불가능하다.
  # 어댑터가 학습한 것은 WORKPLACE 뿐이므로 그쪽으로 보낸다(정보 손실 감수).
  # DEPARTMENT·SCHOOL 학습 추가는 팀원에게 요청해 둔 상태다.
  "ORG": "WORKPLACE",
}


def _build_adapter_tag_map() -> dict[str, str]:
  """내부 단축 태그 → 어댑터 학습 라벨 매핑을 만든다.

  Returns:
    dict[str, str]: {"PER": "NAME", "ORG": "WORKPLACE", ...}. 대응 라벨이
      없는 태그는 아예 담기지 않으며, 호출부가 내부 태그를 그대로 쓴다.
  """
  reverse: dict[str, str] = {}
  for source_label, internal_tag in NER_LABEL_MAP.items():
    reverse.setdefault(internal_tag, source_label)
  reverse.update(_ADAPTER_TAG_OVERRIDES)
  return reverse


ADAPTER_TAG_MAP: dict[str, str] = _build_adapter_tag_map()


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

  # 로컬 어댑터(한국어 system + JSON user)용 기본 지시문.
  # 어댑터의 실제 학습 지시문과 다를 수 있어 `pii.sllm.adapter_system_prompt`
  # 로 덮어쓸 수 있게 열어 둔다.
  ADAPTER_SYSTEM_PROMPT = (
    "당신은 개인정보 판별기입니다. 주어진 후보가 개인정보인지 판단해 "
    "PII 또는 NOT_PII 중 하나만 출력하세요."
  )

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
      - ``pii.sllm.base_url``: OpenAI 호환 엔드포인트 주소. 지정하면 로컬
        sLLM(vLLM·Ollama 등)으로 붙고 Closed API 호출이 0건이 된다.
        환경변수 ``PII_SLLM_BASE_URL`` 로도 지정할 수 있다.
      - ``pii.sllm.prompt_format``: ``plain``(기본, 영문 평문) 또는
        ``adapter_json``(한국어 system + JSON user, 팀원 로컬 어댑터 형식)
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
    self.base_url = (
      os.getenv("PII_SLLM_BASE_URL") or sllm_config.get("base_url") or ""
    ).strip()
    # 로컬 서버는 키를 검사하지 않지만 OpenAI SDK 가 빈 키를 거부하므로 자리채움을 준다.
    self.api_key = (
      os.getenv("PII_SLLM_API_KEY") or sllm_config.get("api_key") or ""
    ).strip()
    self.prompt_format = sllm_config.get("prompt_format", "plain")
    self.adapter_system_prompt = (
      sllm_config.get("adapter_system_prompt") or self.ADAPTER_SYSTEM_PROMPT
    )
    # base_url 이 있으면 OPENAI_API_KEY 없이도 실제 호출이 가능하므로 mock 으로 빠지지 않는다.
    self.mock_mode = (
      self.enabled and not self.base_url and not bool(os.getenv("OPENAI_API_KEY"))
    )
    self.error_message = ""

    if not self.enabled:
      self.mode = "disabled"
    elif self.mock_mode:
      self.mode = "mock_conservative"
    else:
      self.mode = "api"

  # 클라이언트 · 프롬프트 구성 (OpenAI / 로컬 sLLM 공통 경로)

  def _client_kwargs(self) -> dict[str, str]:
    """OpenAI/AsyncOpenAI 생성자에 넘길 인자를 만든다.

    Returns:
      dict[str, str]: base_url·api_key 중 설정된 것만 담긴 딕셔너리.
        비어 있으면 SDK 기본값(OpenAI 공식 엔드포인트 + 환경변수 키)을 쓴다.
    """
    kwargs: dict[str, str] = {}
    if self.base_url:
      kwargs["base_url"] = self.base_url
      # 로컬 서버는 키를 검사하지 않지만 SDK 가 빈 키에서 예외를 던진다.
      kwargs["api_key"] = self.api_key or "EMPTY"
    elif self.api_key:
      kwargs["api_key"] = self.api_key
    return kwargs

  def _build_messages(
    self,
    entity_text: str,
    tag: str,
    context: str,
  ) -> list[dict[str, str]]:
    """prompt_format 에 맞는 chat messages 를 만든다.

    Args:
      tag: 내부 단축 태그(PER·ORG 등)
      context: 개체 주변 문맥

    Returns:
      list[dict[str, str]]: chat.completions 에 그대로 넘길 messages.
    """
    if self.prompt_format != "adapter_json":
      return [
        {
          "role": "system",
          "content": "You are validating whether a span is personal information.",
        },
        {
          "role": "user",
          "content": self.VERIFICATION_PROMPT.format(
            entity=entity_text,
            tag=tag,
            context=context,
          ),
        },
      ]

    # 한계: 문맥 내 첫 출현 위치로 오프셋을 잡는다. 같은 값이 문맥에 두 번
    # 나오면 앞쪽을 가리키지만, 어댑터는 text/tag 위주로 판단하므로 실익이 없다.
    # 정확한 오프셋이 필요해지면 NERMatch 좌표를 여기까지 내려보내면 된다.
    offset = context.find(entity_text)
    payload = {
      "answer": context,
      "candidate": {
        "text": entity_text,
        # 어댑터는 33종 원본 라벨로 학습됐으므로 내부 태그를 되돌려 보낸다.
        "tag": ADAPTER_TAG_MAP.get(tag, tag),
        "start": offset,
        "end": offset + len(entity_text) if offset >= 0 else -1,
      },
    }
    return [
      {
        "role": "system",
        "content": self.adapter_system_prompt,
      },
      {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
    ]

  # 외부 동기 인터페이스 (기존 호출자와의 호환을 보장한다)

  def verify(self, entity_text: str, tag: str, context: str) -> bool:
    """단일 NER 후보 1건을 동기적으로 검증한다.

    Args:
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

  # 내부 async 구현

  async def _verify_batch_async(
    self,
    matches: list[NERMatch],
    full_text: str,
  ) -> list[NERMatch]:
    """병렬 API 호출 코어. 단일 AsyncOpenAI 클라이언트를 공유한다."""
    from openai import AsyncOpenAI

    client = AsyncOpenAI(**self._client_kwargs())
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
    messages = self._build_messages(entity_text, tag, context)

    for attempt in range(self.max_retries):
      try:
        response = await client.chat.completions.create(
          model=self.model,
          messages=messages,
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

    client = AsyncOpenAI(**self._client_kwargs())
    try:
      return await self._call_api_async(client, entity_text, tag, context)
    finally:
      await client.close()

  # 동기 폴백 (asyncio.run 사용 불가 환경 대비)

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

    client = OpenAI(**self._client_kwargs())
    messages = self._build_messages(entity_text, tag, context)

    for attempt in range(self.max_retries):
      try:
        response = client.chat.completions.create(
          model=self.model,
          messages=messages,
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

  # 런타임 상태 보고

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
      # 대회 규정(Closed API 0건) 증빙용 — 리포트가 이 값으로 로컬/외부를 구분한다.
      "endpoint": self.base_url or "openai-default",
      "is_closed_api": self.mode == "api" and not self.base_url,
      "prompt_format": self.prompt_format,
      "concurrency": self.concurrency,
      "candidate_count": candidate_count,
      "verified_count": verified_count,
      "error": self.error_message,
    }
