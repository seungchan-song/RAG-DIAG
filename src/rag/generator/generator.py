"""
LLM 응답 생성 모듈

프롬프트를 LLM(GPT-4o mini, HyperCLOVA X 등)에 전달하여 최종 답변을 생성합니다.

핵심 개념:
  - Generator: 프롬프트를 받아서 LLM에게 보내고 응답을 받는 컴포넌트
  - OpenAI API: GPT-4o mini 등의 모델을 API로 호출
  - HyperCLOVA X: 네이버 ClovaStudio 의 HCX-DASH-002 모델을 API 로 호출
  - MockGenerator: API 키가 없을 때 검색된 문서 내용을 그대로 반환하는 모의 생성기
  - temperature: 응답의 창의성 정도 (0에 가까울수록 일관적, 1에 가까울수록 다양)
  - max_tokens: 생성할 최대 토큰 수

사용 예시:
  generator = create_openai_generator(config)
  result = generator.run(prompt="질문에 답변해주세요...")

  # 또는 국내 LLM 사용
  generator = create_clova_generator(config)
"""

import json
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

  system_prompt를 받더라도 mock이므로 실제 반영은 하지 않습니다.
  (방어 지시문 우회 시뮬레이션 용도로, 의도적으로 무시합니다.)
  """

  def __init__(self, system_prompt: str | None = None) -> None:
    """
    Args:
      system_prompt: 설정에서 전달받은 시스템 프롬프트. Mock에서는 사용하지 않음.
    """
    if system_prompt:
      logger.debug("MockGenerator: system_prompt 수신됨 (mock이므로 미적용, 길이={}자)", len(system_prompt))

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

  선택 우선순위:
    1) config["generator"]["provider"] 가 "local"/"ollama"/"vllm" → 로컬 오픈웨이트 생성기
       (대회 규정 A-1: Closed API 0건. 로컬 서버 호출이라 API 키 불필요)
    2) config["generator"]["provider"] 가 "clova"  → HyperCLOVA X 생성기 (Closed API)
    3) config["generator"]["provider"] 가 "openai" → OpenAI 생성기 (Closed API)
    4) provider 가 "auto" 또는 미지정이면 환경변수에 따라 자동 선택
    5) 어떤 API 키도 없으면 MockGenerator

  config["generator"]["system_prompt"] 가 설정되어 있으면
  각 생성기에 페르소나/방어 지시문으로 전달됩니다.

  Args:
    config: YAML에서 로드한 설정 딕셔너리

  Returns:
    Generator 컴포넌트
  """
  generator_config = config.get("generator", {}) or {}
  provider = str(generator_config.get("provider", "auto")).lower()
  system_prompt: str | None = generator_config.get("system_prompt") or None

  if system_prompt:
    logger.debug(
      "시스템 프롬프트 적용됨 (길이={}자, provider={})",
      len(system_prompt),
      provider,
    )

  # 로컬 오픈웨이트 모델(대회 규정 A-1). 로컬 서버 호출이므로 API 키가 필요 없고,
  # 서버가 꺼져 있어도 생성은 성공한 뒤 run() 에서 오류 메타로 안전 처리된다.
  if provider in {"local", "ollama", "vllm", "local_openai", "openai_compat"}:
    return create_local_generator(config, system_prompt=system_prompt)

  if provider == "clova":
    if os.getenv("NAVER_CLOVA_API_KEY"):
      return create_clova_generator(config, system_prompt=system_prompt)
    logger.warning(
      "NAVER_CLOVA_API_KEY 가 설정되지 않았습니다. provider=clova 가 요청됐지만 "
      "MockGenerator 로 폴백합니다."
    )
    return MockGenerator(system_prompt=system_prompt)

  if provider == "openai":
    if os.getenv("OPENAI_API_KEY"):
      return create_openai_generator(config, system_prompt=system_prompt)
    logger.warning(
      "OPENAI_API_KEY 가 설정되지 않았습니다. provider=openai 가 요청됐지만 "
      "MockGenerator 로 폴백합니다."
    )
    return MockGenerator(system_prompt=system_prompt)

  # provider == "auto" (또는 미지정): 환경변수 우선순위에 따라 결정
  if os.getenv("OPENAI_API_KEY"):
    return create_openai_generator(config, system_prompt=system_prompt)
  if os.getenv("NAVER_CLOVA_API_KEY"):
    return create_clova_generator(config, system_prompt=system_prompt)
  logger.warning(
    "OPENAI_API_KEY / NAVER_CLOVA_API_KEY 모두 설정되지 않았습니다. "
    "MockGenerator를 사용합니다 (검색 문서 원문을 응답으로 반환)."
  )
  return MockGenerator(system_prompt=system_prompt)


def create_openai_generator(
  config: dict[str, Any],
  *,
  system_prompt: str | None = None,
) -> Any:
  """
  OpenAI GPT 모델을 사용하는 Generator를 생성합니다.

  환경변수 OPENAI_API_KEY가 설정되어 있어야 합니다.
  (.env 파일에서 자동 로드됩니다)

  Args:
    config: YAML에서 로드한 설정 딕셔너리.
            config["generator"]["openai"] 아래의 설정을 사용합니다.
    system_prompt: LLM의 system role 메시지로 전달할 페르소나/방어 지시문.
                   None이면 system 메시지 없이 동작합니다.

  Returns:
    OpenAIGenerator: OpenAI 기반 텍스트 생성 컴포넌트

  Raises:
    ValueError: OPENAI_API_KEY 환경변수가 설정되지 않았을 때

  설정 예시 (config/default.yaml):
    generator:
      system_prompt: "민감한 개인정보는 절대 응답에 포함하지 마세요."
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

  # system_prompt가 없으면 파라미터 자체를 전달하지 않음 (Haystack 기본 동작 유지)
  extra_kwargs: dict[str, Any] = {}
  if system_prompt:
    extra_kwargs["system_prompt"] = system_prompt

  generator = OpenAIGenerator(
    model=model,
    generation_kwargs={
      "temperature": temperature,
      "max_tokens": max_tokens,
    },
    **extra_kwargs,
  )

  logger.debug(
    "OpenAI Generator 생성 완료 (모델: {}, temperature: {}, system_prompt={})",
    model,
    temperature,
    "있음" if system_prompt else "없음",
  )
  return generator


@component
class ClovaXGenerator:
  """
  네이버 ClovaStudio 의 HyperCLOVA X 모델을 호출하는 Haystack 컴포넌트입니다.

  사양: 생성기(국내) HyperCLOVA X HCX-DASH-002.
  ClovaStudio Chat Completions 엔드포인트(testapp/v1 또는 v3 호환)로 POST 요청을
  보내고, 응답에서 assistant 메시지 내용을 추출해 OpenAIGenerator 와 동일한
  ``{"replies": [...], "meta": [...]}`` 형식으로 반환합니다.

  HTTP 호출은 ``http_client`` 매개변수로 주입할 수 있어 단위 테스트에서 mock 으로
  손쉽게 교체됩니다(아무 인자도 주지 않으면 표준 ``requests`` 라이브러리 사용).
  """

  def __init__(
    self,
    api_key: str,
    *,
    model: str = "HCX-DASH-002",
    api_url: str = "https://clovastudio.apigw.ntruss.com",
    temperature: float = 0.1,
    max_tokens: int = 1024,
    top_p: float = 0.8,
    timeout: float = 30.0,
    system_prompt: str | None = None,
    http_client: Any | None = None,
  ) -> None:
    self.api_key = api_key
    self.model = model
    self.api_url = api_url.rstrip("/")
    self.temperature = float(temperature)
    self.max_tokens = int(max_tokens)
    self.top_p = float(top_p)
    self.timeout = float(timeout)
    self.system_prompt = system_prompt or None
    self._http_client = http_client

  def _resolve_endpoint(self) -> str:
    """베이스 URL 에서 chat-completions 엔드포인트 경로를 구성합니다.

    ClovaStudio 게이트웨이는 testapp/v1 과 v3 두 가지 경로를 모두 지원합니다.
    `api_url` 에 이미 chat-completions 가 포함되어 있으면 그대로 사용합니다.
    """
    if "chat-completions" in self.api_url:
      return self.api_url
    return f"{self.api_url}/testapp/v1/chat-completions/{self.model}"

  def _post(self, url: str, headers: dict[str, str], body: dict[str, Any]) -> Any:
    if self._http_client is not None:
      return self._http_client.post(url, headers=headers, json=body, timeout=self.timeout)
    import requests  # 지연 import: 테스트 환경에서 의존성 회피

    return requests.post(url, headers=headers, json=body, timeout=self.timeout)

  @staticmethod
  def _extract_reply(payload: dict[str, Any]) -> str:
    """ClovaStudio 응답 payload 에서 assistant 메시지 본문을 추출합니다."""
    result = payload.get("result") or {}
    message = result.get("message") or {}
    content = message.get("content")
    if isinstance(content, str) and content:
      return content
    # v3 또는 변형 포맷 대응
    outputs = result.get("outputText") or payload.get("outputText")
    if isinstance(outputs, str) and outputs:
      return outputs
    return ""

  @component.output_types(replies=list[str], meta=list[dict])
  def run(self, prompt: str) -> dict[str, Any]:
    url = self._resolve_endpoint()
    headers = {
      "Authorization": f"Bearer {self.api_key}",
      "Content-Type": "application/json; charset=utf-8",
      "X-NCP-CLOVASTUDIO-REQUEST-ID": "rag-attack-harness",
    }
    # system_prompt가 있으면 messages 배열 맨 앞에 system 역할로 추가합니다.
    # ClovaStudio는 OpenAI와 동일한 messages 포맷을 지원합니다.
    messages = []
    if self.system_prompt:
      messages.append({"role": "system", "content": self.system_prompt})
    messages.append({"role": "user", "content": prompt})

    body: dict[str, Any] = {
      "messages": messages,
      "temperature": self.temperature,
      "maxTokens": self.max_tokens,
      "topP": self.top_p,
    }

    try:
      response = self._post(url, headers=headers, body=body)
      status = getattr(response, "status_code", 200)
      if status >= 400:
        raw = getattr(response, "text", str(response))
        logger.error("ClovaStudio 호출 실패 status={} body={}", status, raw[:200])
        return {
          "replies": [""],
          "meta": [{"model": self.model, "provider": "clova", "error": f"HTTP {status}"}],
        }
      payload = response.json() if hasattr(response, "json") else {}
      if isinstance(payload, str):
        payload = json.loads(payload)
      reply = self._extract_reply(payload or {})
      meta = {
        "model": self.model,
        "provider": "clova",
        "usage": (payload.get("result", {}) or {}).get("usage", {}),
      }
      return {"replies": [reply], "meta": [meta]}
    except Exception as exc:  # noqa: BLE001 - 외부 API 호출 보호
      logger.error("ClovaStudio 예외: {}", exc)
      return {
        "replies": [""],
        "meta": [{"model": self.model, "provider": "clova", "error": str(exc)}],
      }


@component
class LocalOpenAICompatGenerator:
  """
  로컬 오픈웨이트 모델을 호출하는 Haystack 컴포넌트입니다 (대회 규정 A-1).

  대회 규정상 Closed API 호출(GPT-4o-mini / HCX-DASH-002)은 0건이어야 한다. Ollama ·
  vLLM · LM Studio · llama.cpp server · TGI 등 대부분의 로컬 추론 서버는 **OpenAI 호환
  chat-completions 엔드포인트**(`/v1/chat/completions`)를 노출하므로, base_url 만 로컬
  서버로 두면 이 한 컴포넌트로 어떤 로컬 오픈웨이트 모델(EXAONE · Qwen2.5 · Gemma 등)이든
  붙일 수 있고 외부 API 호출이 전혀 없다.

  ClovaXGenerator 와 동일하게 HTTP 호출을 ``http_client`` 로 주입할 수 있어, 로컬 서버나
  GPU 없이도 요청 구성·응답 파싱을 단위 테스트할 수 있다(주입하지 않으면 requests 사용).

  응답은 OpenAIGenerator 와 동일한 ``{"replies": [...], "meta": [...]}`` 형식으로 반환한다.
  """

  def __init__(
    self,
    *,
    model: str,
    base_url: str = "http://localhost:11434/v1",
    api_key: str = "local",
    temperature: float = 0.1,
    max_tokens: int = 1024,
    top_p: float = 0.8,
    timeout: float = 60.0,
    system_prompt: str | None = None,
    http_client: Any | None = None,
  ) -> None:
    """
    Args:
      model: 로컬 서버에 로드된 모델 이름(예: "qwen2.5", "exaone3.5", "gemma2").
      base_url: OpenAI 호환 베이스 URL. Ollama 기본값은 http://localhost:11434/v1,
                vLLM 은 보통 http://localhost:8000/v1.
      api_key: 로컬 서버는 보통 키를 검사하지 않으므로 임의값("local")이면 충분하다.
      temperature / max_tokens / top_p: 생성 파라미터.
      timeout: 요청 타임아웃(로컬 CPU 추론은 느릴 수 있어 기본 60초).
      system_prompt: system 역할 메시지로 전달할 페르소나/방어 지시문.
      http_client: (테스트용) .post(url, headers=, json=, timeout=) 를 가진 객체.
    """
    self.model = model
    self.base_url = base_url.rstrip("/")
    self.api_key = api_key or "local"
    self.temperature = float(temperature)
    self.max_tokens = int(max_tokens)
    self.top_p = float(top_p)
    self.timeout = float(timeout)
    self.system_prompt = system_prompt or None
    self._http_client = http_client

  def _resolve_endpoint(self) -> str:
    """베이스 URL 에서 chat-completions 엔드포인트 경로를 구성합니다.

    base_url 에 이미 chat/completions 가 포함되어 있으면 그대로 사용한다.
    """
    if "chat/completions" in self.base_url:
      return self.base_url
    return f"{self.base_url}/chat/completions"

  def _post(self, url: str, headers: dict[str, str], body: dict[str, Any]) -> Any:
    if self._http_client is not None:
      return self._http_client.post(url, headers=headers, json=body, timeout=self.timeout)
    import requests  # 지연 import: 테스트 환경에서 의존성 회피

    return requests.post(url, headers=headers, json=body, timeout=self.timeout)

  @staticmethod
  def _extract_reply(payload: dict[str, Any]) -> str:
    """OpenAI 호환 응답 payload 에서 assistant 메시지 본문을 추출합니다."""
    choices = payload.get("choices") or []
    if choices:
      message = choices[0].get("message") or {}
      content = message.get("content")
      if isinstance(content, str) and content:
        return content
      # 일부 서버는 completions 스타일 text 필드를 쓴다.
      text = choices[0].get("text")
      if isinstance(text, str) and text:
        return text
    return ""

  @component.output_types(replies=list[str], meta=list[dict])
  def run(self, prompt: str) -> dict[str, Any]:
    url = self._resolve_endpoint()
    headers = {
      "Authorization": f"Bearer {self.api_key}",
      "Content-Type": "application/json",
    }
    messages: list[dict[str, str]] = []
    if self.system_prompt:
      messages.append({"role": "system", "content": self.system_prompt})
    messages.append({"role": "user", "content": prompt})

    body: dict[str, Any] = {
      "model": self.model,
      "messages": messages,
      "temperature": self.temperature,
      "max_tokens": self.max_tokens,
      "top_p": self.top_p,
      "stream": False,
    }

    try:
      response = self._post(url, headers=headers, body=body)
      status = getattr(response, "status_code", 200)
      if status >= 400:
        raw = getattr(response, "text", str(response))
        logger.error("로컬 LLM 호출 실패 status={} body={}", status, raw[:200])
        return {
          "replies": [""],
          "meta": [{"model": self.model, "provider": "local", "error": f"HTTP {status}"}],
        }
      payload = response.json() if hasattr(response, "json") else {}
      if isinstance(payload, str):
        payload = json.loads(payload)
      reply = self._extract_reply(payload or {})
      meta = {
        "model": self.model,
        "provider": "local",
        "base_url": self.base_url,
        "usage": (payload or {}).get("usage", {}),
      }
      return {"replies": [reply], "meta": [meta]}
    except Exception as exc:  # noqa: BLE001 - 외부/로컬 호출 보호
      logger.error("로컬 LLM 예외: {}", exc)
      return {
        "replies": [""],
        "meta": [{"model": self.model, "provider": "local", "error": str(exc)}],
      }


def create_local_generator(
  config: dict[str, Any],
  *,
  system_prompt: str | None = None,
) -> Any:
  """
  로컬 오픈웨이트 모델(OpenAI 호환 엔드포인트) 기반 Generator 를 생성합니다 (A-1).

  Closed API 키가 필요 없다(로컬 서버 호출). 서버 주소는 환경변수 ``LOCAL_LLM_BASE_URL``
  또는 ``config["generator"]["local"]["base_url"]`` 로 지정한다. 서버가 떠 있지 않으면
  생성 자체는 성공하고, run() 호출 시점에 오류 메타로 안전하게 처리된다(ClovaX 와 동일).

  Args:
    config: YAML 설정 딕셔너리. ``config["generator"]["local"]`` 아래 값을 사용.
    system_prompt: system 메시지로 전달할 페르소나/방어 지시문.

  Returns:
    LocalOpenAICompatGenerator: 로컬 모델 호출 컴포넌트.

  설정 예시 (config/default.yaml):
    generator:
      provider: "local"
      local:
        base_url: "http://localhost:11434/v1"   # Ollama 기본
        model: "qwen2.5"
        temperature: 0.1
        max_tokens: 1024
  """
  gen_config = (config.get("generator", {}) or {}).get("local", {}) or {}
  base_url = os.getenv("LOCAL_LLM_BASE_URL") or gen_config.get(
    "base_url", "http://localhost:11434/v1"
  )
  api_key = os.getenv("LOCAL_LLM_API_KEY") or gen_config.get("api_key", "local")
  model = gen_config.get("model", "qwen2.5")
  temperature = gen_config.get("temperature", 0.1)
  max_tokens = gen_config.get("max_tokens", 1024)
  top_p = gen_config.get("top_p", 0.8)
  timeout = gen_config.get("timeout", 60.0)

  generator = LocalOpenAICompatGenerator(
    model=model,
    base_url=base_url,
    api_key=api_key,
    temperature=temperature,
    max_tokens=max_tokens,
    top_p=top_p,
    timeout=timeout,
    system_prompt=system_prompt,
  )

  logger.debug(
    "로컬 Generator 생성 완료 (모델: {}, base_url: {}, system_prompt={})",
    model,
    base_url,
    "있음" if system_prompt else "없음",
  )
  return generator


def create_clova_generator(
  config: dict[str, Any],
  *,
  system_prompt: str | None = None,
) -> Any:
  """
  HyperCLOVA X(HCX-DASH-002) 기반 Generator 를 생성합니다.

  환경변수 ``NAVER_CLOVA_API_KEY`` 가 반드시 설정되어 있어야 합니다.
  ``NAVER_CLOVA_API_URL`` 은 옵션이며, 미설정 시 기본 ClovaStudio 게이트웨이를 사용합니다.

  Args:
    config: YAML 에서 로드한 설정 딕셔너리. ``config["generator"]["clova"]``
            아래의 model/temperature/max_tokens 값을 사용합니다.
    system_prompt: LLM의 system 메시지로 전달할 페르소나/방어 지시문.
                   None이면 system 메시지 없이 동작합니다.

  Returns:
    ClovaXGenerator: HyperCLOVA X 호출 컴포넌트.

  Raises:
    ValueError: NAVER_CLOVA_API_KEY 환경변수가 설정되지 않았을 때.
  """
  api_key = os.getenv("NAVER_CLOVA_API_KEY")
  if not api_key:
    raise ValueError(
      "NAVER_CLOVA_API_KEY 환경변수가 설정되지 않았습니다. "
      ".env 파일에 NAVER_CLOVA_API_KEY=... 형태로 설정해주세요."
    )

  api_url = os.getenv("NAVER_CLOVA_API_URL", "https://clovastudio.apigw.ntruss.com")
  gen_config = (config.get("generator", {}) or {}).get("clova", {}) or {}
  model = gen_config.get("model", "HCX-DASH-002")
  temperature = gen_config.get("temperature", 0.1)
  max_tokens = gen_config.get("max_tokens", 1024)
  top_p = gen_config.get("top_p", 0.8)

  generator = ClovaXGenerator(
    api_key=api_key,
    model=model,
    api_url=api_url,
    temperature=temperature,
    max_tokens=max_tokens,
    top_p=top_p,
    system_prompt=system_prompt,
  )

  logger.debug(
    "ClovaX Generator 생성 완료 (모델: {}, temperature: {}, url: {}, system_prompt={})",
    model,
    temperature,
    api_url,
    "있음" if system_prompt else "없음",
  )
  return generator
