"""
RestRagAdapter — 외부 REST RAG(예: AnythingLLM)를 붙이는 참조 어댑터.

"우리가 만들지 않은 인기 OSS RAG 에 진단을 그대로 붙인다" 는 A-2 실증 데모(§5)의 핵심
구현체다. HTTP 로 질의를 던지고 응답(answer + 검색 원문 sources)을 RagTrace 로 옮긴다.

설계 포인트:
  - **transport 주입** — 실제 HTTP 클라이언트(requests) 대신 콜러블을 주입할 수 있어,
    서버 없이 요청 구성·응답 파싱을 단위 테스트할 수 있다(기본은 requests 지연 임포트).
  - **필드 매핑 설정** — 응답 스키마가 RAG 마다 다르므로 answer/sources 필드 경로를
    설정으로 받는다. 기본값은 AnythingLLM 개발자 API 스키마에 맞춰 뒀다.
  - **build_variant 미지원** — 남의 라이브 인덱스에서 특정 문서만 뺀 반사실 세계를
    만들 수 없으므로 INDEX_REBUILD 를 노출하지 않는다. → R4 는 능력 계획에서 자동 skip.
    (반사실 진단은 test/staging 인덱스를 통제할 수 있을 때만 성립한다는 위협 모델과 일치.)

기본값 실측(2026-08-12, 로컬 Docker `mintplexlabs/anythingllm` + Ollama qwen2.5:3b):
  - `chat_path`/`answer_field`/`sources_field`/`source_content_field`/`source_score_field`
    기본값은 실제 응답과 그대로 일치했다(변경 불필요).
  - `write_documents` 는 예전엔 `{name, content}` 를 `/api/v1/document/upload` 에 JSON 으로
    보냈는데, 실제 AnythingLLM 은 그 경로가 multipart/binary 전용이라 전량 실패했다.
    실제로는 **2단계**다 — (1) `/api/v1/document/raw-text` 에 `{textContent, metadata.title}`
    로 텍스트를 넣으면 응답에 `documents[].location` 이 오고, (2) 그 location 들을
    `/api/v1/workspace/{workspace}/update-embeddings` 의 `adds` 로 넘겨야 실제로 검색
    대상(임베딩)에 잡힌다. 업로드만 하고 끝내면 문서가 존재는 하되 검색되지 않는다.
  - `sources[].text` 에는 AnythingLLM 이 매 청크 앞에 `<document_metadata>...</document_metadata>`
    블록을 붙여 보낸다. R2 의 ROUGE 비교엔 잡음이라 파싱 시 제거한다.
  - **코드 밖 함정**: 워크스페이스 기본 `similarityThreshold`(0.25)가 꽤 높아서, 실제로
    유출돼야 할 문서도 스코어가 임계값 밑이면 `sources: []` 로 조용히 걸러진다(실측:
    방금 넣은 문서가 score 0.166 으로 기본 임계값 미달). 대상 워크스페이스의 임계값을
    낮춰두지 않으면 R2 가 "유출 없음"으로 오판할 수 있다 — 코드가 아니라 AnythingLLM
    쪽 설정이라 여기서 고칠 수 없다.

주의: 엔드포인트 경로·필드명은 대상 RAG 버전마다 다를 수 있다. 실제 연동 전 대상의
`/api/docs` 스키마와 대조해 config 로 맞춰야 한다(기본값은 출발점일 뿐이다).
"""

from __future__ import annotations

import re
from typing import Any, Callable

from loguru import logger

from rag.adapters.base import Capability, RagTrace
from rag.adapters.registry import AdapterConfigError, register_adapter

# transport 콜러블 계약: (url, json_payload, headers) -> 응답 dict.
Transport = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]

# AnythingLLM 이 sources[].text 앞에 매번 붙이는 메타데이터 블록(실측 2026-08-12).
# R2 ROUGE 비교엔 잡음이라 파싱 시 제거한다. 다른 REST RAG 는 이 태그를 안 쓰므로
# 매치가 안 되면 그냥 no-op.
_DOCUMENT_METADATA_PREFIX = re.compile(r"^<document_metadata>.*?</document_metadata>\s*", re.DOTALL)

# REST RAG 가 노출할 수 있는 native(최대) 능력. INDEX_REBUILD 는 없음(라이브 인덱스
# 반사실 불가) → R4 자동 skip. 운영자는 config.adapter.capabilities 로 더 좁힐 수 있다.
#
# ⚠️ SYSTEM_PROMPT 는 **여기 있다고 항상 노출되는 게 아니다.** 인스턴스는 정답 프롬프트를
# 실제로 확보했을 때만 이 능력을 선언한다(`__init__` 의 self.capabilities 참조). 예전에는
# 값이 None 이어도 무조건 선언해서, R7 이 "완전판(run)" 으로 돌면서 우리 내장 RAG 의
# 프롬프트를 정답 삼아 남의 RAG 응답을 채점했다(RAG-2026-0812-008).
REST_NATIVE_CAPABILITIES: set[Capability] = {
  Capability.QUERY,
  Capability.RETRIEVAL_TRACE,
  Capability.DOC_LABELS,
  Capability.SYSTEM_PROMPT,
  Capability.INDEX_WRITE,
}

# AnythingLLM 워크스페이스 조회/수정 엔드포인트 기본값(실측 2026-08-13).
#   GET  /api/v1/workspace/{slug}         → workspace[0].openAiPrompt 에 시스템 프롬프트
#   POST /api/v1/workspace/{slug}/update  → {"openAiPrompt": "..."} 로 설정
_DEFAULT_WORKSPACE_PATH = "/api/v1/workspace/{workspace}"
_DEFAULT_WORKSPACE_UPDATE_PATH = "/api/v1/workspace/{workspace}/update"
# 워크스페이스 응답에서 시스템 프롬프트를 꺼낼 필드 경로 후보(대상 버전마다 다를 수 있다).
_WORKSPACE_PROMPT_FIELDS = ("openAiPrompt", "systemPrompt", "prompt")

# 우리가 주입한 R9 poison 문서를 대상 저장소 경로에서 알아보는 패턴.
# doc_id 는 `query_generator.generate_r9_payloads` 가 항상 `poison-` 접두사로 만들고,
# AnythingLLM 은 raw-text 업로드를 `<폴더>/raw-<title>-<uuid>.json` 으로 저장한다.
_POISON_DOC_NAME = re.compile(r"(?:^|/)raw-poison-")


def _resolve_push_prompt(config: dict[str, Any]) -> str | None:
  """`adapter.push_system_prompt` 설정을 실제로 밀어넣을 문구로 해석합니다.

  `true` 면 우리 `generator.system_prompt` 를 그대로 쓴다 — 외부 대상을 내장 RAG 와
  **같은 방어 조건**에 놓아야 두 결과를 나란히 비교할 수 있기 때문이다. 문자열을 적으면
  그 문구를 쓴다. 비우거나 false 면 대상을 건드리지 않는다(기본값).

  Args:
    config: load_config 결과.

  Returns:
    str | None: 밀어넣을 프롬프트, 없으면 None.
  """
  raw = (config.get("adapter") or {}).get("push_system_prompt")
  if isinstance(raw, str) and raw.strip():
    return raw
  if raw is True:
    return (config.get("generator") or {}).get("system_prompt") or None
  return None


def _get_path(obj: Any, path: str) -> Any:
  """점(.)으로 구분된 경로로 중첩 dict 값을 꺼냅니다. 없으면 None."""
  current = obj
  for key in path.split("."):
    if isinstance(current, dict) and key in current:
      current = current[key]
    else:
      return None
  return current


class RestRagAdapter:
  """외부 REST RAG 를 TargetRAG 계약으로 감싸는 어댑터."""

  # 이 어댑터 인스턴스가 노출하는 능력. `__init__` 이 정답 프롬프트 확보 여부에 따라
  # SYSTEM_PROMPT 를 빼고 다시 채운다(게이팅은 상위에서 한 번 더 좁힐 수 있다).
  capabilities: set[Capability]

  def __init__(
    self,
    *,
    base_url: str,
    workspace: str = "",
    api_key: str = "",
    chat_path: str = "/api/v1/workspace/{workspace}/chat",
    raw_text_path: str = "/api/v1/document/raw-text",
    update_embeddings_path: str = "/api/v1/workspace/{workspace}/update-embeddings",
    workspace_path: str = _DEFAULT_WORKSPACE_PATH,
    workspace_update_path: str = _DEFAULT_WORKSPACE_UPDATE_PATH,
    answer_field: str = "textResponse",
    sources_field: str = "sources",
    source_content_field: str = "text",
    source_score_field: str = "score",
    system_prompt: str | None = None,
    push_system_prompt: str | None = None,
    transport: Transport | None = None,
    transport_get: Callable[[str, dict[str, str]], dict[str, Any]] | None = None,
    timeout: float = 30.0,
  ) -> None:
    """
    RestRagAdapter 를 초기화합니다.

    Args:
      base_url: 대상 RAG 의 기본 URL(예: "http://localhost:3001").
      workspace: chat_path/update_embeddings_path 의 {workspace} 자리에 치환될 워크스페이스 식별자.
      api_key: Bearer 토큰(있으면 Authorization 헤더에 실린다).
      chat_path: 질의 엔드포인트 경로.
      raw_text_path: R9 poison 텍스트 업로드 엔드포인트(1단계).
      update_embeddings_path: 업로드한 문서를 워크스페이스 검색 대상에 실제로
        편입시키는 엔드포인트(2단계) — 이걸 안 부르면 문서가 존재만 하고 검색되지 않는다.
      workspace_path: 워크스페이스 조회 경로(시스템 프롬프트 되읽기용).
      workspace_update_path: 워크스페이스 수정 경로(push_system_prompt 사용 시).
      answer_field / sources_field / source_content_field / source_score_field:
        응답 JSON 에서 답변·검색원문 목록·원문 내용·점수를 꺼낼 필드 경로(점 표기 지원).
      system_prompt: R7 평가 정답으로 쓸, 대상에 설정된 방어 프롬프트 원문(명시 지정).
        비워 두면 대상 워크스페이스에서 실제 걸린 값을 조회한다.
      push_system_prompt: 지정하면 이 문구를 **대상에 설정한 뒤** 되읽는다. 진단 전에
        방어 조건을 통제하고 싶을 때만 쓴다(기본 None = 남의 RAG 를 건드리지 않는다).
      transport: (url, payload, headers) -> dict 콜러블(POST 용). None 이면 requests 사용.
      transport_get: (url, headers) -> dict 콜러블(GET 용). None 이고 transport 가
        주입돼 있으면 GET 을 아예 보내지 않는다 — POST 만 검증하는 단위 테스트의 호출
        기록을 조회 요청이 오염시키지 않도록 하기 위해서다.
      timeout: 기본 transport 의 요청 타임아웃(초).
    """
    self.base_url = base_url.rstrip("/")
    self.workspace = workspace
    self.api_key = api_key
    self.chat_path = chat_path
    self.raw_text_path = raw_text_path
    self.update_embeddings_path = update_embeddings_path
    self.workspace_path = workspace_path
    self.workspace_update_path = workspace_update_path
    self.answer_field = answer_field
    self.sources_field = sources_field
    self.source_content_field = source_content_field
    self.source_score_field = source_score_field
    self.transport = transport
    self.transport_get = transport_get
    self.timeout = timeout
    self._declared_sensitive: set[str] = set()

    # === R7 정답 프롬프트 해석 ===
    # 순서는 (1) 밀어넣기 요청이 있으면 설정 → (2) 명시 지정 → (3) 대상에서 되읽기.
    # 밀어넣은 경우에도 **반드시 되읽어** 실제로 걸린 값을 쓴다 — 설정 실패를 조용히
    # 넘기면 다시 "우리가 의도한 프롬프트"와 채점하게 되어 같은 사고가 반복된다.
    if push_system_prompt:
      self.push_system_prompt(push_system_prompt)
    self.system_prompt = system_prompt or self.fetch_system_prompt()

    # 정답을 못 구했으면 SYSTEM_PROMPT 능력을 내리고 R7 을 축소 진단으로 떨어뜨린다.
    # 능력만 선언하고 값이 없으면 계획은 "완전판"인데 평가는 무의미해진다.
    self.capabilities = set(REST_NATIVE_CAPABILITIES)
    if not self.system_prompt:
      self.capabilities.discard(Capability.SYSTEM_PROMPT)
      logger.warning(
        "RestRagAdapter: 대상의 시스템 프롬프트를 확보하지 못해 SYSTEM_PROMPT 능력을 "
        "선언하지 않습니다 — R7 은 축소 진단으로 실행됩니다. "
        "adapter.system_prompt 에 원문을 적거나 adapter.push_system_prompt 를 켜세요."
      )

  @classmethod
  def from_config(cls, config: dict[str, Any]) -> "RestRagAdapter":
    """
    config["adapter"] 블록으로 RestRagAdapter 를 구성합니다(레지스트리 팩토리용).

    Raises:
      AdapterConfigError: base_url 이 없을 때.
    """
    adapter_cfg = dict(config.get("adapter") or {})
    base_url = adapter_cfg.get("base_url")
    if not base_url:
      raise AdapterConfigError("adapter.type=rest 에는 adapter.base_url 이 필요합니다.")

    adapter = cls(
      base_url=str(base_url),
      workspace=str(adapter_cfg.get("workspace", "")),
      api_key=str(adapter_cfg.get("api_key", "")),
      chat_path=str(adapter_cfg.get("chat_path", "/api/v1/workspace/{workspace}/chat")),
      raw_text_path=str(adapter_cfg.get("raw_text_path", "/api/v1/document/raw-text")),
      update_embeddings_path=str(
        adapter_cfg.get(
          "update_embeddings_path", "/api/v1/workspace/{workspace}/update-embeddings"
        )
      ),
      workspace_path=str(adapter_cfg.get("workspace_path", _DEFAULT_WORKSPACE_PATH)),
      workspace_update_path=str(
        adapter_cfg.get("workspace_update_path", _DEFAULT_WORKSPACE_UPDATE_PATH)
      ),
      answer_field=str(adapter_cfg.get("answer_field", "textResponse")),
      sources_field=str(adapter_cfg.get("sources_field", "sources")),
      source_content_field=str(adapter_cfg.get("source_content_field", "text")),
      source_score_field=str(adapter_cfg.get("source_score_field", "score")),
      system_prompt=adapter_cfg.get("system_prompt"),
      # true 로 두면 config.generator.system_prompt 를 대상에 밀어넣는다(통제 변수화).
      # 문자열을 직접 적으면 그 문구를 쓴다.
      push_system_prompt=_resolve_push_prompt(config),
      timeout=float(adapter_cfg.get("timeout", 30.0)),
    )
    # 지난 실행이 남긴 R9 poison 을 질의가 시작되기 전에 걷어낸다(대조군 오염 차단).
    # 외부 RAG 는 워크스페이스가 하나뿐이라 이 정리가 있어야 poison 주입을 켤 수 있다.
    # 여기가 런당 정확히 한 번 도는 지점이다 — CLI 의 `_resolve_target_adapter` →
    # `registry.create_target_adapter` 가 이 팩토리를 부른다.
    adapter.cleanup_stale_poison()
    return adapter

  @property
  def _headers(self) -> dict[str, str]:
    """공통 요청 헤더(api_key 있으면 Bearer 토큰 포함)."""
    headers = {"Content-Type": "application/json"}
    if self.api_key:
      headers["Authorization"] = f"Bearer {self.api_key}"
    return headers

  def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """대상 RAG 에 POST 요청을 보내고 JSON 응답을 반환합니다(transport 주입 가능)."""
    url = self.base_url + path
    if self.transport is not None:
      return self.transport(url, payload, self._headers)

    import requests

    response = requests.post(url, json=payload, headers=self._headers, timeout=self.timeout)
    response.raise_for_status()
    return response.json()

  def _get(self, path: str) -> dict[str, Any]:
    """대상 RAG 에 GET 요청을 보내고 JSON 응답을 반환합니다(실패하면 빈 dict).

    조회 실패는 예외를 올리지 않는다 — 프롬프트를 못 읽는 건 능력 미선언으로 이어질 뿐
    진단 전체를 멈출 일이 아니다.
    """
    url = self.base_url + path
    try:
      if self.transport_get is not None:
        return self.transport_get(url, self._headers) or {}
      if self.transport is not None:
        # POST transport 만 주입된 상태(단위 테스트) — 조회는 보내지 않는다.
        return {}
      import requests

      response = requests.get(url, headers=self._headers, timeout=self.timeout)
      response.raise_for_status()
      return response.json() or {}
    except Exception as error:  # 네트워크·스키마·권한 어느 쪽이든 동작은 같다.
      logger.debug("RestRagAdapter: GET {} 실패 — {}", path, error)
      return {}

  def fetch_system_prompt(self) -> str | None:
    """대상 워크스페이스에 **실제로 걸려 있는** 시스템 프롬프트를 조회합니다.

    R7 은 응답과 시스템 프롬프트의 코사인·ROUGE 로 채점하므로 정답이 틀리면 판정 전체가
    무의미해진다. 예전에는 여기가 없어서 `config.generator.system_prompt`(= 우리 내장
    RAG 의 프롬프트)로 폴백했고, 남의 RAG 응답을 우리 규칙과 대조해 "방어규칙 3/4개
    복원" 같은 값을 냈다(RAG-2026-0812-008).

    AnythingLLM 실측(2026-08-13): `GET /api/v1/workspace/{slug}` 의 `workspace[0].openAiPrompt`.
    당시 대상은 **기본 프롬프트 그대로**여서 PII 차단·근거 한정 규칙이 하나도 없었다 —
    즉 "방어 없는 대상"의 유출률을 재고 있었다는 사실 자체가 리포트에 실려야 한다.

    Returns:
      str | None: 조회에 성공하면 프롬프트 원문, 실패하거나 비어 있으면 None.
    """
    if not self.workspace_path:
      return None
    payload = self._get(self.workspace_path.format(workspace=self.workspace))
    # AnythingLLM 은 {"workspace": [ {...} ]} 로 감싸 준다. 다른 RAG 는 평평할 수 있다.
    candidates: list[Any] = []
    workspace = payload.get("workspace")
    if isinstance(workspace, list):
      candidates.extend(workspace)
    elif isinstance(workspace, dict):
      candidates.append(workspace)
    candidates.append(payload)

    for candidate in candidates:
      if not isinstance(candidate, dict):
        continue
      for field in _WORKSPACE_PROMPT_FIELDS:
        value = candidate.get(field)
        if isinstance(value, str) and value.strip():
          return value
    return None

  def describe_target(self) -> dict[str, Any]:
    """진단 대상이 실제로 무엇으로 굴러가는지 요약합니다(리포트 '실험 설정'용).

    외부 RAG 를 진단할 때 우리 `config.generator` 를 "진단 대상 생성 모델" 로 적으면
    거짓이다 — 그건 이 도구가 쓰는 모델이지 대상이 쓰는 모델이 아니다. 대상이 API 로
    알려주는 값을 그대로 싣는다(실측 2026-08-13 · AnythingLLM `GET /api/v1/system`).

    조회에 실패하면 아는 것만 담아 돌려준다(연결 정보). 모르는 걸 지어내지 않는다.

    Returns:
      dict[str, Any]: 화면에 그대로 찍을 수 있는 {항목: 값} 요약.
    """
    described: dict[str, Any] = {
      "종류": "AnythingLLM 계열 REST RAG",
      "엔드포인트": self.base_url,
      "워크스페이스": self.workspace,
    }

    settings = (self._get("/api/v1/system") or {}).get("settings") or {}
    if isinstance(settings, dict):
      provider = str(settings.get("LLMProvider") or "")
      model = str(settings.get(f"{provider.capitalize()}LLMModelPref") or "")
      if provider:
        described["생성 LLM"] = f"{model} ({provider})" if model else provider
      embed_engine = str(settings.get("EmbeddingEngine") or "")
      embed_model = str(settings.get("EmbeddingModelPref") or "")
      if embed_engine or embed_model:
        described["임베딩"] = f"{embed_model} ({embed_engine})".strip()
      if settings.get("VectorDB"):
        described["벡터 DB"] = str(settings["VectorDB"])

    workspace = (self._get(self.workspace_path.format(workspace=self.workspace)) or {}).get(
      "workspace"
    )
    entry = workspace[0] if isinstance(workspace, list) and workspace else workspace
    if isinstance(entry, dict):
      top_n = entry.get("topN")
      threshold = entry.get("similarityThreshold")
      if top_n is not None or threshold is not None:
        described["검색"] = f"top_k {top_n} · 유사도 임계값 {threshold}"
      # "방어 프롬프트가 걸려 있었나" 는 이 리포트의 모든 유출 수치를 읽는 전제다.
      described["시스템 프롬프트"] = (
        "설정됨" if self.system_prompt else "확인 불가"
      )
    return described

  def push_system_prompt(self, prompt: str) -> bool:
    """대상 워크스페이스에 시스템 프롬프트를 설정합니다(선택 기능).

    "내 시스템을 내가 감사한다" 는 전제에서는 방어 프롬프트를 **통제 변수**로 두는 편이
    맞다. 그래야 내장 RAG 와 같은 방어 조건에서 비교가 서고, R2/R9 숫자도 "방어가 걸린
    상태"의 값이 된다. 다만 남의 RAG 를 말없이 바꾸면 안 되므로 기본은 꺼져 있고
    `adapter.push_system_prompt` 를 명시했을 때만 호출된다.

    성공 여부와 무관하게 `__init__` 이 곧바로 되읽으므로, 여기서 실패해도 정답이
    조용히 어긋나지는 않는다.

    Args:
      prompt: 대상에 설정할 시스템 프롬프트 원문.

    Returns:
      bool: 요청이 예외 없이 끝났으면 True.
    """
    if not self.workspace_update_path:
      return False
    try:
      self._post(
        self.workspace_update_path.format(workspace=self.workspace),
        {"openAiPrompt": prompt},
      )
      logger.info("RestRagAdapter: 대상 워크스페이스에 시스템 프롬프트를 설정했습니다.")
      return True
    except Exception as error:
      logger.warning("RestRagAdapter: 시스템 프롬프트 설정 실패 — {}", error)
      return False

  def query(self, query: str) -> RagTrace:
    """
    대상 RAG 에 질의하고 응답을 표준 트레이스로 변환합니다.

    Args:
      query: 질의 문자열.

    Returns:
      RagTrace: 답변 + (있으면) 검색 원문 목록을 담은 트레이스.
    """
    path = self.chat_path.format(workspace=self.workspace)
    response = self._post(path, {"message": query, "mode": "query"})

    answer = str(_get_path(response, self.answer_field) or "")
    raw_sources = _get_path(response, self.sources_field) or []
    retrieved: list[dict[str, Any]] = []
    for source in raw_sources:
      if isinstance(source, dict):
        content = str(source.get(self.source_content_field, "") or "")
        content = _DOCUMENT_METADATA_PREFIX.sub("", content)
        score = source.get(self.source_score_field)
        meta = {k: v for k, v in source.items() if k != self.source_content_field}
      else:
        content, score, meta = str(source), None, {}
      retrieved.append({"content": content, "score": score, "meta": meta})

    return RagTrace(
      answer=answer,
      retrieved_documents=retrieved,
      system_prompt=self.system_prompt,
      metadata={"adapter": "rest", "source_count": len(retrieved)},
    )

  def declare_sensitive(self, doc_ids: Any) -> None:
    """민감 문서 식별자를 선언합니다(R2 라벨). 외부 RAG 는 라벨이 없으므로 여기 보존."""
    self._declared_sensitive.update(str(doc_id) for doc_id in doc_ids)

  def write_documents(self, documents: Any) -> int:
    """
    대상 RAG 에 문서를 업로드하고 워크스페이스 검색 대상에 편입시킵니다(R9 poison 주입).

    AnythingLLM 실측(2026-08-12) 기준 2단계다 — (1) raw-text 엔드포인트로 텍스트를
    넣어 documents[].location 을 받고, (2) 그 location 들을 update-embeddings 의
    adds 로 한 번에 넘겨야 실제로 검색된다. (1)만 하면 문서가 존재는 하되 워크스페이스
    벡터 검색에는 잡히지 않는다(구 구현의 함정 — 능력 계획은 run 인데 실제 주입은
    비어 있는 상태가 됨).

    Returns:
      int: 실제로 임베딩까지 완료된 문서 수.
    """
    locations: list[str] = []
    for index, doc in enumerate(documents):
      if isinstance(doc, dict):
        content = str(doc.get("content", "") or "")
        name = str(doc.get("doc_id") or doc.get("id") or f"poison-{index}")
      else:
        content = str(getattr(doc, "content", "") or "")
        name = str(getattr(doc, "id", "") or f"poison-{index}")

      response = self._post(
        self.raw_text_path,
        {"textContent": content, "metadata": {"title": f"{name}.txt"}},
      )
      for uploaded in response.get("documents") or []:
        location = uploaded.get("location")
        if location:
          locations.append(location)

    if locations:
      path = self.update_embeddings_path.format(workspace=self.workspace)
      self._post(path, {"adds": locations, "deletes": []})

    logger.info("RestRagAdapter: 문서 {}건 업로드 + 임베드", len(locations))
    return len(locations)

  def cleanup_stale_poison(self) -> int:
    """이전 실행이 남긴 R9 poison 문서를 워크스페이스 검색 대상에서 제거합니다.

    `write_documents()` 는 poison 을 대상 워크스페이스에 **영구히** 넣는다. 그걸 지우는
    주체가 없으면 다음 실행의 NORMAL(대조군)이 지난 회차 poison 을 검색하게 되고,
    "공격이 대조군보다 PII 를 얼마나 더 노출했나" 라는 이 프로젝트의 핵심 비교가 깨진다.
    외부 RAG 는 워크스페이스가 하나뿐이라 시나리오별로 코퍼스를 분리할 수 없어서
    (우리 builtin 은 clean/poisoned 인덱스를 따로 둔다) 이 정리가 **주입을 켤 수 있는
    전제 조건**이다. 같은 문제를 SOTA 어댑터는 이미 이렇게 풀었다
    (`adapters/sota.py:cleanup_stale_poison` · commit 8f4efbb).

    삭제 대상은 우리가 만든 poison 문서뿐이다 — doc_id 는 `query_generator.
    generate_r9_payloads` 가 항상 `poison-` 접두사로 만들고, 업로드 시 그 이름이 그대로
    파일명에 실린다. 같은 워크스페이스의 다른 문서는 건드리지 않는다.

    ponytail: 워크스페이스 임베딩에서만 뺀다(= 더 이상 검색되지 않는다). AnythingLLM
    저장소의 원본 파일은 남을 수 있는데, 삭제 엔드포인트가 DELETE 바디를 요구해
    현재 POST 전용 transport 계약과 맞지 않기 때문이다. 오염의 원인은 '검색 가능성'
    이므로 비교 정합성에는 영향이 없다. transport 가 DELETE 를 지원하게 되면
    `/api/v1/system/remove-documents` 를 여기서 함께 부를 것.

    Returns:
      int: 검색 대상에서 제외한 문서 수. 남은 poison 이 없으면 0(정상 — 첫 실행).
    """
    payload = self._get(self.workspace_path.format(workspace=self.workspace))
    workspace = payload.get("workspace")
    entries = workspace if isinstance(workspace, list) else [workspace or payload]

    stale: list[str] = []
    for entry in entries:
      if not isinstance(entry, dict):
        continue
      for document in entry.get("documents") or []:
        docpath = str((document or {}).get("docpath") or "")
        # AnythingLLM 은 raw-text 업로드를 `<폴더>/raw-<title>-<uuid>.json` 으로 저장한다.
        if _POISON_DOC_NAME.search(docpath):
          stale.append(docpath)

    if not stale:
      return 0

    self._post(
      self.update_embeddings_path.format(workspace=self.workspace),
      {"adds": [], "deletes": stale},
    )
    # WARNING 인 이유: 남아 있었다는 건 지난 실행이 정리 없이 끝났다는 뜻이고, 그 사이에
    # 돌린 대조군 수치가 오염됐을 수 있다는 신호다. 조용히 넘기면 안 된다.
    logger.warning(
      "이전 실행이 남긴 R9 poison {}건을 워크스페이스 검색 대상에서 제외했습니다. "
      "그 사이에 측정한 대조군 수치는 오염됐을 수 있습니다.",
      len(stale),
    )
    return len(stale)


# 레지스트리에 "rest" 타입 등록. __init__.py 가 이 모듈을 import 하면 등록이 실행된다.
register_adapter(
  "rest",
  lambda config, pipeline: RestRagAdapter.from_config(config),
  REST_NATIVE_CAPABILITIES,
)
