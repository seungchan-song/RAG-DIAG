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

주의: 엔드포인트 경로·필드명은 대상 RAG 버전마다 다를 수 있다. 실제 연동 전 대상의
`/api/docs` 스키마와 대조해 config 로 맞춰야 한다(기본값은 출발점일 뿐이다).
"""

from __future__ import annotations

from typing import Any, Callable

from loguru import logger

from rag.adapters.base import Capability, RagTrace
from rag.adapters.registry import AdapterConfigError, register_adapter

# transport 콜러블 계약: (url, json_payload, headers) -> 응답 dict.
Transport = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]

# REST RAG 가 노출할 수 있는 native(최대) 능력. INDEX_REBUILD 는 없음(라이브 인덱스
# 반사실 불가) → R4 자동 skip. 운영자는 config.adapter.capabilities 로 더 좁힐 수 있다.
REST_NATIVE_CAPABILITIES: set[Capability] = {
  Capability.QUERY,
  Capability.RETRIEVAL_TRACE,
  Capability.DOC_LABELS,
  Capability.SYSTEM_PROMPT,
  Capability.INDEX_WRITE,
}


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

  # 이 어댑터 인스턴스가 노출하는 능력. 레지스트리 native 와 동일(게이팅은 상위에서).
  capabilities: set[Capability] = set(REST_NATIVE_CAPABILITIES)

  def __init__(
    self,
    *,
    base_url: str,
    workspace: str = "",
    api_key: str = "",
    chat_path: str = "/api/v1/workspace/{workspace}/chat",
    upload_path: str = "/api/v1/document/upload",
    answer_field: str = "textResponse",
    sources_field: str = "sources",
    source_content_field: str = "text",
    source_score_field: str = "score",
    system_prompt: str | None = None,
    transport: Transport | None = None,
    timeout: float = 30.0,
  ) -> None:
    """
    RestRagAdapter 를 초기화합니다.

    Args:
      base_url: 대상 RAG 의 기본 URL(예: "http://localhost:3001").
      workspace: chat_path 의 {workspace} 자리에 치환될 워크스페이스 식별자.
      api_key: Bearer 토큰(있으면 Authorization 헤더에 실린다).
      chat_path / upload_path: 질의·업로드 엔드포인트 경로.
      answer_field / sources_field / source_content_field / source_score_field:
        응답 JSON 에서 답변·검색원문 목록·원문 내용·점수를 꺼낼 필드 경로(점 표기 지원).
      system_prompt: R7 평가 정답으로 쓸, 대상에 설정된 방어 프롬프트 원문.
      transport: (url, payload, headers) -> dict 콜러블. None 이면 requests 사용.
      timeout: 기본 transport 의 요청 타임아웃(초).
    """
    self.base_url = base_url.rstrip("/")
    self.workspace = workspace
    self.api_key = api_key
    self.chat_path = chat_path
    self.upload_path = upload_path
    self.answer_field = answer_field
    self.sources_field = sources_field
    self.source_content_field = source_content_field
    self.source_score_field = source_score_field
    self.system_prompt = system_prompt
    self.transport = transport
    self.timeout = timeout
    self._declared_sensitive: set[str] = set()

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

    return cls(
      base_url=str(base_url),
      workspace=str(adapter_cfg.get("workspace", "")),
      api_key=str(adapter_cfg.get("api_key", "")),
      chat_path=str(adapter_cfg.get("chat_path", "/api/v1/workspace/{workspace}/chat")),
      upload_path=str(adapter_cfg.get("upload_path", "/api/v1/document/upload")),
      answer_field=str(adapter_cfg.get("answer_field", "textResponse")),
      sources_field=str(adapter_cfg.get("sources_field", "sources")),
      source_content_field=str(adapter_cfg.get("source_content_field", "text")),
      source_score_field=str(adapter_cfg.get("source_score_field", "score")),
      system_prompt=adapter_cfg.get("system_prompt"),
      timeout=float(adapter_cfg.get("timeout", 30.0)),
    )

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
    대상 RAG 에 문서를 업로드합니다(R9 poison 주입).

    업로드 스키마는 백엔드마다 다르므로 여기서는 JSON {name, content} 로 단순화한다.
    multipart 등 다른 방식이 필요하면 transport 를 교체하거나 이 메서드를 재정의한다.

    Returns:
      int: 업로드를 시도한 문서 수.
    """
    count = 0
    for index, doc in enumerate(documents):
      if isinstance(doc, dict):
        content = str(doc.get("content", "") or "")
        name = str(doc.get("doc_id") or doc.get("id") or f"poison-{index}")
      else:
        content = str(getattr(doc, "content", "") or "")
        name = str(getattr(doc, "id", "") or f"poison-{index}")
      self._post(self.upload_path, {"name": name, "content": content})
      count += 1
    logger.info("RestRagAdapter: 문서 {}건 업로드", count)
    return count


# 레지스트리에 "rest" 타입 등록. __init__.py 가 이 모듈을 import 하면 등록이 실행된다.
register_adapter(
  "rest",
  lambda config, pipeline: RestRagAdapter.from_config(config),
  REST_NATIVE_CAPABILITIES,
)
