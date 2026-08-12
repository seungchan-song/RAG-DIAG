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
    raw_text_path: str = "/api/v1/document/raw-text",
    update_embeddings_path: str = "/api/v1/workspace/{workspace}/update-embeddings",
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
      workspace: chat_path/update_embeddings_path 의 {workspace} 자리에 치환될 워크스페이스 식별자.
      api_key: Bearer 토큰(있으면 Authorization 헤더에 실린다).
      chat_path: 질의 엔드포인트 경로.
      raw_text_path: R9 poison 텍스트 업로드 엔드포인트(1단계).
      update_embeddings_path: 업로드한 문서를 워크스페이스 검색 대상에 실제로
        편입시키는 엔드포인트(2단계) — 이걸 안 부르면 문서가 존재만 하고 검색되지 않는다.
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
    self.raw_text_path = raw_text_path
    self.update_embeddings_path = update_embeddings_path
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
      raw_text_path=str(adapter_cfg.get("raw_text_path", "/api/v1/document/raw-text")),
      update_embeddings_path=str(
        adapter_cfg.get(
          "update_embeddings_path", "/api/v1/workspace/{workspace}/update-embeddings"
        )
      ),
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


# 레지스트리에 "rest" 타입 등록. __init__.py 가 이 모듈을 import 하면 등록이 실행된다.
register_adapter(
  "rest",
  lambda config, pipeline: RestRagAdapter.from_config(config),
  REST_NATIVE_CAPABILITIES,
)
