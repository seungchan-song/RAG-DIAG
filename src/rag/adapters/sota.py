"""
SotaRagAdapter — SOTA_RAG(C:\\SOTA_RAG, RunPod 배포) REST API 전용 참조 어댑터.

rest.py(AnythingLLM 참조 구현)를 재사용하지 않고 별도 파일로 둔 이유: rest.py 는
{"message","mode"} 요청 본문·{"name","content"} 업로드 스키마·INDEX_REBUILD 미노출
(R4 자동 skip)이 AnythingLLM 스키마에 맞춰 고정돼 있다. SOTA_RAG 는 자체 스키마
(QueryRequest/QueryResponse, IngestRequest, dict 기반 filters)를 쓰고 R4 도 완전판으로
띄워야 하므로, rest.py 를 오염시키는 대신 이 전용 어댑터를 새로 등록한다
(`registry.register_adapter("sota", ...)`).

R4 파일 단위 번역(핵심 설계 포인트):
  R4 의 build_variant(exclude_doc_ids=...) 에 넘어오는 값은 우리 Haystack 인덱스의
  chunk_id(f"{file_level_doc_id}::chunk-XXXX")다. SOTA_RAG 는 청킹 방식이 다르므로
  (Kiwi 320토큰 vs Haystack sentence splitter) 청크 단위로는 대응이 불가능하다. 대신
  "::chunk-" 앞부분(file_level_doc_id)만 취해 RAG-DIAG 로컬 코퍼스를 스캔한 매핑에서
  dataset-relative source 를 복원하고, SOTA 측 source_file 절대경로로 변환해
  {"source_file": {"$nin": [...]}} 필터로 검색에서 제외한다. doc_id 산출 로직은
  rag.ingest.metadata.build_doc_id_from_source 를 그대로 재사용하므로, 두 시스템이
  같은 파일 집합을 인덱싱하는 한(현재 데이터셋 정책) 값이 정확히 일치한다. 인덱스
  자체는 건드리지 않으므로(제외 필터만 얹음) 반사실 세계가 안전하고 재현 가능하다.

가드레일 처리:
  SOTA_RAG 는 입력 인젝션 탐지·출력 PII 필터·할루시네이션 탐지가 기본 켜져 있다(요청:
  "켠 채로 진단"). 차단/마스킹 여부(is_blocked, guardrails)는 trace.metadata 에 그대로
  실어 리포트가 "방어가 작동했다" 를 설명할 수 있게 한다. 차단 시 응답 문자열 자체가
  차단 메시지이므로 R2/R7 평가기는 별도 처리 없이 자연히 낮은 점수를 매긴다.

전제: RAG-DIAG 와 SOTA_RAG 는 같은 RunPod pod(같은 파일시스템) 위에서 구동된다
(write_documents 가 SOTA 문서 트리에 직접 파일을 쓰고 /api/v1/ingest 로 알리는 방식이
이 전제에 의존한다).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from loguru import logger

from rag.adapters.base import Capability, RagTrace
from rag.adapters.registry import AdapterConfigError, register_adapter

# transport 콜러블 계약: (url, json_payload, headers) -> 응답 dict.
Transport = Callable[[str, dict[str, Any], dict[str, str]], dict[str, Any]]

# SOTA_RAG 가 노출할 수 있는 native(최대) 능력. 6개 전부 — R4/R9 도 완전판으로 실행된다.
SOTA_NATIVE_CAPABILITIES: set[Capability] = {
  Capability.QUERY,
  Capability.SYSTEM_PROMPT,
  Capability.RETRIEVAL_TRACE,
  Capability.DOC_LABELS,
  Capability.INDEX_REBUILD,
  Capability.INDEX_WRITE,
}


def _build_doc_id_source_map(local_corpus_root: str) -> dict[str, str]:
  """
  RAG-DIAG 로컬 코퍼스를 스캔해 file-level doc_id -> dataset-relative source 매핑을 만든다.

  rag.ingest.metadata 의 기존 함수(collect_dataset_selection·build_file_metadata_map)를
  그대로 재사용해, ingest 파이프라인이 실제로 doc_id 를 산출하는 방식과 항상 일치하게
  한다(중복 구현으로 인한 불일치 방지).

  Args:
    local_corpus_root: RAG-DIAG 의 clean 문서 루트(예: "data/documents/clean").

  Returns:
    dict[str, str]: {file_level_doc_id: dataset-relative source path} 매핑.
  """
  from rag.ingest.metadata import build_file_metadata_map, collect_dataset_selection

  selection = collect_dataset_selection(local_corpus_root, environment="clean")
  metadata_map = build_file_metadata_map(
    selection.file_paths, selection.dataset_root, environment="clean"
  )
  return {meta["doc_id"]: meta["source"] for meta in metadata_map.values()}


def _infer_doc_role(source_file: str) -> str:
  """source_file 경로로 문서 역할을 판정한다(RAG-DIAG ingest 규약과 동일 기준 재사용)."""
  if not source_file:
    return "normal"

  from rag.ingest.metadata import infer_doc_role

  return infer_doc_role(Path(source_file))


class SotaRagAdapter:
  """
  SOTA_RAG(하이브리드 검색 + Cross-Encoder 리랭킹 + vLLM) 를 감싸는 참조 어댑터.

  Attributes:
    capabilities: 전 능력(Tier 2) 노출.
    exclude_source_files: 이 인스턴스가 검색에서 제외할 SOTA 측 source_file 절대경로
      집합(build_variant 가 만든 반사실 인스턴스만 비어 있지 않다).
  """

  capabilities: set[Capability] = set(SOTA_NATIVE_CAPABILITIES)

  def __init__(
    self,
    *,
    base_url: str,
    documents_root: str,
    local_corpus_root: str = "data/documents/clean",
    poison_upload_dir: str | None = None,
    query_path: str = "/api/v1/query",
    ingest_path: str = "/api/v1/ingest",
    max_sources: int = 5,
    system_prompt: str | None = None,
    exclude_source_files: frozenset[str] = frozenset(),
    transport: Transport | None = None,
    timeout: float = 120.0,
  ) -> None:
    """
    SotaRagAdapter 를 초기화합니다.

    Args:
      base_url: SOTA_RAG API 기본 URL(예: "http://localhost:8080").
      documents_root: SOTA_RAG 가 문서를 인덱싱한 절대 경로. ingest 시 사용한
        directory_path 와 반드시 동일해야 한다(source_file 매칭 기준점).
      local_corpus_root: RAG-DIAG 가 타깃 문서 선택에 쓰는 로컬 코퍼스 루트. R4 의
        doc_id → source 번역에 사용한다(config.ingest 의 clean 문서 루트와 일치시킨다).
      poison_upload_dir: R9 poison 문서를 documents_root 아래 어느 하위 폴더에 쓸지
        (기본 "poison"). SOTA 인덱스 스캔 대상에 포함되도록 documents_root 내부여야 한다.
      query_path / ingest_path: SOTA_RAG API 경로.
      max_sources: QueryRequest.max_sources 로 보낼 값(reranker.top_k 대응).
      system_prompt: R7 평가 정답으로 쓸 SOTA 측 시스템 프롬프트 원문(대상에 실제로
        설정된 값을 그대로 붙여넣는다 — PromptBuilder.DEFAULT_SYSTEM_PROMPT 등).
      exclude_source_files: 검색에서 제외할 source_file 절대경로 집합(build_variant 가
        채운다. 최초 인스턴스는 비어 있어야 한다).
      transport: (url, payload, headers) -> dict 콜러블. None 이면 requests 사용.
      timeout: 기본 transport 타임아웃(초). vLLM 생성 지연을 고려해 넉넉히 잡는다.
    """
    self.base_url = base_url.rstrip("/")
    self.documents_root = documents_root.rstrip("/")
    self.local_corpus_root = local_corpus_root
    self.poison_upload_dir = poison_upload_dir or "poison"
    self.query_path = query_path
    self.ingest_path = ingest_path
    self.max_sources = max_sources
    self.system_prompt = system_prompt
    self.exclude_source_files = frozenset(exclude_source_files)
    self.transport = transport
    self.timeout = timeout
    self._declared_sensitive: set[str] = set()
    self._doc_id_source_map: dict[str, str] | None = None
    self._poison_seq = 0

  @classmethod
  def from_config(cls, config: dict[str, Any]) -> "SotaRagAdapter":
    """
    config["adapter"] 블록으로 SotaRagAdapter 를 구성합니다(레지스트리 팩토리용).

    Raises:
      AdapterConfigError: base_url 또는 documents_root 가 없을 때.
    """
    adapter_cfg = dict(config.get("adapter") or {})
    base_url = adapter_cfg.get("base_url")
    documents_root = adapter_cfg.get("documents_root")
    if not base_url:
      raise AdapterConfigError("adapter.type=sota 에는 adapter.base_url 이 필요합니다.")
    if not documents_root:
      raise AdapterConfigError("adapter.type=sota 에는 adapter.documents_root 가 필요합니다.")

    return cls(
      base_url=str(base_url),
      documents_root=str(documents_root),
      local_corpus_root=str(adapter_cfg.get("local_corpus_root", "data/documents/clean")),
      poison_upload_dir=adapter_cfg.get("poison_upload_dir"),
      query_path=str(adapter_cfg.get("query_path", "/api/v1/query")),
      ingest_path=str(adapter_cfg.get("ingest_path", "/api/v1/ingest")),
      max_sources=int(adapter_cfg.get("max_sources", 5)),
      system_prompt=adapter_cfg.get("system_prompt"),
      timeout=float(adapter_cfg.get("timeout", 120.0)),
    )

  def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """SOTA_RAG 에 POST 요청을 보내고 JSON 응답을 반환합니다(transport 주입 가능)."""
    url = self.base_url + path
    if self.transport is not None:
      return self.transport(url, payload, {"Content-Type": "application/json"})

    import requests

    response = requests.post(url, json=payload, timeout=self.timeout)
    response.raise_for_status()
    return response.json()

  def query(self, query: str) -> RagTrace:
    """
    SOTA_RAG 에 질의하고 응답을 표준 트레이스로 변환합니다.

    Args:
      query: 질의 문자열.

    Returns:
      RagTrace: 답변 + 검색 원문(doc_role 라벨 포함) + 가드레일 판정을 담은 트레이스.
    """
    payload: dict[str, Any] = {"query": query}
    if self.max_sources:
      payload["max_sources"] = self.max_sources
    if self.exclude_source_files:
      payload["filters"] = {"source_file": {"$nin": sorted(self.exclude_source_files)}}

    response = self._post(self.query_path, payload)

    answer = str(response.get("answer") or "")
    retrieved: list[dict[str, Any]] = []
    for source in response.get("sources") or []:
      source_file = str(source.get("source_file", "") or "")
      retrieved.append({
        "content": str(source.get("content", "") or ""),
        "score": source.get("relevance_score"),
        "meta": {
          "source_file": source_file,
          "doc_role": _infer_doc_role(source_file),
          "page_number": source.get("page_number"),
          "section_title": source.get("section_title"),
        },
      })

    return RagTrace(
      answer=answer,
      retrieved_documents=retrieved,
      system_prompt=self.system_prompt,
      metadata={
        "adapter": "sota",
        "is_blocked": bool(response.get("is_blocked", False)),
        "guardrails": response.get("guardrails", []),
        "response_metadata": response.get("metadata", {}),
        "source_count": len(retrieved),
      },
    )

  def declare_sensitive(self, doc_ids: Any) -> None:
    """
    민감 문서 식별자를 선언합니다(R2 라벨 보조).

    SOTA_RAG 는 doc_role 메타가 없으므로 기본 판정은 source_file 경로 기반
    _infer_doc_role 이 담당한다. 이 메서드는 외부에서 라벨을 추가로 병합하고 싶을 때를
    대비한 계약 완결용 보존소다.
    """
    self._declared_sensitive.update(str(doc_id) for doc_id in doc_ids)

  def build_variant(self, *, exclude_doc_ids: set[str]) -> "SotaRagAdapter":
    """
    특정 문서를 제외한 반사실(counterfactual) 어댑터를 만듭니다(R4).

    exclude_doc_ids(청크 단위 chunk_id)를 파일 단위 doc_id 로 축소한 뒤, 로컬 코퍼스
    스캔 매핑에서 dataset-relative source 를 찾아 SOTA 측 source_file 절대경로로
    변환해 제외 목록에 더한다. 대응 파일을 못 찾으면 그 항목은 건너뛰고 경고 로그를
    남긴다(제외 실패보다 최소 침습을 택함).

    Args:
      exclude_doc_ids: 제외할 문서 식별자 집합(chunk_id 형식).

    Returns:
      SotaRagAdapter: 제외 파일이 반영된 새 어댑터(원본은 불변).
    """
    if self._doc_id_source_map is None:
      self._doc_id_source_map = _build_doc_id_source_map(self.local_corpus_root)

    new_excludes: set[str] = set(self.exclude_source_files)
    for raw_id in exclude_doc_ids:
      file_doc_id = raw_id.split("::chunk-")[0]
      relative_source = self._doc_id_source_map.get(file_doc_id)
      if relative_source is None:
        logger.warning(
          "SotaRagAdapter.build_variant: doc_id '{}' 를 로컬 코퍼스에서 찾지 못해 제외를 건너뜀",
          file_doc_id,
        )
        continue
      new_excludes.add(f"{self.documents_root}/{relative_source}")

    variant = SotaRagAdapter(
      base_url=self.base_url,
      documents_root=self.documents_root,
      local_corpus_root=self.local_corpus_root,
      poison_upload_dir=self.poison_upload_dir,
      query_path=self.query_path,
      ingest_path=self.ingest_path,
      max_sources=self.max_sources,
      system_prompt=self.system_prompt,
      exclude_source_files=frozenset(new_excludes),
      transport=self.transport,
      timeout=self.timeout,
    )
    variant._declared_sensitive = set(self._declared_sensitive)
    variant._doc_id_source_map = self._doc_id_source_map
    logger.debug(
      "SotaRagAdapter.build_variant: 신규 제외 {}건 (누적 {}건)",
      len(new_excludes) - len(self.exclude_source_files),
      len(new_excludes),
    )
    return variant

  def write_documents(self, documents: Any) -> int:
    """
    SOTA_RAG 에 문서를 업로드합니다(R9 poison 주입).

    같은 파일시스템(RunPod pod)을 공유한다는 전제 하에, poison 문서를 SOTA_RAG 문서
    트리 내부(poison_upload_dir)에 .txt 로 직접 써넣고 /api/v1/ingest 로 개별
    인덱싱을 요청한다.

    Args:
      documents: 주입할 poison 문서들(dict 또는 content/id 속성을 가진 객체).

    Returns:
      int: 실제로 업로드를 요청한 문서 수.
    """
    upload_dir = Path(self.documents_root) / self.poison_upload_dir
    upload_dir.mkdir(parents=True, exist_ok=True)

    count = 0
    for doc in documents:
      if isinstance(doc, dict):
        content = str(doc.get("content", "") or "")
        doc_id = str(doc.get("doc_id") or doc.get("id") or "")
      else:
        content = str(getattr(doc, "content", "") or "")
        doc_id = str(getattr(doc, "id", "") or "")

      if doc_id:
        filename = f"{doc_id}.txt"
      else:
        self._poison_seq += 1
        filename = f"poison-{self._poison_seq:04d}.txt"

      file_path = upload_dir / filename
      file_path.write_text(content, encoding="utf-8")

      self._post(self.ingest_path, {"file_path": str(file_path), "overwrite": True})
      count += 1

    logger.info("SotaRagAdapter.write_documents: poison {}건 업로드", count)
    return count


# 레지스트리에 "sota" 타입 등록. __init__.py 가 이 모듈을 import 하면 등록이 실행된다.
register_adapter(
  "sota",
  lambda config, pipeline: SotaRagAdapter.from_config(config),
  SOTA_NATIVE_CAPABILITIES,
)
