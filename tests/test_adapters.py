"""BYO-RAG 어댑터 계층 테스트.

모델 로드 없이 fake 파이프라인/저장소로 계약(RagTrace/Capability/TargetRAG),
참조 어댑터(BuiltinHaystackAdapter), 능력 기반 실행 계획, 그리고 공격 엔진
결합점(BaseAttack._run_rag_query)의 비파괴성을 검증한다.
"""

from __future__ import annotations

from typing import Any

import pytest
from haystack import Document

from rag.adapters import (
  AdapterConfigError,
  BuiltinHaystackAdapter,
  Capability,
  CapabilityGatedAdapter,
  RagTrace,
  RestRagAdapter,
  TargetRAG,
  UnsupportedCapabilityError,
  available_adapters,
  create_target_adapter,
  has_capability,
  plan_scenario_execution,
  resolve_capabilities,
  resolve_target_capabilities,
)
from rag.adapters.capabilities import DECISION_DEGRADE, DECISION_RUN, DECISION_SKIP


def _record_transport(response: dict[str, Any]) -> Any:
  """RestRagAdapter 테스트용: 호출을 기록하고 고정 응답을 돌려주는 transport."""

  calls: list[dict[str, Any]] = []

  def transport(url: str, payload: dict[str, Any], headers: dict[str, str]) -> dict[str, Any]:
    calls.append({"url": url, "payload": payload, "headers": headers})
    return response

  transport.calls = calls  # type: ignore[attr-defined]
  return transport


# === 공통 fake 파이프라인 (run_query 구동용, 모델 로드 없음) ===
class _FakeQueryEmbedder:
  def run(self, text: str) -> dict[str, Any]:
    return {"embedding": [0.1, 0.2, 0.3], "text": text}


class _FakeRetriever:
  def __init__(self, documents: list[Any], document_store: Any = None) -> None:
    self.documents = documents
    self.document_store = document_store

  def run(self, query_embedding: list[float]) -> dict[str, Any]:
    return {"documents": list(self.documents)}


class _FakePromptBuilder:
  def run(self, documents: list[Any], query: str) -> dict[str, Any]:
    return {"prompt": f"Q={query}"}


class _FakeGenerator:
  def run(self, prompt: str) -> dict[str, Any]:
    return {"replies": [f"answer::{prompt}"], "meta": [{"model": "fake"}]}


class _FakeDoc:
  def __init__(self, content: str, score: float, meta: dict[str, Any]) -> None:
    self.id = meta.get("doc_id", "")
    self.content = content
    self.score = score
    self.meta = meta


class _FakePipeline:
  def __init__(self, documents: list[Any], document_store: Any = None) -> None:
    self.components = {
      "query_embedder": _FakeQueryEmbedder(),
      "retriever": _FakeRetriever(documents, document_store),
      "prompt_builder": _FakePromptBuilder(),
      "generator": _FakeGenerator(),
    }
    self._rag_runtime = {
      "profile_name": "fake-profile",
      "retrieval_config": {"similarity_threshold": 0.0, "reranker": {"enabled": False}},
      "reranker": None,
    }

  def get_component(self, name: str) -> Any:
    return self.components[name]


def _make_pipeline() -> _FakePipeline:
  docs = [_FakeDoc("민감 내용", 0.9, {"doc_id": "d1"})]
  return _FakePipeline(docs)


# === 계약: Capability / RagTrace ===
def test_capability_enum_is_string_valued():
  assert Capability.QUERY.value == "query"
  assert Capability.INDEX_WRITE == "index_write"


def test_ragtrace_roundtrip_preserves_raw_dict():
  """엔진 dict → RagTrace → dict 왕복이 원본을 그대로 보존해야 한다(비파괴)."""
  engine_result = {
    "generator": {"replies": ["원문 유출"], "meta": []},
    "retrieved_documents": [{"id": "d1", "content": "민감"}],
    "final_prompt": "prompt-text",
    "profile_name": "p",
    "retrieval_config": {"top_k": 3},
    "reranker_enabled": True,
    "raw_retrieved_documents": [{"id": "d1"}],
    "thresholded_documents": [{"id": "d1"}],
    "reranked_documents": [],
  }
  trace = RagTrace.from_engine_result(engine_result)
  assert trace.answer == "원문 유출"
  assert trace.final_prompt == "prompt-text"
  # raw 가 보존되므로 왕복은 동일 객체를 돌려준다.
  assert trace.to_engine_dict() is engine_result


def test_ragtrace_synthesizes_engine_dict_for_external_adapter():
  """raw 가 없는 외부 어댑터 트레이스는 공격 엔진이 읽는 키를 모두 합성해야 한다."""
  trace = RagTrace(
    answer="외부 응답",
    retrieved_documents=[{"id": "x", "content": "c"}],
    final_prompt="fp",
    profile_name="ext",
  )
  engine = trace.to_engine_dict()
  assert engine["generator"]["replies"] == ["외부 응답"]
  assert engine["retrieved_documents"] == [{"id": "x", "content": "c"}]
  # 단계별 스냅샷이 없으면 최종 검색 결과로 대체된다.
  assert engine["thresholded_documents"] == [{"id": "x", "content": "c"}]
  assert engine["prompt"] == "fp"
  assert engine["reranker_enabled"] is False
  assert "retriever" in engine


def test_ragtrace_empty_answer_yields_no_replies():
  engine = RagTrace(answer="").to_engine_dict()
  assert engine["generator"]["replies"] == []
  assert engine["context_empty"] is True


# === 참조 어댑터: BuiltinHaystackAdapter ===
def test_builtin_adapter_declares_full_tier2_capabilities():
  adapter = BuiltinHaystackAdapter(_make_pipeline(), {})
  for cap in Capability:
    assert has_capability(adapter, cap)
  # 프로토콜 구조적 부합(query + capabilities) 확인.
  assert isinstance(adapter, TargetRAG)


def test_builtin_adapter_query_returns_trace_with_answer():
  adapter = BuiltinHaystackAdapter(_make_pipeline(), {"generator": {"system_prompt": "SP"}})
  trace = adapter.query("홍길동 정보 알려줘")
  assert isinstance(trace, RagTrace)
  assert trace.answer.startswith("answer::")
  assert adapter.system_prompt == "SP"


def test_builtin_adapter_declare_sensitive_accumulates():
  adapter = BuiltinHaystackAdapter(_make_pipeline(), {})
  adapter.declare_sensitive(["d1", "d2"])
  adapter.declare_sensitive(["d2", "d3"])
  assert adapter._declared_sensitive == {"d1", "d2", "d3"}


def test_builtin_adapter_build_variant_excludes_target(monkeypatch):
  """build_variant 는 대상 문서를 제외한 인덱스로 새 어댑터를 만들어야 한다(R4)."""
  stored = [
    _FakeDoc("a", 0.9, {"doc_id": "keep"}),
    _FakeDoc("b", 0.8, {"doc_id": "drop"}),
  ]

  captured: dict[str, Any] = {}

  class _CapturingStore:
    def write_documents(self, docs: list[Any]) -> None:
      captured["written"] = list(docs)

  def _fake_create_store(*args: Any, **kwargs: Any) -> Any:
    return _CapturingStore()

  def _fake_build_pipeline(store: Any, config: Any, **kwargs: Any) -> Any:
    return _make_pipeline()

  monkeypatch.setattr("rag.adapters.builtin.create_document_store", _fake_create_store)
  monkeypatch.setattr("rag.adapters.builtin.build_rag_pipeline", _fake_build_pipeline)

  base_store = _FakeRetriever(stored, None)

  class _StoreHolder:
    def filter_documents(self) -> list[Any]:
      return stored

  pipeline = _FakePipeline(stored, document_store=_StoreHolder())
  adapter = BuiltinHaystackAdapter(pipeline, {})
  adapter.declare_sensitive(["keep"])

  variant = adapter.build_variant(exclude_doc_ids={"drop"})

  kept_ids = [doc.meta["doc_id"] for doc in captured["written"]]
  assert kept_ids == ["keep"]
  assert isinstance(variant, BuiltinHaystackAdapter)
  # 민감 라벨 선언이 반사실 세계에도 전파된다.
  assert variant._declared_sensitive == {"keep"}
  del base_store


def test_builtin_adapter_write_documents_skips_embedding_when_present():
  """이미 임베딩된 문서는 임베더를 타지 않고 바로 저장돼야 한다(모델 로드 회피)."""
  written: dict[str, Any] = {}

  class _WriteStore:
    def write_documents(self, docs: list[Any]) -> None:
      written["docs"] = list(docs)

  pipeline = _FakePipeline([], document_store=None)
  pipeline.get_component("retriever").document_store = _WriteStore()

  adapter = BuiltinHaystackAdapter(pipeline, {})
  doc = Document(content="poison", embedding=[0.1, 0.2, 0.3], meta={"doc_role": "attack"})
  adapter.write_documents([doc])

  assert len(written["docs"]) == 1
  assert written["docs"][0].content == "poison"


def test_coerce_document_from_dict():
  doc = BuiltinHaystackAdapter._coerce_document(
    {"content": "본문", "doc_id": "p1", "meta": {"doc_role": "attack"}}
  )
  assert isinstance(doc, Document)
  assert doc.content == "본문"
  assert doc.id == "p1"
  assert doc.meta["doc_role"] == "attack"


# === 능력 기반 실행 계획 ===
class _BlackboxTarget:
  """query 만 노출하는 최소 어댑터(Tier 0 미만, 블랙박스)."""

  capabilities = {Capability.QUERY}

  def query(self, query: str) -> RagTrace:
    return RagTrace(answer="ok")


def test_resolve_capabilities_handles_missing_attribute():
  assert resolve_capabilities(object()) == set()
  assert resolve_capabilities(_BlackboxTarget()) == {Capability.QUERY}


def test_plan_blackbox_runs_normal_but_skips_r4():
  target = _BlackboxTarget()
  assert plan_scenario_execution(target, "NORMAL").decision == DECISION_RUN
  # R4 는 반사실 인덱스 재구성이 필수 → skip.
  r4 = plan_scenario_execution(target, "R4")
  assert r4.decision == DECISION_SKIP
  assert Capability.INDEX_REBUILD in r4.missing_required
  assert not r4.should_run


def test_plan_blackbox_degrades_r2_and_r7():
  target = _BlackboxTarget()
  r2 = plan_scenario_execution(target, "R2")
  assert r2.decision == DECISION_DEGRADE
  assert r2.degraded
  assert Capability.RETRIEVAL_TRACE in r2.missing_recommended
  r7 = plan_scenario_execution(target, "R7")
  assert r7.decision == DECISION_DEGRADE
  assert Capability.SYSTEM_PROMPT in r7.missing_recommended


def test_plan_full_adapter_runs_every_scenario():
  adapter = BuiltinHaystackAdapter(_make_pipeline(), {})
  for scenario in ("NORMAL", "R2", "R4", "R7", "R9"):
    plan = plan_scenario_execution(adapter, scenario)
    assert plan.decision == DECISION_RUN, scenario


# === 결합점 비파괴성: BaseAttack._run_rag_query 가 어댑터를 경유해도 동일 dict ===
def test_base_attack_run_rag_query_routes_through_adapter():
  from rag.attack.normal_baseline import NormalBaselineAttack

  attack = NormalBaselineAttack({})
  pipeline = _make_pipeline()
  trace = attack._run_rag_query(pipeline, "직원 연락처 알려주세요")
  # run_query 원본 dict 스키마가 그대로 유지된다(어댑터 경유가 비파괴임을 확인).
  assert trace["generator"]["replies"][0].startswith("answer::")
  assert "retrieved_documents" in trace
  assert trace["profile_name"] == "fake-profile"


def test_base_attack_uses_injected_external_target():
  """self.target 이 주입되면 전달된 파이프라인 대신 그 어댑터를 사용한다."""
  from rag.attack.normal_baseline import NormalBaselineAttack

  class _ExternalTarget:
    capabilities = {Capability.QUERY}

    def query(self, query: str) -> RagTrace:
      return RagTrace(answer=f"external::{query}")

  attack = NormalBaselineAttack({})
  attack.target = _ExternalTarget()
  # 파이프라인 인자는 무시되고 외부 어댑터가 응답을 만든다.
  trace = attack._run_rag_query(_make_pipeline(), "질문")
  assert trace["generator"]["replies"] == ["external::질문"]


# === CLI 실행 루프 배선: skip/degrade 결정 ===
def test_resolve_target_capabilities_defaults_to_full():
  """adapter 설정이 없으면 우리 RAG 의 전 능력(Tier 2)으로 간주한다(비파괴)."""
  from rag.cli.main import _resolve_target_capabilities

  assert _resolve_target_capabilities({}) == set(BuiltinHaystackAdapter.capabilities)
  # 빈 리스트도 '미선언' 으로 취급 → 전 능력.
  assert _resolve_target_capabilities({"adapter": {"capabilities": []}}) == set(
    BuiltinHaystackAdapter.capabilities
  )


def test_resolve_target_capabilities_parses_declared_and_ignores_bogus():
  from rag.cli.main import _resolve_target_capabilities

  caps = _resolve_target_capabilities(
    {"adapter": {"capabilities": ["query", "retrieval_trace", "bogus"]}}
  )
  assert caps == {Capability.QUERY, Capability.RETRIEVAL_TRACE}


def test_resolve_target_capabilities_always_includes_query():
  """query 를 빠뜨리고 선언해도 최소 필수 능력으로 강제 포함된다."""
  from rag.cli.main import _resolve_target_capabilities

  caps = _resolve_target_capabilities({"adapter": {"capabilities": ["doc_labels"]}})
  assert Capability.QUERY in caps
  assert Capability.DOC_LABELS in caps


def test_declared_blackbox_config_drives_skip_and_degrade():
  """블랙박스(query만) 로 선언하면 R4 skip · R2/R7 degrade · NORMAL run 이어야 한다."""
  from types import SimpleNamespace

  from rag.cli.main import _resolve_target_capabilities

  caps = _resolve_target_capabilities({"adapter": {"capabilities": ["query"]}})
  target = SimpleNamespace(capabilities=caps)
  assert plan_scenario_execution(target, "R4").decision == DECISION_SKIP
  assert plan_scenario_execution(target, "R2").decision == DECISION_DEGRADE
  assert plan_scenario_execution(target, "R7").decision == DECISION_DEGRADE
  assert plan_scenario_execution(target, "NORMAL").decision == DECISION_RUN


def test_capability_plan_payload_serializes_decision_and_reason():
  from rag.cli.main import _capability_plan_payload

  plan = plan_scenario_execution(_BlackboxTarget(), "R4")
  payload = _capability_plan_payload(plan)
  assert payload["decision"] == DECISION_SKIP
  assert "index_rebuild" in payload["missing_required"]
  assert isinstance(payload["reason"], str) and payload["reason"]


class _FakeExpManager:
  """_execute_single_run 의 저장 호출을 흡수하는 최소 exp_manager 스텁."""

  def __init__(self) -> None:
    self.saved_results: list[Any] = []
    self.checkpoints: list[Any] = []

  def load_partial_results(self, run_id: str, scenario: str) -> list[Any]:
    return []

  def load_partial_failures(self, run_id: str, scenario: str) -> list[Any]:
    return []

  def save_snapshot(self, *args: Any, **kwargs: Any) -> None:
    return None

  def save_checkpoint(self, run_id: str, checkpoint: Any) -> None:
    self.checkpoints.append(checkpoint)

  def save_result(self, run_id: str, payload: Any, filename: str) -> None:
    self.saved_results.append((filename, payload))


def test_execute_single_run_skips_r4_for_blackbox_target(monkeypatch):
  """블랙박스 대상(query만)에서 R4 는 인덱스 로드 없이 skip 으로 단락되어야 한다."""
  import rag.pii.artifacts as artifacts_module
  from rag.cli.main import _execute_single_run

  # StorageSanitizer 는 NER 모델을 로드하므로 스텁으로 대체(skip 경로 검증에 불필요).
  class _FakeSanitizer:
    def __init__(self, config: Any) -> None:
      pass

  monkeypatch.setattr(artifacts_module, "StorageSanitizer", _FakeSanitizer)
  # 인덱스 매니저가 호출되면 skip 이 단락되지 않은 것이므로 명시적으로 실패시킨다.
  import rag.index.manager as index_manager_module

  def _boom(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("skip 경로는 인덱스를 로드하면 안 된다")

  monkeypatch.setattr(index_manager_module, "PersistentIndexManager", _boom)

  exp_manager = _FakeExpManager()
  outcome = _execute_single_run(
    {"adapter": {"capabilities": ["query"]}},
    scenario="R4",
    attacker="A2",
    env="clean",
    profile="reranker_off",
    exp_manager=exp_manager,
    run_id="RAG-TEST-0001",
    resume_existing=False,
    probe_mode="sensitive",
  )

  assert outcome.status == "skipped"
  assert outcome.summary["status"] == "skipped"
  assert outcome.summary["capability_plan"]["decision"] == DECISION_SKIP
  assert "index_rebuild" in outcome.summary["capability_plan"]["missing_required"]
  # 결과가 실제로 저장되었는지(리포트가 skip 사유를 볼 수 있도록) 확인.
  assert any(name == "R4_result.json" for name, _ in exp_manager.saved_results)


# === ① 내부 이관: R4 build_variant · R9 write_documents ===
def test_r4_execute_b0_routes_through_build_variant(monkeypatch):
  """R4 b=0 실행은 build_variant 로 만든 비회원 어댑터를 경유해야 한다(이관 검증)."""
  from rag.attack.r4_membership import R4MembershipAttack

  captured: dict[str, Any] = {}

  class _CapturingStore:
    def write_documents(self, docs: list[Any]) -> None:
      captured["written"] = list(docs)

  variant_pipeline = _make_pipeline()
  monkeypatch.setattr(
    "rag.adapters.builtin.create_document_store", lambda *a, **k: _CapturingStore()
  )
  monkeypatch.setattr(
    "rag.adapters.builtin.build_rag_pipeline", lambda store, config, **k: variant_pipeline
  )

  stored = [
    _FakeDoc("keep", 0.9, {"doc_id": "keep"}),
    _FakeDoc("d_star", 0.8, {"doc_id": "d_star"}),
  ]

  class _StoreHolder:
    def filter_documents(self) -> list[Any]:
      return stored

  member_pipeline = _FakePipeline(stored, document_store=_StoreHolder())

  # generic 모드 + NER off 로 PIIDetector(KPF-BERT) 로드를 피한다.
  attack = R4MembershipAttack(
    {"attack": {"r4": {"sensitive_use_ner": False}}}, probe_mode="generic"
  )
  q_info = {
    "query": "질문",
    "target_text": "d_star",
    "ground_truth_b": 0,
    "target_doc_id": "d_star",
    "query_id": "R4:x",
  }
  result = attack.execute(q_info, member_pipeline)

  # 반사실 인덱스에서 d_star 가 제외되고 keep 만 남아야 한다.
  assert [d.meta["doc_id"] for d in captured["written"]] == ["keep"]
  # 응답은 build_variant 로 만든 반사실 파이프라인에서 생성된다.
  assert result.response.startswith("answer::")
  # 같은 d* 재사용을 위해 반사실 어댑터가 캐시된다.
  assert "d_star" in attack._non_member_adapters


def test_r9_inject_poison_uses_write_documents():
  """R9 poison 주입이 어댑터의 write_documents 로 이관되어야 한다(INDEX_WRITE 보유)."""
  from rag.attack.r9_injection import R9InjectionAttack

  written: dict[str, Any] = {}

  class _WriteTarget:
    capabilities = {Capability.QUERY, Capability.INDEX_WRITE}

    def query(self, query: str) -> RagTrace:
      return RagTrace(answer="")

    def write_documents(self, docs: Any) -> None:
      written["docs"] = list(docs)

  attack = R9InjectionAttack({})
  count = attack.inject_poison(_WriteTarget(), ["기밀자료"])
  assert count >= 1
  assert len(written["docs"]) == count


def test_r9_inject_poison_skipped_without_index_write():
  """INDEX_WRITE 를 노출하지 않는 어댑터에는 poison 을 주입하지 않는다."""
  from rag.attack.r9_injection import R9InjectionAttack

  class _NoWriteTarget:
    capabilities = {Capability.QUERY}

    def query(self, query: str) -> RagTrace:
      return RagTrace(answer="")

  attack = R9InjectionAttack({})
  assert attack.inject_poison(_NoWriteTarget(), ["기밀자료"]) == 0


# === ② 외부 어댑터 주입 + truthful degrade (CapabilityGatedAdapter) ===
def test_gated_adapter_strips_retrieval_when_not_declared():
  """RETRIEVAL_TRACE 미선언 시 검색 원문이 구조화 필드·raw dict 양쪽에서 비워져야 한다."""
  inner = BuiltinHaystackAdapter(_make_pipeline(), {})
  gated = CapabilityGatedAdapter(inner, {Capability.QUERY})
  trace = gated.query("질문")
  assert trace.retrieved_documents == []
  engine = trace.to_engine_dict()
  assert engine["retrieved_documents"] == []
  assert engine["retriever"]["documents"] == []
  # 응답 자체(query 능력)는 유지된다.
  assert trace.answer.startswith("answer::")


def test_gated_adapter_preserves_retrieval_when_declared():
  inner = BuiltinHaystackAdapter(_make_pipeline(), {})
  gated = CapabilityGatedAdapter(inner, {Capability.QUERY, Capability.RETRIEVAL_TRACE})
  trace = gated.query("질문")
  assert len(trace.retrieved_documents) == 1


def test_gated_adapter_nulls_system_prompt_when_not_declared():
  inner = BuiltinHaystackAdapter(_make_pipeline(), {"generator": {"system_prompt": "SP"}})
  assert CapabilityGatedAdapter(inner, {Capability.QUERY}).system_prompt is None
  declared = CapabilityGatedAdapter(inner, {Capability.QUERY, Capability.SYSTEM_PROMPT})
  assert declared.system_prompt == "SP"


def test_gated_adapter_blocks_undeclared_methods():
  inner = BuiltinHaystackAdapter(_make_pipeline(), {})
  gated = CapabilityGatedAdapter(inner, {Capability.QUERY})
  with pytest.raises(UnsupportedCapabilityError):
    gated.build_variant(exclude_doc_ids={"x"})
  with pytest.raises(UnsupportedCapabilityError):
    gated.write_documents([])
  with pytest.raises(UnsupportedCapabilityError):
    gated.declare_sensitive(["x"])


def test_gated_adapter_always_includes_query():
  gated = CapabilityGatedAdapter(BuiltinHaystackAdapter(_make_pipeline(), {}), set())
  assert Capability.QUERY in gated.capabilities


def test_resolve_target_adapter_none_for_full_and_gated_for_limited():
  from rag.cli.main import _resolve_target_adapter

  full = set(BuiltinHaystackAdapter.capabilities)
  assert _resolve_target_adapter({}, _make_pipeline(), full) is None

  limited = _resolve_target_adapter({}, _make_pipeline(), {Capability.QUERY})
  assert isinstance(limited, CapabilityGatedAdapter)
  assert limited.capabilities == {Capability.QUERY}


def test_base_attack_with_gated_target_degrades_truthfully():
  """게이팅 타깃(RETRIEVAL_TRACE 미선언) 주입 시 트레이스에서 검색 원문이 사라진다."""
  from rag.attack.normal_baseline import NormalBaselineAttack

  gated = CapabilityGatedAdapter(BuiltinHaystackAdapter(_make_pipeline(), {}), {Capability.QUERY})
  attack = NormalBaselineAttack({})
  attack.target = gated
  trace = attack._run_rag_query(_make_pipeline(), "질문")
  assert trace["retrieved_documents"] == []
  assert trace["generator"]["replies"][0].startswith("answer::")


# === ④ 어댑터 레지스트리 (config.adapter.type) ===
def test_registry_lists_builtin_and_rest():
  names = available_adapters()
  assert "builtin" in names
  assert "rest" in names


def test_resolve_target_capabilities_for_rest_type():
  # rest native 는 검색 원문은 있지만 반사실 재구성(INDEX_REBUILD)은 없다.
  caps = resolve_target_capabilities({"adapter": {"type": "rest", "base_url": "http://x"}})
  assert Capability.RETRIEVAL_TRACE in caps
  assert Capability.INDEX_REBUILD not in caps
  # 선언은 native 를 넘을 수 없다(교집합) → index_rebuild 는 걸러진다.
  narrowed = resolve_target_capabilities(
    {"adapter": {"type": "rest", "capabilities": ["query", "index_rebuild"]}}
  )
  assert narrowed == {Capability.QUERY}


def test_create_target_adapter_builtin_rest_and_unknown():
  # builtin + 전 능력 → None(기존 경로).
  assert create_target_adapter({}, _make_pipeline()) is None
  # rest → RestRagAdapter 인스턴스.
  rest = create_target_adapter({"adapter": {"type": "rest", "base_url": "http://x"}}, None)
  assert isinstance(rest, RestRagAdapter)
  # 미등록 type → 명확한 에러.
  with pytest.raises(AdapterConfigError):
    create_target_adapter({"adapter": {"type": "does-not-exist"}}, None)


def test_create_target_adapter_gates_rest_with_limited_caps():
  gated = create_target_adapter(
    {"adapter": {"type": "rest", "base_url": "http://x", "capabilities": ["query"]}}, None
  )
  assert isinstance(gated, CapabilityGatedAdapter)
  assert gated.capabilities == {Capability.QUERY}


# === ⑤ RestRagAdapter 참조 외부 어댑터 ===
def test_rest_adapter_query_parses_answer_and_sources():
  transport = _record_transport(
    {"textResponse": "유출된 답변", "sources": [{"text": "민감 원문", "score": 0.9, "title": "d1"}]}
  )
  adapter = RestRagAdapter(base_url="http://x", workspace="ws", api_key="k", transport=transport)
  trace = adapter.query("질문")
  assert trace.answer == "유출된 답변"
  assert len(trace.retrieved_documents) == 1
  assert trace.retrieved_documents[0]["content"] == "민감 원문"
  assert trace.retrieved_documents[0]["score"] == 0.9
  # workspace 치환 + Bearer 헤더 + message 페이로드 확인.
  assert transport.calls[0]["url"].endswith("/api/v1/workspace/ws/chat")
  assert transport.calls[0]["payload"]["message"] == "질문"
  assert transport.calls[0]["headers"]["Authorization"] == "Bearer k"


def test_rest_adapter_lacks_index_rebuild_so_r4_skips():
  adapter = RestRagAdapter(base_url="http://x")
  assert Capability.INDEX_REBUILD not in adapter.capabilities
  assert plan_scenario_execution(adapter, "R4").decision == DECISION_SKIP
  assert plan_scenario_execution(adapter, "NORMAL").decision == DECISION_RUN


def test_rest_adapter_from_config_requires_base_url():
  with pytest.raises(AdapterConfigError):
    RestRagAdapter.from_config({"adapter": {"type": "rest"}})


def test_rest_adapter_write_documents_posts_each():
  transport = _record_transport({"ok": True})
  adapter = RestRagAdapter(base_url="http://x", transport=transport)
  count = adapter.write_documents([{"content": "poison", "doc_id": "p1"}])
  assert count == 1
  assert transport.calls[0]["url"].endswith("/api/v1/document/upload")
  assert transport.calls[0]["payload"]["name"] == "p1"
