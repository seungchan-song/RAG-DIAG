"""BYO-RAG 어댑터 계층 테스트.

모델 로드 없이 fake 파이프라인/저장소로 계약(RagTrace/Capability/TargetRAG),
참조 어댑터(BuiltinHaystackAdapter), 능력 기반 실행 계획, 그리고 공격 엔진
결합점(BaseAttack._run_rag_query)의 비파괴성을 검증한다.
"""

from __future__ import annotations

from typing import Any

from haystack import Document

from rag.adapters import (
  BuiltinHaystackAdapter,
  Capability,
  RagTrace,
  TargetRAG,
  has_capability,
  plan_scenario_execution,
  resolve_capabilities,
)
from rag.adapters.capabilities import DECISION_DEGRADE, DECISION_RUN, DECISION_SKIP


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
