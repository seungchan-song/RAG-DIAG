"""Tests for structured execution failure artifacts and resume behavior."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import rag.attack.runner as runner_module
import rag.index.manager as index_manager_module
import rag.pii.artifacts as artifacts_module
import rag.retriever.pipeline as pipeline_module
from rag.attack.base import AttackResult
from rag.cli import main as cli_main
from rag.utils.experiment import ExperimentManager


def _base_config(tmp_path) -> dict:
  return {
    "profile_name": "reranker_off",
    "report": {
      "output_dir": str(tmp_path / "results"),
      "mask_raw_pii": True,
      "persist_raw_response": False,
    },
    "attack": {"doc_path": "data/documents"},
    "index": {"auto_build_if_missing": True},
    "retrieval_config": {
      "reranker": {
        "enabled": False,
        "model_name": "test-reranker",
        "top_k": 3,
      }
    },
    "embedding": {"model_name": "test-embedding"},
    "pii": {
      "ner": {"model_path": "test-ner"},
      "sllm": {"model": "test-sllm"},
    },
    "experiment": {"random_seed": 7},
    "evaluator": {
      "r2": {"rouge_threshold": 0.7},
      "r4": {"hit_rate_threshold": 0.5},
      "r9": {"trigger_marker": "[R9_ATTACK_SUCCESS_777]"},
    },
  }


class _DummyDoc:
  def __init__(self, *, content: str, meta: dict[str, object], doc_id: str) -> None:
    self.content = content
    self.meta = meta
    self.id = doc_id


class _DummyStore:
  def filter_documents(self):
    return [
      _DummyDoc(
        content="safe content",
        meta={
          "doc_role": "normal",
          "keyword": "safe",
          "doc_id": "doc-1",
          "chunk_id": "doc-1#0",
        },
        doc_id="doc-1#0",
      )
    ]


class _DummyPipeline:
  def warm_up(self) -> None:
    return None


class _FakeSanitizer:
  def __init__(self, config) -> None:
    self.config = config

  def sanitized_copy(self, result: AttackResult) -> AttackResult:
    masked = copy.deepcopy(result)
    masked.response = "[MASKED_RESPONSE]"
    masked.response_masked = "[MASKED_RESPONSE]"
    masked.masking_applied = True
    masked.pii_summary = {
      "total": 0,
      "by_tag": {},
      "by_route": {},
      "top3_tags": [],
      "high_risk_count": 0,
      "high_risk_tags": [],
      "has_high_risk": False,
    }
    masked.pii_findings = []
    masked.pii_runtime_status = {}
    return masked

  def sanitize_failure(self, failure):
    masked = copy.deepcopy(failure)
    masked.query_masked = "[MASKED_QUERY]"
    masked.error_message_masked = "[MASKED_ERROR]"
    return masked


class _FakeEvaluator:
  def evaluate(self, result: AttackResult) -> None:
    result.success = True
    result.score = 1.0


class _FakeIndexManager:
  def __init__(self, config, *, doc_path: str, environment: str, scenario: str | None = None):
    scenario_scope = "base" if environment == "clean" else str(scenario or "").upper()
    self.manifest_path = Path(
      f"data/indexes/{environment}/{scenario_scope}/reranker_off/manifest.json"
    )
    self.index_dir = Path(f"data/indexes/{environment}/{scenario_scope}/reranker_off")
    self.environment = environment
    self.scenario = scenario

  def ensure_index(self, **kwargs):
    return (
      _DummyStore(),
      {
        "scenario_scope": (
          "base" if self.environment == "clean" else str(self.scenario or "").upper()
        ),
        "dataset_scope": (
          "clean/base"
          if self.environment == "clean"
          else f"poisoned/{str(self.scenario or '').upper()}"
        ),
        "dataset_selection_mode": "canonical",
        "doc_count": 1,
        "doc_selection_summary": {"normal": 1, "sensitive": 0, "attack": 0},
      },
      "reused",
    )


class _FailingIndexManager(_FakeIndexManager):
  def ensure_index(self, **kwargs):
    raise RuntimeError("index failure 010-1234-5678")


class _FakeRunner:
  attempts: dict[str, int] = {}

  def __init__(self, config) -> None:
    self.config = config

  def prepare_queries(self, scenario, target_docs, attacker="A2"):
    return object(), [
      {"query": "query 010-1234-5678", "query_id": "q1"},
      {"query": "safe query", "query_id": "q2"},
    ]

  def execute_query(
    self,
    attack,
    *,
    query_info,
    rag_pipeline,
    attacker,
    env,
    trial_index,
  ):
    query_id = str(query_info.get("query_id", ""))
    attempt = self.attempts.get(query_id, 0)
    self.attempts[query_id] = attempt + 1
    if query_id == "q1" and attempt == 0:
      raise RuntimeError("query failure 010-1234-5678")
    return AttackResult(
      scenario="R2",
      query=str(query_info.get("query", "")),
      response=f"answer:{query_id}",
      query_id=query_id,
      environment_type=env,
      profile_name="reranker_off",
      metadata={"trial_index": trial_index, "attacker": attacker},
    )


def _patch_success_dependencies(monkeypatch) -> None:
  _FakeRunner.attempts = {}
  monkeypatch.setattr(index_manager_module, "PersistentIndexManager", _FakeIndexManager)
  monkeypatch.setattr(runner_module, "AttackRunner", _FakeRunner)
  monkeypatch.setattr(
    pipeline_module,
    "build_rag_pipeline",
    lambda document_store, config: _DummyPipeline(),
  )
  monkeypatch.setattr(artifacts_module, "StorageSanitizer", _FakeSanitizer)
  monkeypatch.setattr(cli_main, "_create_evaluator", lambda scenario, config: _FakeEvaluator())


def test_query_failures_are_saved_and_resumed(tmp_path, monkeypatch):
  config = _base_config(tmp_path)
  _patch_success_dependencies(monkeypatch)
  exp_manager = ExperimentManager(config)

  first_outcome = cli_main._execute_single_run(
    config,
    scenario="R2",
    attacker="A1",
    env="clean",
    profile="reranker_off",
    exp_manager=exp_manager,
  )

  checkpoint = exp_manager.load_checkpoint(first_outcome.run_id)
  failures = exp_manager.load_partial_failures(first_outcome.run_id, "R2")
  with open(
    exp_manager.run_dir(first_outcome.run_id) / "R2_result.json",
    "r",
    encoding="utf-8",
  ) as file:
    first_result = json.load(file)

  assert first_outcome.status == "partial"
  assert checkpoint["status"] == "partial"
  assert checkpoint["completed_query_ids"] == ["q2"]
  assert checkpoint["failed_query_ids"] == ["q1"]
  assert checkpoint["failure_attempt_count"] == 1
  assert checkpoint["failure_stage_counts"] == {"query_execute": 1}
  assert len(failures) == 1
  assert failures[0]["stage"] == "query_execute"
  assert "010-1234-5678" not in json.dumps(failures, ensure_ascii=False)
  assert first_result["execution_failure_count"] == 1
  assert first_result["open_failure_count"] == 1
  assert first_result["total"] == 1

  second_outcome = cli_main._execute_single_run(
    config,
    scenario="R2",
    attacker="A1",
    env="clean",
    profile="reranker_off",
    exp_manager=exp_manager,
    run_id=first_outcome.run_id,
    resume_existing=True,
  )

  checkpoint_after_resume = exp_manager.load_checkpoint(first_outcome.run_id)
  failures_after_resume = exp_manager.load_partial_failures(first_outcome.run_id, "R2")
  with open(
    exp_manager.run_dir(first_outcome.run_id) / "R2_result.json",
    "r",
    encoding="utf-8",
  ) as file:
    resumed_result = json.load(file)

  assert second_outcome.status == "completed"
  assert checkpoint_after_resume["status"] == "completed"
  assert checkpoint_after_resume["completed_query_ids"] == ["q1", "q2"]
  assert checkpoint_after_resume["failed_query_ids"] == []
  assert len(failures_after_resume) == 1
  assert resumed_result["execution_failure_count"] == 1
  assert resumed_result["open_failure_count"] == 0
  assert resumed_result["total"] == 2


def test_setup_failure_writes_masked_failure_artifacts(tmp_path, monkeypatch):
  config = _base_config(tmp_path)
  monkeypatch.setattr(index_manager_module, "PersistentIndexManager", _FailingIndexManager)
  monkeypatch.setattr(artifacts_module, "StorageSanitizer", _FakeSanitizer)

  exp_manager = ExperimentManager(config)
  outcome = cli_main._execute_single_run(
    config,
    scenario="R2",
    attacker="A1",
    env="poisoned",
    profile="reranker_off",
    exp_manager=exp_manager,
  )

  checkpoint = exp_manager.load_checkpoint(outcome.run_id)
  failures = exp_manager.load_partial_failures(outcome.run_id, "R2")
  with open(
    exp_manager.run_dir(outcome.run_id) / "R2_result.json",
    "r",
    encoding="utf-8",
  ) as file:
    result = json.load(file)

  assert outcome.status == "failed_setup"
  assert checkpoint["status"] == "failed_setup"
  assert checkpoint["last_error_stage"] == "index_load"
  assert checkpoint["failure_stage_counts"] == {"index_load": 1}
  assert failures[0]["stage"] == "index_load"
  assert "010-1234-5678" not in json.dumps(failures, ensure_ascii=False)
  assert result["status"] == "failed_setup"
  assert result["execution_failure_count"] == 1
  assert result["open_failure_count"] == 1
  assert result["total"] == 0
