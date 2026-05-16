"""Tests for config loading, experiment snapshots, and report generation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from rag.report.generator import ReportGenerator
from rag.utils.config import load_config
from rag.utils.experiment import ExperimentManager


def _make_result(
  *,
  scenario: str,
  query_id: str,
  environment: str,
  reranker_enabled: bool,
  profile_name: str,
  success: bool,
  score: float,
  response: str,
  response_masked: str | None = None,
  scenario_scope: str = "base",
  dataset_scope: str | None = None,
  index_manifest_ref: str = "",
  pii_total: int | None = None,
  pii_by_tag: dict[str, int] | None = None,
  has_high_risk: bool = False,
  step3_load_status: str = "ready",
  step3_model_source: str = "hub",
  step4_mode: str = "mock_conservative",
  step4_status: str = "ready",
  step4_reason: str = "mock_conservative",
  retrieved_ids: list[str] | None = None,
) -> dict:
  retrieved_ids = retrieved_ids or []
  pii_by_tag = pii_by_tag or {}
  pii_total = pii_total if pii_total is not None else sum(pii_by_tag.values())
  retrieved_documents = [
    {
      "id": doc_id,
      "score": 1.0 - index * 0.1,
      "content": f"document-{doc_id}",
      "meta": {"doc_id": doc_id, "chunk_id": doc_id, "file_path": f"{doc_id}.txt"},
    }
    for index, doc_id in enumerate(retrieved_ids)
  ]
  retrieval_config = {
    "top_k": 5,
    "similarity_threshold": 0.0,
    "reranker": {
      "enabled": reranker_enabled,
      "model_name": "test-reranker",
      "top_k": 3,
    },
  }
  reranker_state = "on" if reranker_enabled else "off"
  resolved_dataset_scope = dataset_scope or f"{environment}/{scenario_scope}"
  return {
    "scenario": scenario,
    "query": f"query for {query_id}",
    "response": response,
    "response_masked": response_masked or response,
    "masking_applied": True,
    "query_id": query_id,
    "environment_type": environment,
    "profile_name": profile_name,
    "scenario_scope": scenario_scope,
    "dataset_scope": resolved_dataset_scope,
    "index_manifest_ref": index_manifest_ref,
    "retrieval_config": retrieval_config,
    "pii_summary": {
      "total": pii_total,
      "by_tag": pii_by_tag,
      "by_route": {},
      "top3_tags": list(pii_by_tag.keys())[:3],
      "high_risk_count": pii_total if has_high_risk else 0,
      "high_risk_tags": list(pii_by_tag.keys())[:3] if has_high_risk else [],
      "has_high_risk": has_high_risk,
      "items": [],
    },
    "pii_findings": [],
    "pii_runtime_status": {
      "step3": {
        "enabled": True,
        "model_source": step3_model_source,
        "load_status": step3_load_status,
      },
      "step4": {
        "enabled": True,
        "mode": step4_mode,
        "status": step4_status,
        "reason": step4_reason,
      },
    },
    "raw_retrieved_documents": retrieved_documents,
    "thresholded_documents": retrieved_documents,
    "reranked_documents": retrieved_documents if reranker_enabled else [],
    "retrieved_documents": retrieved_documents,
    "success": success,
    "score": score,
    "metadata": {
      "env": environment,
      "query_id": query_id,
      "trial_index": 0,
      "profile_name": profile_name,
      "reranker_enabled": reranker_enabled,
      "reranker_state": reranker_state,
      "scenario_scope": scenario_scope,
      "dataset_scope": resolved_dataset_scope,
      "index_manifest_ref": index_manifest_ref,
      "target_doc_id": "doc-1",
      "attacker": "A1",
    },
  }


def _write_run(
  base_dir: Path,
  run_id: str,
  scenario: str,
  result_payload: dict,
) -> None:
  run_dir = base_dir / run_id
  run_dir.mkdir(parents=True, exist_ok=True)
  with open(run_dir / f"{scenario}_result.json", "w", encoding="utf-8") as file:
    json.dump(result_payload, file, ensure_ascii=False, indent=2)
  with open(run_dir / "snapshot.yaml", "w", encoding="utf-8") as file:
    yaml.safe_dump(
      {
        "run_id": run_id,
        "created_at": "2026-04-25T00:00:00",
        "config": {
          "profile_name": result_payload.get("profile_name", "default"),
          "retrieval_config": result_payload.get("retrieval_config", {}),
        },
        "runtime": {
          "scenario_scope": result_payload.get("scenario_scope", ""),
          "dataset_scope": result_payload.get("dataset_scope", ""),
        },
        "index_manifest_ref": result_payload.get("index_manifest_ref", ""),
      },
      file,
      allow_unicode=True,
      sort_keys=False,
    )


class TestConfig:
  def test_load_default_config(self):
    config = load_config()
    assert isinstance(config, dict)
    assert "ingest" in config
    assert "embedding" in config
    assert "retriever" in config
    assert "attack" in config
    assert "evaluator" in config
    assert config["profile_name"] == "default"
    assert config["retrieval_config"]["reranker"]["enabled"] is False

  def test_profile_override_keeps_base_keys(self):
    config = load_config(profile="reranker_on")
    assert config["profile_name"] == "reranker_on"
    assert config["retriever"]["top_k"] == 5
    assert config["retrieval_config"]["reranker"]["enabled"] is True

  def test_unknown_profile_raises(self):
    with pytest.raises(ValueError):
      load_config(profile="missing-profile")

  def test_load_nonexistent_config(self):
    with pytest.raises(FileNotFoundError):
      load_config("/nonexistent/path.yaml")


class TestExperimentManager:
  def test_create_run_and_save_snapshot(self, tmp_path):
    config = {"report": {"output_dir": str(tmp_path)}}
    manager = ExperimentManager(config)

    run_id = manager.create_run()
    assert run_id.startswith("RAG-")
    assert (tmp_path / run_id).exists()

    snapshot_path = manager.save_snapshot(run_id, {"hello": "world"})
    assert snapshot_path.exists()
    snapshot = manager.load_snapshot(run_id)
    assert snapshot["run_id"] == run_id
    assert snapshot["config"]["hello"] == "world"
    assert "config_fingerprint" in snapshot
    assert snapshot["provenance"]["python_version"]
    assert "code_version" in snapshot["provenance"]

  def test_save_replay_audit(self, tmp_path):
    config = {"report": {"output_dir": str(tmp_path)}}
    manager = ExperimentManager(config)
    run_id = manager.create_run()

    audit_path = manager.save_replay_audit(
      run_id,
      {
        "source_run_id": "RAG-2026-0425-001",
        "source_run_type": "single",
        "replayed_run_id": run_id,
        "compatibility_mode": False,
        "snapshot_diff": [],
        "provenance_diff": [],
        "index_manifest_match": True,
      },
    )

    assert audit_path == manager.replay_audit_path(run_id)
    with open(audit_path, "r", encoding="utf-8") as file:
      payload = json.load(file)
    assert payload["source_run_id"] == "RAG-2026-0425-001"
    assert payload["index_manifest_match"] is True
    assert "generated_at" in payload

  def test_save_result(self, tmp_path):
    config = {"report": {"output_dir": str(tmp_path)}}
    manager = ExperimentManager(config)
    run_id = manager.create_run()

    saved_path = manager.save_result(run_id, {"total": 3}, "R2_result.json")
    assert saved_path.exists()
    with open(saved_path, "r", encoding="utf-8") as file:
      loaded = json.load(file)
    assert loaded["total"] == 3

  def test_save_and_load_checkpoint(self, tmp_path):
    config = {"report": {"output_dir": str(tmp_path)}}
    manager = ExperimentManager(config)
    run_id = manager.create_run()

    saved_path = manager.save_checkpoint(
      run_id,
      {
        "scenario": "R2",
        "attacker": "A1",
        "environment_type": "clean",
        "profile_name": "default",
        "completed_query_ids": ["q1"],
        "failed_query_ids": ["q2"],
        "index_manifest_ref": "data/indexes/clean/manifest.json",
      },
    )

    assert saved_path == manager.checkpoint_path(run_id)
    checkpoint = manager.load_checkpoint(run_id)
    assert checkpoint["run_id"] == run_id
    assert checkpoint["scenario"] == "R2"
    assert checkpoint["completed_query_ids"] == ["q1"]
    assert checkpoint["failed_query_ids"] == ["q2"]
    assert "updated_at" in checkpoint

  def test_save_and_load_partial_results(self, tmp_path):
    config = {"report": {"output_dir": str(tmp_path)}}
    manager = ExperimentManager(config)
    run_id = manager.create_run()
    partial_results = [
      {"query_id": "q1", "response": "masked answer 1"},
      {"query_id": "q2", "response": "masked answer 2"},
    ]

    saved_path = manager.save_partial_results(run_id, "R2", partial_results)

    assert saved_path == manager.partial_results_path(run_id, "R2")
    loaded_results = manager.load_partial_results(run_id, "R2")
    assert loaded_results == partial_results

  def test_save_and_load_partial_failures(self, tmp_path):
    config = {"report": {"output_dir": str(tmp_path)}}
    manager = ExperimentManager(config)
    run_id = manager.create_run()
    partial_failures = [
      {
        "scenario": "R2",
        "query_id": "q1",
        "query_masked": "[MASKED_QUERY]",
        "stage": "query_execute",
        "error_type": "RuntimeError",
        "error_message_masked": "[MASKED_ERROR]",
        "attempt_index": 1,
      }
    ]

    saved_path = manager.save_partial_failures(run_id, "R2", partial_failures)

    assert saved_path == manager.partial_failures_path(run_id, "R2")
    loaded_failures = manager.load_partial_failures(run_id, "R2")
    assert loaded_failures == partial_failures

  def test_save_and_load_suite_artifacts(self, tmp_path):
    config = {"report": {"output_dir": str(tmp_path)}}
    manager = ExperimentManager(config)
    run_id = manager.create_run()

    manifest_path = manager.save_suite_manifest(
      run_id,
      {
        "scenario_mode": "single",
        "planned_cells": ["R2__clean__reranker_off"],
      },
    )
    checkpoint_path = manager.save_suite_checkpoint(
      run_id,
      {
        "scenario_mode": "single",
        "planned_cells": ["R2__clean__reranker_off"],
        "completed_cells": [],
        "failed_cells": [],
      },
    )

    assert manifest_path == manager.suite_manifest_path(run_id)
    assert checkpoint_path == manager.suite_checkpoint_path(run_id)
    assert manager.load_suite_manifest(run_id)["planned_cells"] == [
      "R2__clean__reranker_off"
    ]
    assert manager.load_suite_checkpoint(run_id)["run_id"] == run_id


class TestReportGenerator:
  def test_nonexistent_run_id(self, tmp_path):
    gen = ReportGenerator({"report": {"output_formats": ["json"], "output_dir": str(tmp_path)}})
    with pytest.raises(FileNotFoundError):
      gen.generate("NONEXISTENT-ID")

  def test_risk_assessment(self, tmp_path):
    gen = ReportGenerator({"report": {"output_formats": ["json"], "output_dir": str(tmp_path)}})
    assert "CRITICAL" in gen._assess_risk_level({"R2": {"success_rate": 0.6}})
    assert "HIGH" in gen._assess_risk_level({"R4": {"is_inference_successful": True}})
    assert "LOW" in gen._assess_risk_level({"R2": {"success_rate": 0}, "R9": {"success_rate": 0}})

  def test_build_env_comparison_pairs_same_reranker_state(self, tmp_path):
    """clean ↔ poisoned 페어가 동일한 reranker 상태로 매칭되는지 검증한다.

    _build_env_comparison 은 입력으로 받은 scenario_results 안에서만
    페어를 찾으므로, clean 과 poisoned 결과를 같은 payload 의
    results 리스트에 함께 넣어 전달해야 한다.
    """
    gen = ReportGenerator({"report": {"output_formats": ["json"], "output_dir": str(tmp_path)}})

    combined_payload = {
      "total": 2,
      "success_count": 1,
      "success_rate": 0.5,
      "profile_name": "reranker_off",
      "retrieval_config": {
        "reranker": {"enabled": False, "model_name": "test-reranker", "top_k": 3},
      },
      "results": [
        _make_result(
          scenario="R2",
          query_id="R2:doc-1:tpl-00:rep-00",
          environment="clean",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=False,
          score=0.1,
          response="clean masked answer",
          pii_total=1,
          pii_by_tag={"QT_MOBILE": 1},
          has_high_risk=True,
          retrieved_ids=["doc-a", "doc-b"],
        ),
        _make_result(
          scenario="R2",
          query_id="R2:doc-1:tpl-00:rep-00",
          environment="poisoned",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=True,
          score=0.9,
          response="poisoned masked answer",
          pii_total=2,
          pii_by_tag={"QT_MOBILE": 1, "TMI_EMAIL": 1},
          has_high_risk=True,
          retrieved_ids=["doc-b", "doc-a"],
        ),
      ],
    }

    _write_run(tmp_path, "RAG-2026-0425-001", "R2", combined_payload)

    comparison = gen._build_env_comparison("RAG-2026-0425-001", {"R2": combined_payload})
    assert comparison["R2"]["matched_query_count"] == 1
    assert comparison["R2"]["base_env"] == "clean"
    assert comparison["R2"]["paired_env"] == "poisoned"
    assert comparison["R2"]["pairs"][0]["base_reranker_state"] == "off"
    assert comparison["R2"]["pairs"][0]["paired_reranker_state"] == "off"

  def test_build_reranker_comparison_pairs_same_environment(self, tmp_path):
    """reranker_off ↔ reranker_on 페어가 동일 환경에서 매칭되는지 검증한다.

    _build_reranker_comparison 도 단일 payload 의 results 리스트
    안에서 페어를 찾으므로 두 reranker 상태의 결과를 합쳐 전달한다.
    """
    gen = ReportGenerator({"report": {"output_formats": ["json"], "output_dir": str(tmp_path)}})

    combined_payload = {
      "total": 2,
      "success_count": 1,
      "success_rate": 0.5,
      "profile_name": "reranker_off",
      "retrieval_config": {
        "reranker": {"enabled": False, "model_name": "test-reranker", "top_k": 3},
      },
      "results": [
        _make_result(
          scenario="R2",
          query_id="R2:doc-1:tpl-00:rep-00",
          environment="clean",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=False,
          score=0.2,
          response="off masked answer",
          pii_total=1,
          pii_by_tag={"QT_MOBILE": 1},
          has_high_risk=True,
          retrieved_ids=["doc-a", "doc-b"],
        ),
        _make_result(
          scenario="R2",
          query_id="R2:doc-1:tpl-00:rep-00",
          environment="clean",
          reranker_enabled=True,
          profile_name="reranker_on",
          success=True,
          score=0.7,
          response="on masked answer",
          pii_total=0,
          pii_by_tag={},
          retrieved_ids=["doc-b", "doc-a"],
        ),
      ],
    }

    _write_run(tmp_path, "RAG-2026-0425-010", "R2", combined_payload)

    comparison = gen._build_reranker_comparison("RAG-2026-0425-010", {"R2": combined_payload})
    assert comparison["R2"]["matched_query_count"] == 1
    assert comparison["R2"]["base_reranker_state"] == "off"
    assert comparison["R2"]["paired_reranker_state"] == "on"
    assert comparison["R2"]["pairs"][0]["base_env"] == "clean"

  def test_build_env_comparison_prefers_same_run_pairs(self, tmp_path):
    gen = ReportGenerator({"report": {"output_formats": ["json"], "output_dir": str(tmp_path)}})

    suite_payload = {
      "total": 2,
      "success_count": 1,
      "success_rate": 0.5,
      "profile_name": "mixed",
      "retrieval_config": {},
      "results": [
        _make_result(
          scenario="R2",
          query_id="R2:q1",
          environment="clean",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=False,
          score=0.1,
          response="clean answer",
          retrieved_ids=["doc-a", "doc-b"],
        ),
        _make_result(
          scenario="R2",
          query_id="R2:q1",
          environment="poisoned",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=True,
          score=0.9,
          response="poisoned answer",
          retrieved_ids=["doc-b", "doc-a"],
        ),
      ],
    }

    _write_run(tmp_path, "RAG-2026-0425-100", "R2", suite_payload)

    comparison = gen._build_env_comparison("RAG-2026-0425-100", {"R2": suite_payload})
    # clean 1건과 poisoned 1건이 같은 query_id 로 묶여 페어 1개를 형성한다.
    assert comparison["R2"]["matched_query_count"] == 1

  def test_build_reranker_comparison_prefers_same_run_pairs(self, tmp_path):
    gen = ReportGenerator({"report": {"output_formats": ["json"], "output_dir": str(tmp_path)}})

    suite_payload = {
      "total": 2,
      "success_count": 1,
      "success_rate": 0.5,
      "profile_name": "mixed",
      "retrieval_config": {},
      "results": [
        _make_result(
          scenario="R2",
          query_id="R2:q2",
          environment="clean",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=False,
          score=0.1,
          response="off answer",
          retrieved_ids=["doc-a", "doc-b"],
        ),
        _make_result(
          scenario="R2",
          query_id="R2:q2",
          environment="clean",
          reranker_enabled=True,
          profile_name="reranker_on",
          success=True,
          score=0.8,
          response="on answer",
          retrieved_ids=["doc-b", "doc-a"],
        ),
      ],
    }

    _write_run(tmp_path, "RAG-2026-0425-101", "R2", suite_payload)

    comparison = gen._build_reranker_comparison("RAG-2026-0425-101", {"R2": suite_payload})
    # reranker_off 1건과 reranker_on 1건이 같은 query_id 로 묶여 페어 1개를 형성한다.
    assert comparison["R2"]["matched_query_count"] == 1

  def test_generate_report_outputs_comparison_sections(self, tmp_path):
    """generate() 통합 흐름에서 두 비교 섹션이 모두 채워지는지 검증한다.

    _build_env_comparison / _build_reranker_comparison 은 단일 run 의
    R2_result.json 안의 results 리스트만 보고 페어를 찾으므로,
    clean(off) · poisoned(off) · clean(on) 세 결과를 한 results 리스트에
    함께 담아 저장한다.
    """
    config = {
      "report": {
        "output_formats": ["json", "csv"],
        "output_dir": str(tmp_path),
      },
    }
    gen = ReportGenerator(config)

    combined_payload = {
      "total": 3,
      "success_count": 2,
      "success_rate": 2 / 3,
      "avg_score": 0.6,
      "max_score": 0.9,
      "threshold": 0.7,
      "profile_name": "reranker_off",
      "scenario_scope": "base",
      "dataset_scope": "clean/base",
      "index_manifest_ref": "data/indexes/clean/base/reranker_off/manifest.json",
      "status": "partial",
      "execution_failures": [
        {
          "scenario": "R2",
          "query_id": "R2:doc-1:tpl-00:rep-00",
          "query_masked": "[MASKED_QUERY]",
          "stage": "query_execute",
          "error_type": "RuntimeError",
          "error_message_masked": "[MASKED_ERROR]",
          "attempt_index": 1,
          "environment_type": "clean",
          "profile_name": "reranker_off",
          "scenario_scope": "base",
          "dataset_scope": "clean/base",
          "index_manifest_ref": "data/indexes/clean/base/reranker_off/manifest.json",
          "suite_run_id": "",
          "suite_cell_id": "",
          "replayed_from_run_id": "",
          "failed_at": "2026-04-25T00:00:00",
          "metadata": {},
        }
      ],
      "execution_failure_count": 1,
      "open_failure_count": 1,
      "failure_stage_counts": {"query_execute": 1},
      "retrieval_config": {
        "reranker": {"enabled": False, "model_name": "test-reranker", "top_k": 3},
      },
      "results": [
        # clean × reranker_off  ← env 비교의 base
        _make_result(
          scenario="R2",
          query_id="R2:doc-1:tpl-00:rep-00",
          environment="clean",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=False,
          score=0.1,
          response="current masked answer",
          response_masked="current masked answer",
          pii_total=2,
          pii_by_tag={"QT_MOBILE": 1, "TMI_EMAIL": 1},
          has_high_risk=True,
          retrieved_ids=["doc-a", "doc-b"],
        ),
        # poisoned × reranker_off  ← env 비교의 paired
        _make_result(
          scenario="R2",
          query_id="R2:doc-1:tpl-00:rep-00",
          environment="poisoned",
          reranker_enabled=False,
          profile_name="reranker_off",
          success=True,
          score=0.9,
          response="poisoned counterpart masked",
          response_masked="poisoned counterpart masked",
          pii_total=1,
          pii_by_tag={"QT_MOBILE": 1},
          has_high_risk=True,
          retrieved_ids=["doc-b", "doc-a"],
        ),
        # clean × reranker_on  ← reranker 비교의 paired
        _make_result(
          scenario="R2",
          query_id="R2:doc-1:tpl-00:rep-00",
          environment="clean",
          reranker_enabled=True,
          profile_name="reranker_on",
          success=True,
          score=0.8,
          response="reranked counterpart masked",
          response_masked="reranked counterpart masked",
          pii_total=0,
          pii_by_tag={},
          retrieved_ids=["doc-b", "doc-a"],
        ),
      ],
    }

    _write_run(tmp_path, "RAG-2026-0425-020", "R2", combined_payload)

    files = gen.generate("RAG-2026-0425-020")
    assert files["json"].exists()
    assert files["csv"].exists()

    with open(files["json"], "r", encoding="utf-8") as file:
      summary = json.load(file)

    assert "clean_vs_poisoned_comparison" in summary
    assert "reranker_on_off_comparison" in summary
    assert summary["experiment"]["dataset_scope"] == "clean/base"
    assert summary["clean_vs_poisoned_comparison"]["R2"]["matched_query_count"] == 1
    assert summary["reranker_on_off_comparison"]["R2"]["matched_query_count"] == 1
    # 통합 payload: clean(pii=2) + poisoned(pii=1) + reranker_on(pii=0) = 합계 3건
    assert summary["pii_leakage_profile"]["R2"]["total_pii_count"] == 3
    # high_risk 응답은 clean(off) 과 poisoned(off) 두 건이다.
    assert summary["pii_leakage_profile"]["R2"]["responses_with_high_risk"] == 2
    assert summary["scenario_results"]["R2"]["dataset_scope"] == "clean/base"
    assert "manifest.json" in summary["scenario_results"]["R2"]["index_manifest_ref"]
    assert summary["execution_reliability"]["scenarios"]["R2"]["execution_failure_count"] == 1
    assert summary["execution_reliability"]["scenarios"]["R2"]["status"] == "partial"

    with open(files["csv"], "r", encoding="utf-8-sig") as file:
      csv_text = file.read()
    assert "dataset_scope" in csv_text
    assert "response_masked" in csv_text
    assert "run_status" in csv_text
    assert "execution_failure_count" in csv_text
    assert "current masked answer" in csv_text

  def test_generate_report_handles_failure_only_result(self, tmp_path):
    config = {
      "report": {
        "output_formats": ["json", "csv"],
        "output_dir": str(tmp_path),
      },
    }
    gen = ReportGenerator(config)

    failure_only_payload = {
      "total": 0,
      "success_count": 0,
      "success_rate": 0.0,
      "avg_score": 0.0,
      "max_score": 0.0,
      "threshold": 0.7,
      "profile_name": "reranker_off",
      "scenario_scope": "R2",
      "dataset_scope": "poisoned/R2",
      "index_manifest_ref": "data/indexes/poisoned/R2/reranker_off/manifest.json",
      "status": "failed_setup",
      "execution_failures": [
        {
          "scenario": "R2",
          "query_id": "",
          "query_masked": "[MASKED_QUERY]",
          "stage": "index_load",
          "error_type": "RuntimeError",
          "error_message_masked": "[MASKED_ERROR]",
          "attempt_index": 1,
          "environment_type": "poisoned",
          "profile_name": "reranker_off",
          "scenario_scope": "R2",
          "dataset_scope": "poisoned/R2",
          "index_manifest_ref": "data/indexes/poisoned/R2/reranker_off/manifest.json",
          "suite_run_id": "",
          "suite_cell_id": "",
          "replayed_from_run_id": "",
          "failed_at": "2026-04-25T00:00:00",
          "metadata": {},
        }
      ],
      "execution_failure_count": 1,
      "open_failure_count": 1,
      "failure_stage_counts": {"index_load": 1},
      "planned_query_count": 1,
      "completed_query_ids": [],
      "failed_query_ids": [],
      "results": [],
      "retrieval_config": {
        "reranker": {"enabled": False, "model_name": "test-reranker", "top_k": 3},
      },
    }

    _write_run(tmp_path, "RAG-2026-0425-030", "R2", failure_only_payload)
    files = gen.generate("RAG-2026-0425-030")

    with open(files["json"], "r", encoding="utf-8") as file:
      summary = json.load(file)

    assert summary["execution_reliability"]["scenarios"]["R2"]["status"] == "failed_setup"
    assert summary["execution_reliability"]["scenarios"]["R2"]["open_failure_count"] == 1


# ============================================================
# NORMAL vs 공격 시나리오 PII 비교 집계 테스트
# ============================================================

class TestNormalVsAttackPiiComparison:
  """ReportGenerator._build_normal_attack_pii_comparison 의 baseline/공격 PII 집계를 검증한다."""

  def _gen(self, tmp_path) -> ReportGenerator:
    return ReportGenerator(
      {"report": {"output_formats": ["json"], "output_dir": str(tmp_path)}}
    )

  def _result(self, *, reranker_state: str, total: int, high_risk: bool) -> dict:
    """NormalEvaluator / 평가기들이 만들어내는 결과 dict 와 동일한 최소 구조를 반환한다."""
    return {
      "environment_type": "clean",
      "metadata": {"reranker_state": reranker_state, "env": "clean"},
      "pii_summary": {"total": total, "has_high_risk": high_risk},
      "pii_findings": [{"risk_level": "high" if high_risk else "low"}] * total,
      "success": False,
      "score": 0.0,
      "query_id": f"q-{reranker_state}-{total}",
      "response": "응답",
    }

  def _scenario_data(self, results: list[dict]) -> dict:
    return {"results": results}

  def test_returns_empty_when_normal_missing(self, tmp_path):
    """NORMAL 결과가 없으면 빈 dict 를 반환해야 한다 (단일 공격 실행 보고서)."""
    gen = self._gen(tmp_path)
    out = gen._build_normal_attack_pii_comparison({"R2": self._scenario_data([])})
    assert out == {}

  def test_compares_all_four_attack_scenarios(self, tmp_path):
    """R2/R4/R7/R9 가 모두 NORMAL 과 비교되어야 한다."""
    gen = self._gen(tmp_path)
    sr = {
      "NORMAL": self._scenario_data([
        self._result(reranker_state="off", total=1, high_risk=False),
        self._result(reranker_state="on", total=0, high_risk=False),
      ]),
      "R2": self._scenario_data([
        self._result(reranker_state="off", total=4, high_risk=True),
        self._result(reranker_state="on", total=3, high_risk=True),
      ]),
      "R4": self._scenario_data([
        self._result(reranker_state="off", total=2, high_risk=False),
      ]),
      "R7": self._scenario_data([
        self._result(reranker_state="on", total=1, high_risk=False),
      ]),
      "R9": self._scenario_data([
        self._result(reranker_state="off", total=5, high_risk=True),
      ]),
    }
    out = gen._build_normal_attack_pii_comparison(sr)
    assert set(out.keys()) == {"R2", "R4", "R7", "R9"}

  def test_baseline_and_attack_totals_match_inputs(self, tmp_path):
    """baseline / attack 의 총 PII 수가 입력 결과와 일치해야 한다."""
    gen = self._gen(tmp_path)
    sr = {
      "NORMAL": self._scenario_data([
        self._result(reranker_state="off", total=1, high_risk=False),
        self._result(reranker_state="off", total=0, high_risk=False),
        self._result(reranker_state="on", total=2, high_risk=True),
      ]),
      "R2": self._scenario_data([
        self._result(reranker_state="off", total=4, high_risk=True),
        self._result(reranker_state="off", total=3, high_risk=True),
        self._result(reranker_state="on", total=5, high_risk=True),
      ]),
    }
    out = gen._build_normal_attack_pii_comparison(sr)
    entry = out["R2"]
    assert entry["baseline"]["total_pii_count"] == 3
    assert entry["attack"]["total_pii_count"] == 12
    assert entry["pii_delta_total"] == 9.0
    # 응답당 평균 변화: 12/3 - 3/3 = 4 - 1 = 3
    assert entry["pii_delta_avg_per_response"] == 3.0
    # 비율: 12 / 3 = 4.0
    assert entry["pii_total_ratio"] == 4.0

  def test_response_rate_and_high_risk_deltas(self, tmp_path):
    """PII 포함 응답률 / 고위험 응답률 차이가 baseline 대비 정확히 계산되어야 한다."""
    gen = self._gen(tmp_path)
    sr = {
      "NORMAL": self._scenario_data([
        self._result(reranker_state="off", total=0, high_risk=False),
        self._result(reranker_state="off", total=0, high_risk=False),
        self._result(reranker_state="off", total=1, high_risk=False),
        self._result(reranker_state="off", total=2, high_risk=True),
      ]),
      "R2": self._scenario_data([
        self._result(reranker_state="off", total=3, high_risk=True),
        self._result(reranker_state="off", total=2, high_risk=True),
        self._result(reranker_state="off", total=1, high_risk=True),
        self._result(reranker_state="off", total=4, high_risk=True),
      ]),
    }
    out = gen._build_normal_attack_pii_comparison(sr)
    entry = out["R2"]
    # baseline: 2/4 응답에 PII, 1/4 응답이 고위험. R2: 4/4 응답에 PII, 4/4 고위험.
    assert entry["response_rate_delta"] == 0.5
    assert entry["high_risk_rate_delta"] == 0.75

  def test_by_reranker_subcomparison(self, tmp_path):
    """reranker off/on 별 하위 비교(by_reranker)가 생성되어야 한다."""
    gen = self._gen(tmp_path)
    sr = {
      "NORMAL": self._scenario_data([
        self._result(reranker_state="off", total=1, high_risk=False),
        self._result(reranker_state="on", total=2, high_risk=False),
      ]),
      "R2": self._scenario_data([
        self._result(reranker_state="off", total=4, high_risk=True),
        self._result(reranker_state="on", total=5, high_risk=True),
      ]),
    }
    out = gen._build_normal_attack_pii_comparison(sr)
    by_state = out["R2"]["by_reranker"]
    assert set(by_state.keys()) == {"off", "on"}
    assert by_state["off"]["baseline"]["total_pii_count"] == 1
    assert by_state["off"]["attack"]["total_pii_count"] == 4
    assert by_state["on"]["baseline"]["total_pii_count"] == 2
    assert by_state["on"]["attack"]["total_pii_count"] == 5
