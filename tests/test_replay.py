"""Tests for snapshot replay and provenance audit flows."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from rag.attack.base import AttackResult
from rag.cli import main as cli_main
from rag.pii.eval import serialize_eval_snapshot
from rag.utils.experiment import ExperimentManager

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "pii_eval_fixture.jsonl"


def _base_config(results_dir: Path) -> dict:
  return {
    "report": {
      "output_dir": str(results_dir),
      "mask_raw_pii": True,
      "persist_raw_response": False,
    },
    "attack": {"doc_path": "data/documents"},
    "embedding": {"model_name": "test-embedding"},
    "reranker": {"model_name": "test-reranker"},
    "retrieval_config": {
      "top_k": 5,
      "similarity_threshold": 0.0,
      "reranker": {
        "enabled": False,
        "model_name": "test-reranker",
        "top_k": 3,
      },
    },
    "experiment": {"random_seed": 42},
    "pii": {
      "runtime": {"enable_step3": False, "enable_step4": False},
      "ner": {"model_path": "townboy/kpfbert-kdpii"},
      "sllm": {"model": "gpt-4o-mini"},
      "eval": {"label_schema_version": "kdpii-33-v1", "error_context_chars": 12},
    },
  }


def _write_manifest(path: Path, *, dataset_scope: str) -> dict:
  path.parent.mkdir(parents=True, exist_ok=True)
  payload = {
    "backend": "faiss",
    "index_version": "faiss-v2",
    "environment_type": dataset_scope.split("/", 1)[0],
    "scenario_scope": dataset_scope.split("/", 1)[1],
    "dataset_scope": dataset_scope,
    "doc_count": 1,
  }
  with open(path, "w", encoding="utf-8") as file:
    json.dump(payload, file, ensure_ascii=False, indent=2)
  return payload


def _remove_provenance(snapshot_path: Path) -> None:
  with open(snapshot_path, "r", encoding="utf-8") as file:
    payload = yaml.safe_load(file) or {}
  payload.pop("config_fingerprint", None)
  payload.pop("provenance", None)
  with open(snapshot_path, "w", encoding="utf-8") as file:
    yaml.safe_dump(payload, file, allow_unicode=True, sort_keys=False)


def _fake_single_executor(
  config,
  *,
  scenario,
  attacker,
  env,
  profile,
  exp_manager,
  run_id=None,
  resume_existing=False,
  snapshot_metadata=None,
  suite_context=None,
  replay_context=None,
):
  actual_run_id = str(run_id)
  exp_manager.save_snapshot(actual_run_id, config, metadata=snapshot_metadata)
  summary = {
    "total": 0,
    "results": [],
    "profile_name": profile,
    "retrieval_config": config.get("retrieval_config", {}),
    "reranker_state": (
      "on"
      if config.get("retrieval_config", {}).get("reranker", {}).get("enabled")
      else "off"
    ),
  }
  if suite_context:
    summary.update(suite_context)
  if replay_context:
    summary.update(replay_context)
  exp_manager.save_result(actual_run_id, summary, f"{scenario.upper()}_result.json")
  return cli_main.SingleRunOutcome(
    run_id=actual_run_id,
    scenario=scenario.upper(),
    environment_type=env,
    profile_name=profile,
    status="completed",
    summary=summary,
  )


def _fake_suite_summary(
  *,
  scenario: str,
  env: str,
  profile: str,
  suite_run_id: str,
  cell_id: str,
  replayed_from_run_id: str,
) -> dict:
  reranker_enabled = profile == "reranker_on"
  dataset_scope = "clean/base" if env == "clean" else f"poisoned/{scenario}"
  result = AttackResult(
    scenario=scenario,
    query=f"query:{cell_id}",
    response="masked response",
    query_id=f"{scenario}:q1",
    environment_type=env,
    profile_name=profile,
    scenario_scope="base" if env == "clean" else scenario,
    dataset_scope=dataset_scope,
    dataset_selection_mode="canonical",
    index_manifest_ref=f"data/indexes/{dataset_scope}/{profile}/manifest.json",
    suite_run_id=suite_run_id,
    suite_cell_id=cell_id,
    cell_environment=env,
    cell_profile_name=profile,
    replayed_from_run_id=replayed_from_run_id,
    success=True,
    score=1.0,
    retrieval_config={
      "reranker": {
        "enabled": reranker_enabled,
        "model_name": "test-reranker",
        "top_k": 3,
      }
    },
    metadata={
      "env": env,
      "query_id": f"{scenario}:q1",
      "profile_name": profile,
      "reranker_enabled": reranker_enabled,
      "reranker_state": "on" if reranker_enabled else "off",
      "replayed_from_run_id": replayed_from_run_id,
    },
  )
  return {
    "total": 1,
    "success_count": 1,
    "success_rate": 1.0,
    "avg_score": 1.0,
    "max_score": 1.0,
    "threshold": 0.7,
    "profile_name": profile,
    "retrieval_config": result.retrieval_config,
    "reranker_state": "on" if reranker_enabled else "off",
    "scenario_scope": result.scenario_scope,
    "dataset_scope": result.dataset_scope,
    "index_manifest_ref": result.index_manifest_ref,
    "completed_query_ids": [result.query_id],
    "failed_query_ids": [],
    "planned_query_count": 1,
    "replayed_from_run_id": replayed_from_run_id,
    "results": [result],
  }


def _fake_suite_executor(
  config,
  *,
  scenario,
  attacker,
  env,
  profile,
  exp_manager,
  run_id=None,
  resume_existing=False,
  snapshot_metadata=None,
  suite_context=None,
  replay_context=None,
):
  actual_run_id = str(run_id)
  exp_manager.save_snapshot(actual_run_id, config, metadata=snapshot_metadata)
  summary = _fake_suite_summary(
    scenario=scenario,
    env=env,
    profile=profile,
    suite_run_id=suite_context["suite_run_id"],
    cell_id=suite_context["suite_cell_id"],
    replayed_from_run_id=replay_context["replayed_from_run_id"],
  )
  exp_manager.save_result(
    actual_run_id,
    cli_main._serialize_summary(summary),
    f"{scenario.upper()}_result.json",
  )
  return cli_main.SingleRunOutcome(
    run_id=actual_run_id,
    scenario=scenario.upper(),
    environment_type=env,
    profile_name=profile,
    status="completed",
    summary=summary,
  )


def test_replay_single_run_creates_new_run_and_audit(tmp_path, monkeypatch):
  results_dir = tmp_path / "results"
  config = _base_config(results_dir)
  manager = ExperimentManager(config)
  source_run_id = manager.create_run()
  manifest_path = tmp_path / "indexes" / "clean" / "base" / "default" / "manifest.json"
  manifest = _write_manifest(manifest_path, dataset_scope="clean/base")

  manager.save_snapshot(
    source_run_id,
    config,
    metadata={
      "runtime": {
        "scenario": "R2",
        "attacker": "A1",
        "environment_type": "clean",
        "profile_name": "default",
      },
      "index_manifest_ref": str(manifest_path),
      "index_manifest": manifest,
    },
  )
  _remove_provenance(manager.run_dir(source_run_id) / "snapshot.yaml")

  runner = CliRunner()
  monkeypatch.setattr(cli_main, "load_config", lambda config_path=None: config)
  monkeypatch.setattr(cli_main, "_execute_single_run", _fake_single_executor)

  result = runner.invoke(cli_main.app, ["replay", "--run-id", source_run_id])

  assert result.exit_code == 0, result.stdout
  replay_dirs = sorted(path for path in results_dir.iterdir() if path.is_dir())
  assert len(replay_dirs) == 2
  replay_dir = next(path for path in replay_dirs if path.name != source_run_id)

  with open(replay_dir / "snapshot.yaml", "r", encoding="utf-8") as file:
    replay_snapshot = yaml.safe_load(file)
  with open(replay_dir / "replay_audit.json", "r", encoding="utf-8") as file:
    audit = json.load(file)
  with open(replay_dir / "R2_result.json", "r", encoding="utf-8") as file:
    summary = json.load(file)

  assert replay_snapshot["replayed_from_run_id"] == source_run_id
  assert replay_snapshot["compatibility_mode"] is True
  assert audit["source_run_type"] == "single"
  assert audit["compatibility_mode"] is True
  assert audit["index_manifest_match"] is True
  assert audit["snapshot_diff"] or audit["provenance_diff"]
  assert summary["replayed_from_run_id"] == source_run_id


def test_replay_suite_run_creates_parent_and_child_runs(tmp_path, monkeypatch):
  results_dir = tmp_path / "results"
  config = _base_config(results_dir)
  manager = ExperimentManager(config)
  source_run_id = manager.create_run()
  cells = [
    cli_main.SuiteCell("R2", "clean", "reranker_off"),
    cli_main.SuiteCell("R2", "poisoned", "reranker_on"),
  ]

  suite_metadata = {
    "scenario_mode": "single",
    "attacker": "A1",
    "scenarios": ["R2"],
    "environments": ["clean", "poisoned"],
    "profiles": ["reranker_off", "reranker_on"],
    "planned_cells": [cell.to_dict() for cell in cells],
    "status": "completed",
  }
  manager.save_snapshot(source_run_id, config, metadata={"suite": suite_metadata})

  source_child_root = manager.run_dir(source_run_id) / "runs"
  child_manager = ExperimentManager(config, results_dir_override=source_child_root)
  for cell in cells:
    manifest_path = (
      tmp_path
      / "indexes"
      / cell.environment_type
      / ("base" if cell.environment_type == "clean" else cell.scenario)
      / cell.profile_name
      / "manifest.json"
    )
    manifest = _write_manifest(
      manifest_path,
      dataset_scope=(
        "clean/base"
        if cell.environment_type == "clean"
        else f"poisoned/{cell.scenario}"
      ),
    )
    child_config = dict(config)
    child_config["profile_name"] = cell.profile_name
    child_config["retrieval_config"] = {
      "reranker": {
        "enabled": cell.profile_name == "reranker_on",
        "model_name": "test-reranker",
        "top_k": 3,
      }
    }
    child_manager.save_snapshot(
      cell.cell_id,
      child_config,
      metadata={
        "runtime": {
          "scenario": cell.scenario,
          "attacker": "A1",
          "environment_type": cell.environment_type,
          "profile_name": cell.profile_name,
        },
        "index_manifest_ref": str(manifest_path),
        "index_manifest": manifest,
      },
    )

  runner = CliRunner()
  monkeypatch.setattr(cli_main, "load_config", lambda config_path=None: config)
  monkeypatch.setattr(cli_main, "_execute_single_run", _fake_suite_executor)

  result = runner.invoke(cli_main.app, ["replay", "--run-id", source_run_id])

  assert result.exit_code == 0, result.stdout
  replay_dir = next(path for path in results_dir.iterdir() if path.name != source_run_id)
  with open(replay_dir / "replay_audit.json", "r", encoding="utf-8") as file:
    audit = json.load(file)
  with open(replay_dir / "R2_result.json", "r", encoding="utf-8") as file:
    summary = json.load(file)

  assert audit["source_run_type"] == "suite"
  assert audit["index_manifest_match"] is True
  assert summary["replayed_from_run_id"] == source_run_id
  for cell in cells:
    assert (replay_dir / "runs" / cell.cell_id / "snapshot.yaml").exists()


def test_replay_pii_eval_recreates_artifacts(tmp_path, monkeypatch):
  results_dir = tmp_path / "results"
  config = _base_config(results_dir)
  manager = ExperimentManager(config)
  source_run_id = manager.create_run(prefix="PII-EVAL")

  manager.save_snapshot(
    source_run_id,
    config,
    metadata=serialize_eval_snapshot(
      dataset_manifest={
        "dataset_path": str(FIXTURE_PATH),
        "dataset_name": FIXTURE_PATH.name,
        "dataset_hash": "seed",
        "sample_count": 2,
        "entity_count": 3,
        "tag_counts": {"TMI_EMAIL": 2},
      },
      modes=["step1"],
      label_schema_version="kdpii-33-v1",
    ),
  )

  runner = CliRunner()
  monkeypatch.setattr(cli_main, "load_config", lambda config_path=None: config)

  result = runner.invoke(cli_main.app, ["replay", "--run-id", source_run_id])

  assert result.exit_code == 0, result.stdout
  replay_dir = next(path for path in results_dir.iterdir() if path.name != source_run_id)
  assert replay_dir.name.startswith("PII-EVAL-")
  assert (replay_dir / "pii_eval_summary.json").exists()
  assert (replay_dir / "replay_audit.json").exists()

  with open(replay_dir / "pii_eval_summary.json", "r", encoding="utf-8") as file:
    summary = json.load(file)
  assert summary["replayed_from_run_id"] == source_run_id
  assert summary["mode"] == "step1"


def test_replay_fails_on_index_manifest_mismatch(tmp_path, monkeypatch):
  results_dir = tmp_path / "results"
  config = _base_config(results_dir)
  manager = ExperimentManager(config)
  source_run_id = manager.create_run()
  manifest_path = tmp_path / "indexes" / "clean" / "base" / "default" / "manifest.json"
  _write_manifest(manifest_path, dataset_scope="clean/base")
  mismatched_manifest = {
    "backend": "faiss",
    "index_version": "faiss-v2",
    "environment_type": "clean",
    "scenario_scope": "base",
    "dataset_scope": "clean/base",
    "doc_count": 999,
  }

  manager.save_snapshot(
    source_run_id,
    config,
    metadata={
      "runtime": {
        "scenario": "R2",
        "attacker": "A1",
        "environment_type": "clean",
        "profile_name": "default",
      },
      "index_manifest_ref": str(manifest_path),
      "index_manifest": mismatched_manifest,
    },
  )

  runner = CliRunner()
  monkeypatch.setattr(cli_main, "load_config", lambda config_path=None: config)

  result = runner.invoke(cli_main.app, ["replay", "--run-id", source_run_id])

  assert result.exit_code == 1
  assert "does not match the saved snapshot" in result.stdout
