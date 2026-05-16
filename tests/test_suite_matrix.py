"""Tests for suite matrix orchestration helpers."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from rag.attack.base import AttackResult
from rag.cli import main as cli_main
from rag.utils.experiment import ExperimentManager


def _base_config(tmp_path) -> dict:
  # NORMAL 도입 후 정책:
  #   - NORMAL/R2/R4/R7 → clean DB (NORMAL 이 공통 baseline)
  #   - R9              → poisoned DB
  return {
    "report": {
      "output_dir": str(tmp_path / "results"),
      "compare_scope": "suite_first",
    },
    "experiment": {
      "matrix": {
        "environments": ["clean", "poisoned"],
        "profiles": ["reranker_off", "reranker_on"],
        "scenarios": ["NORMAL", "R2", "R4", "R7", "R9"],
        "scenario_environments": {
          "NORMAL": ["clean"],
          "R2": ["clean"],
          "R4": ["clean"],
          "R7": ["clean"],
          "R9": ["poisoned"],
        },
      }
    },
    "evaluator": {
      "r2": {"rouge_threshold": 0.7},
      "r4": {"hit_rate_threshold": 0.5},
      "r9": {"trigger_marker": "[R9_ATTACK_SUCCESS_777]"},
    },
  }


def _fake_child_summary(
  *,
  scenario: str,
  env: str,
  profile: str,
  suite_run_id: str,
  cell_id: str,
) -> dict:
  reranker_enabled = profile == "reranker_on"
  reranker_state = "on" if reranker_enabled else "off"
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
      "reranker_state": reranker_state,
      "scenario_scope": "base" if env == "clean" else scenario,
      "dataset_scope": dataset_scope,
      "suite_run_id": suite_run_id,
      "suite_cell_id": cell_id,
      "cell_environment": env,
      "cell_profile_name": profile,
      "attacker": "A1",
      "trial_index": 0,
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
    "reranker_state": reranker_state,
    "scenario_scope": "base" if env == "clean" else scenario,
    "dataset_scope": dataset_scope,
    "index_manifest_ref": result.index_manifest_ref,
    "completed_query_ids": [result.query_id],
    "failed_query_ids": [],
    "planned_query_count": 1,
    "results": [result],
  }


def test_build_suite_cells_counts(tmp_path):
  config = _base_config(tmp_path)

  # R2 단독 + all_envs: R2 는 clean 만 허용 → 1 env * 2 profiles = 2 셀
  r2_cells = cli_main._build_suite_cells(
    scenario="R2",
    env="clean",
    profile="default",
    all_envs=True,
    all_profiles=True,
    all_scenarios=False,
    config=config,
  )
  # all_scenarios + all_envs + all_profiles:
  #   NORMAL/R2/R4/R7 (clean, 4시나리오) + R9 (poisoned) = 5 시나리오 × 2 profiles = 10 셀
  ten_cells = cli_main._build_suite_cells(
    scenario=None,
    env="clean",
    profile="default",
    all_envs=True,
    all_profiles=True,
    all_scenarios=True,
    config=config,
  )

  assert len(r2_cells) == 2
  assert {c.environment_type for c in r2_cells} == {"clean"}

  assert len(ten_cells) == 10
  cell_ids = {f"{c.scenario}__{c.environment_type}__{c.profile_name}" for c in ten_cells}
  expected_cells = {
    f"{scenario}__clean__{profile}"
    for scenario in ("NORMAL", "R2", "R4", "R7")
    for profile in ("reranker_off", "reranker_on")
  } | {
    f"R9__poisoned__{profile}"
    for profile in ("reranker_off", "reranker_on")
  }
  assert cell_ids == expected_cells


def test_check_scenario_env_constraint_rejects_invalid_combos(tmp_path):
  """시나리오별 단일 환경 정책 위반 시 ValueError 가 발생하는지 확인한다."""
  import pytest

  config = _base_config(tmp_path)
  # 유효한 조합은 통과
  cli_main._check_scenario_env_constraint("clean", "NORMAL", config)
  cli_main._check_scenario_env_constraint("clean", "R7", config)
  cli_main._check_scenario_env_constraint("poisoned", "R9", config)
  # 금지 조합은 거부
  for env, scenario in [
    ("poisoned", "NORMAL"),
    ("poisoned", "R2"),
    ("poisoned", "R4"),
    ("poisoned", "R7"),
    ("clean", "R9"),
  ]:
    with pytest.raises(ValueError):
      cli_main._check_scenario_env_constraint(env, scenario, config)


def test_run_rejects_scenario_and_all_scenarios():
  runner = CliRunner()
  result = runner.invoke(cli_main.app, ["run", "--scenario", "R2", "--all-scenarios"])
  assert result.exit_code == 1
  assert "cannot be used together" in result.stdout


def test_ingest_rejects_poisoned_without_scenario():
  runner = CliRunner()
  result = runner.invoke(cli_main.app, ["ingest", "--env", "poisoned"])
  assert result.exit_code == 1
  # 새 정책: poisoned 는 R9 만 허용
  assert "--scenario R9" in result.stdout


def test_query_rejects_poisoned_without_scenario():
  runner = CliRunner()
  result = runner.invoke(
    cli_main.app,
    ["query", "--question", "hello", "--env", "poisoned"],
  )
  assert result.exit_code == 1
  assert "--scenario R9" in result.stdout


def test_ingest_rejects_rebuild_and_incremental_together():
  runner = CliRunner()
  result = runner.invoke(
    cli_main.app,
    ["ingest", "--env", "clean", "--rebuild", "--incremental"],
  )
  assert result.exit_code == 1
  assert "--rebuild" in result.stdout
  assert "--incremental" in result.stdout


def test_ingest_rejects_sync_delete_without_incremental():
  runner = CliRunner()
  result = runner.invoke(
    cli_main.app,
    ["ingest", "--env", "clean", "--sync-delete"],
  )
  assert result.exit_code == 1
  assert "--sync-delete" in result.stdout
  assert "--incremental" in result.stdout


def test_execute_suite_run_skips_completed_cells_on_resume(tmp_path, monkeypatch):
  base_config = _base_config(tmp_path)
  base_manager = ExperimentManager(base_config)
  suite_run_id = base_manager.create_run()
  cells = cli_main._build_suite_cells(
    scenario="R2",
    env="clean",
    profile="default",
    all_envs=True,
    all_profiles=True,
    all_scenarios=False,
    config=base_config,
  )

  base_manager.save_suite_manifest(
    suite_run_id,
    {
      "scenario_mode": "single",
      "attacker": "A1",
      "scenarios": ["R2"],
      "environments": ["clean", "poisoned"],
      "profiles": ["reranker_off", "reranker_on"],
      "planned_cells": [cell.to_dict() for cell in cells],
      "status": "running",
    },
  )
  base_manager.save_suite_checkpoint(
    suite_run_id,
    {
      "scenario_mode": "single",
      "planned_cells": [cell.cell_id for cell in cells],
      "completed_cells": [cells[0].cell_id],
      "failed_cells": [cells[1].cell_id],
      "status": "partial",
    },
  )

  child_root = base_manager.run_dir(suite_run_id) / "runs"
  child_manager = ExperimentManager(base_config, results_dir_override=child_root)
  child_manager.save_checkpoint(
    cells[1].cell_id,
    {
      "scenario": "R2",
      "attacker": "A1",
      "environment_type": cells[1].environment_type,
      "profile_name": cells[1].profile_name,
      "completed_query_ids": [],
      "failed_query_ids": [],
      "status": "partial",
    },
  )
  child_manager.save_snapshot(
    cells[1].cell_id,
    {"profile_name": cells[1].profile_name},
    metadata={
      "config": {"profile_name": cells[1].profile_name},
    },
  )

  def fake_load_config(config_path=None, profile="default"):
    config = dict(base_config)
    config["profile_name"] = profile
    config["retrieval_config"] = {
      "reranker": {
        "enabled": profile == "reranker_on",
        "model_name": "test-reranker",
        "top_k": 3,
      }
    }
    return config

  executed_cells: list[tuple[str, bool]] = []

  def fake_executor(
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
  ):
    actual_run_id = str(run_id)
    executed_cells.append((actual_run_id, resume_existing))
    summary = _fake_child_summary(
      scenario=scenario,
      env=env,
      profile=profile,
      suite_run_id=suite_context["suite_run_id"],
      cell_id=suite_context["suite_cell_id"],
    )
    exp_manager.save_snapshot(actual_run_id, config, metadata=snapshot_metadata)
    exp_manager.save_result(
      actual_run_id,
      cli_main._serialize_summary(summary),
      f"{scenario.upper()}_result.json",
    )
    exp_manager.save_checkpoint(
      actual_run_id,
      {
        "scenario": scenario.upper(),
        "attacker": attacker,
        "environment_type": env,
        "profile_name": profile,
        "completed_query_ids": [f"{scenario}:q1"],
        "failed_query_ids": [],
        "status": "completed",
      },
    )
    return cli_main.SingleRunOutcome(
      run_id=actual_run_id,
      scenario=scenario.upper(),
      environment_type=env,
      profile_name=profile,
      status="completed",
      summary=summary,
    )

  monkeypatch.setattr(cli_main, "load_config", fake_load_config)

  resumed_run_id = cli_main._execute_suite_run(
    base_config=base_config,
    base_exp_manager=base_manager,
    scenario=None,
    attacker="A1",
    env="clean",
    profile="default",
    all_envs=False,
    all_profiles=False,
    all_scenarios=False,
    resume=suite_run_id,
    config_path=None,
    single_run_executor=fake_executor,
  )

  # 새 정책에서 R2 단독 + all_envs 는 clean × 2 profiles = 2 셀.
  # cells[0]=완료(스킵), cells[1]=실패(재시도) → 재실행은 1개.
  assert resumed_run_id == suite_run_id
  assert len(executed_cells) == 1
  assert cells[0].cell_id not in [cell_id for cell_id, _ in executed_cells]
  assert (cells[1].cell_id, True) in executed_cells

  with open(base_manager.run_dir(suite_run_id) / "R2_result.json", "r", encoding="utf-8") as file:
    parent_summary = json.load(file)
  # cells[0] 은 completed_cells 에만 등록되어 있고 사전 저장된 결과 파일이 없으므로
  # 부모 합산에는 새로 실행된 cells[1] 결과 1건만 포함된다 (원래 4셀 가정에서는 미실행
  # 셀까지 새로 저장되어 3건이 되던 자리).
  assert parent_summary["total"] == 1
  assert all(result["suite_run_id"] == suite_run_id for result in parent_summary["results"])


def test_refresh_suite_results_aggregates_child_failures(tmp_path):
  base_config = _base_config(tmp_path)
  base_manager = ExperimentManager(base_config)
  suite_run_id = base_manager.create_run()
  child_root = base_manager.run_dir(suite_run_id) / "runs"
  child_manager = ExperimentManager(base_config, results_dir_override=child_root)

  success_summary = _fake_child_summary(
    scenario="R2",
    env="clean",
    profile="reranker_off",
    suite_run_id=suite_run_id,
    cell_id="R2__clean__reranker_off",
  )
  failed_summary = {
    "total": 0,
    "success_count": 0,
    "success_rate": 0.0,
    "avg_score": 0.0,
    "max_score": 0.0,
    "threshold": 0.7,
    "profile_name": "reranker_off",
    "retrieval_config": {
      "reranker": {"enabled": False, "model_name": "test-reranker", "top_k": 3},
    },
    "scenario_scope": "R2",
    "dataset_scope": "poisoned/R2",
    "index_manifest_ref": "data/indexes/poisoned/R2/reranker_off/manifest.json",
    "completed_query_ids": [],
    "failed_query_ids": [],
    "planned_query_count": 1,
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
        "suite_run_id": suite_run_id,
        "suite_cell_id": "R2__poisoned__reranker_off",
        "replayed_from_run_id": "",
        "failed_at": "2026-04-25T00:00:00",
        "metadata": {},
      }
    ],
    "execution_failure_count": 1,
    "open_failure_count": 1,
    "failure_stage_counts": {"index_load": 1},
    "results": [],
    "suite_run_id": suite_run_id,
  }

  child_manager.save_result(
    "R2__clean__reranker_off",
    cli_main._serialize_summary(success_summary),
    "R2_result.json",
  )
  child_manager.save_result(
    "R2__poisoned__reranker_off",
    cli_main._serialize_summary(failed_summary),
    "R2_result.json",
  )

  cli_main._refresh_suite_results(
    base_manager,
    suite_run_id=suite_run_id,
    config=base_config,
  )

  with open(base_manager.run_dir(suite_run_id) / "R2_result.json", "r", encoding="utf-8") as file:
    parent_summary = json.load(file)

  assert parent_summary["total"] == 1
  assert parent_summary["execution_failure_count"] == 1
  assert parent_summary["failure_stage_counts"] == {"index_load": 1}
  assert parent_summary["failed_cell_count"] == 1
  assert parent_summary["status"] == "partial"
