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

  # 옵션 B: R2 단독 + --all-attackers → A1, A2 × 2 profiles = 4 셀
  r2_cells = cli_main._build_suite_cells(
    scenario="R2",
    attacker=None,
    profile="default",
    all_profiles=True,
    all_scenarios=False,
    all_attackers=True,
    config=config,
  )
  # 옵션 B 전체 매트릭스 (12셀):
  #   NORMAL(A1) ×2 + R2(A1,A2) ×2 + R4(A2,sensitive) ×2 + R7(A1) ×2 + R9(A3) ×2 = 12
  # R4 는 항상 sensitive 모드(카테고리 분해 분석)만 돌린다. generic 모드는 컨셉상
  # sensitive 의 약화된 변종으로 폐기됐다 (대시보드 R4 패널 참고).
  full_cells = cli_main._build_suite_cells(
    scenario=None,
    attacker=None,
    profile="default",
    all_profiles=True,
    all_scenarios=True,
    all_attackers=True,
    config=config,
  )

  assert len(r2_cells) == 4
  assert {c.environment_type for c in r2_cells} == {"clean"}
  assert {c.attacker for c in r2_cells} == {"A1", "A2"}
  # R2 는 probe_mode 분기가 의미 없으므로 모두 generic 으로 유지된다.
  assert {c.probe_mode for c in r2_cells} == {"generic"}

  assert len(full_cells) == 12
  cell_ids = {c.cell_id for c in full_cells}
  expected_cells = (
    {f"NORMAL__A1__{p}" for p in ("reranker_off", "reranker_on")}
    | {f"R2__{a}__{p}" for a in ("A1", "A2") for p in ("reranker_off", "reranker_on")}
    | {f"R4__A2__{p}__sensitive" for p in ("reranker_off", "reranker_on")}
    | {f"R7__A1__{p}" for p in ("reranker_off", "reranker_on")}
    | {f"R9__A3__{p}" for p in ("reranker_off", "reranker_on")}
  )
  assert cell_ids == expected_cells
  # R4 셀은 항상 sensitive 만 존재한다.
  r4_modes = {c.probe_mode for c in full_cells if c.scenario == "R4"}
  assert r4_modes == {"sensitive"}


def test_build_suite_cells_threat_model_first(tmp_path):
  """위협 모델 우선 UX: --attacker A2 + --all-scenarios → 호환 시나리오만 셀 생성."""
  config = _base_config(tmp_path)

  cells = cli_main._build_suite_cells(
    scenario=None,
    attacker="A2",
    profile="default",
    all_profiles=False,
    all_scenarios=True,
    all_attackers=False,
    config=config,
  )
  # A2 와 호환되는 시나리오는 R2, R4. R4 는 항상 sensitive 단일 셀이므로
  #   R2(A2) ×1 + R4(A2, sensitive) ×1 = 2 셀이 된다.
  assert {c.scenario for c in cells} == {"R2", "R4"}
  assert {c.attacker for c in cells} == {"A2"}
  assert len(cells) == 2
  r4_modes = {c.probe_mode for c in cells if c.scenario == "R4"}
  assert r4_modes == {"sensitive"}

  # A3 + all-scenarios → R9 만
  cells_a3 = cli_main._build_suite_cells(
    scenario=None,
    attacker="A3",
    profile="default",
    all_profiles=False,
    all_scenarios=True,
    all_attackers=False,
    config=config,
  )
  assert {c.scenario for c in cells_a3} == {"R9"}
  assert {c.attacker for c in cells_a3} == {"A3"}


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
  # 옵션 B: R2 단독 + --all-attackers + --all-profiles → A1/A2 × 2profile = 4셀
  cells = cli_main._build_suite_cells(
    scenario="R2",
    attacker=None,
    profile="default",
    all_profiles=True,
    all_scenarios=False,
    all_attackers=True,
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
    probe_mode="generic",
    **kwargs,
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
    profile="default",
    all_profiles=False,
    all_scenarios=False,
    all_attackers=False,
    resume=suite_run_id,
    config_path=None,
    single_run_executor=fake_executor,
  )

  # 옵션 B 4셀 (A1/A2 × 2 profile) 중 cells[0]=완료(스킵), cells[1]=실패(재시도) →
  # cells[2], cells[3] 은 매니페스트엔 있지만 checkpoint 의 completed_cells/failed_cells
  # 에 없으므로 신규 실행 대상이다. 총 3건 실행.
  assert resumed_run_id == suite_run_id
  assert len(executed_cells) == 3
  assert cells[0].cell_id not in [cell_id for cell_id, _ in executed_cells]
  assert (cells[1].cell_id, True) in executed_cells

  with open(base_manager.run_dir(suite_run_id) / "R2_result.json", "r", encoding="utf-8") as file:
    parent_summary = json.load(file)
  # cells[0] 은 completed_cells 에만 등록되고 사전 저장된 결과 파일이 없으므로 합산 제외.
  # cells[1]/cells[2]/cells[3] 은 신규/재시도로 결과를 저장 → 부모 합산 3건.
  assert parent_summary["total"] == 3
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
