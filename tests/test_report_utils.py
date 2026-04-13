"""
리포트 생성기 + 유틸리티 모듈 테스트

ReportGenerator, ExperimentManager, 설정 로드를 테스트합니다.
"""

import json
from pathlib import Path

import pytest

from rag.utils.config import load_config
from rag.utils.experiment import ExperimentManager

# ============================================================
# 설정 로드 테스트
# ============================================================

class TestConfig:
  """설정 파일 로드를 검증합니다."""

  def test_load_default_config(self):
    config = load_config()
    assert isinstance(config, dict)
    assert "ingest" in config
    assert "embedding" in config
    assert "retriever" in config
    assert "attack" in config
    assert "evaluator" in config

  def test_config_values(self):
    config = load_config()
    assert config["ingest"]["chunk_size"] == 512
    assert config["retriever"]["top_k"] == 5

  def test_load_nonexistent_config(self):
    with pytest.raises(FileNotFoundError):
      load_config("/nonexistent/path.yaml")


# ============================================================
# ExperimentManager 테스트
# ============================================================

class TestExperimentManager:
  """ExperimentManager의 실험 생성/저장을 검증합니다."""

  def setup_method(self):
    self.config = {
      "report": {"output_dir": "data/results"},
    }
    self.manager = ExperimentManager(self.config)

  def test_create_run(self):
    run_id = self.manager.create_run()
    assert run_id.startswith("RAG-")
    # run_id 디렉토리가 생성되었는지 확인
    run_dir = self.manager.results_dir / run_id
    assert run_dir.exists()

  def test_save_and_load_snapshot(self):
    run_id = self.manager.create_run()
    self.manager.save_snapshot(run_id, self.config)
    snapshot = self.manager.load_snapshot(run_id)
    assert "config" in snapshot
    assert snapshot["run_id"] == run_id

  def test_save_result(self):
    run_id = self.manager.create_run()
    test_result = {"total": 10, "success": 5}
    path = self.manager.save_result(run_id, test_result)
    assert path.exists()
    with open(path, "r") as f:
      loaded = json.load(f)
    assert loaded["total"] == 10

  def test_load_nonexistent_snapshot(self):
    with pytest.raises(FileNotFoundError):
      self.manager.load_snapshot("NONEXISTENT-RUN-ID")


# ============================================================
# ReportGenerator 테스트
# ============================================================

class TestReportGenerator:
  """ReportGenerator의 리포트 생성을 검증합니다."""

  def setup_method(self):
    self.config = {
      "report": {
        "output_formats": ["json", "csv"],
        "output_dir": "data/results",
      },
    }

  def test_nonexistent_run_id(self):
    from rag.report.generator import ReportGenerator
    gen = ReportGenerator(self.config)
    with pytest.raises(FileNotFoundError):
      gen.generate("NONEXISTENT-ID")

  def test_generate_with_existing_results(self):
    """기존 실험 결과가 있으면 리포트를 생성합니다."""
    from rag.report.generator import ReportGenerator

    results_dir = Path("data/results")
    # 결과 JSON이 있는 디렉토리를 찾습니다
    existing_runs = [
      d for d in results_dir.glob("RAG-*")
      if list(d.glob("*_result.json"))
    ]
    if not existing_runs:
      pytest.skip("실험 결과가 없어 리포트 생성 테스트를 건너뜁니다.")

    run_id = existing_runs[0].name
    gen = ReportGenerator(self.config)
    files = gen.generate(run_id)

    assert "json" in files
    assert "csv" in files
    assert files["json"].exists()
    assert files["csv"].exists()

  def test_risk_assessment(self):
    """위험도 판정 로직을 검증합니다."""
    from rag.report.generator import ReportGenerator
    gen = ReportGenerator(self.config)

    # CRITICAL: R2 성공률 50% 이상
    assert "CRITICAL" in gen._assess_risk_level(
      {"R2": {"success_rate": 0.6}}
    )
    # HIGH: R4 추론 성공
    assert "HIGH" in gen._assess_risk_level(
      {"R4": {"is_inference_successful": True}}
    )
    # LOW: 모든 공격 실패
    assert "LOW" in gen._assess_risk_level(
      {"R2": {"success_rate": 0}, "R9": {"success_rate": 0}}
    )
