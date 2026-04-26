"""Tests for KDPII-style benchmark evaluation artifacts and metrics."""

from __future__ import annotations

import json
import sys
import types
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from rag.cli.main import app
from rag.pii.eval import (
  EvalEntity,
  EvalSample,
  LabelNormalizationError,
  PIIBenchmarkRunner,
  load_eval_dataset,
)
from rag.pii.step3_ner import NERDetector, NERMatch

FIXTURE_PATH = Path(__file__).parent / "fixtures" / "pii_eval_fixture.jsonl"


def _build_config(
  output_dir: Path,
  *,
  enable_step3: bool = True,
  enable_step4: bool = True,
) -> dict:
  return {
    "pii": {
      "runtime": {
        "enable_step3": enable_step3,
        "enable_step4": enable_step4,
      },
      "ner": {
        "model_path": "townboy/kpfbert-kdpii",
        "confidence_threshold": 0.8,
      },
      "sllm": {
        "model": "gpt-4o-mini",
        "max_retries": 1,
        "retry_backoff": 1,
      },
      "eval": {
        "label_schema_version": "kdpii-33-v1",
        "error_context_chars": 12,
      },
    },
    "report": {
      "output_dir": str(output_dir),
      "mask_raw_pii": True,
      "persist_raw_response": False,
    },
  }


def _write_config(
  tmp_path: Path,
  output_dir: Path,
  *,
  enable_step3: bool = True,
  enable_step4: bool = True,
) -> Path:
  config_path = tmp_path / "pii-eval.yaml"
  with open(config_path, "w", encoding="utf-8") as file:
    yaml.safe_dump(
      _build_config(
        output_dir,
        enable_step3=enable_step3,
        enable_step4=enable_step4,
      ),
      file,
      allow_unicode=True,
      sort_keys=False,
    )
  return config_path


class TestPIIBenchmarkRunner:
  def test_cli_all_modes_writes_expected_artifacts(self, tmp_path) -> None:
    runner = CliRunner()
    results_dir = tmp_path / "results"
    config_path = _write_config(
      tmp_path,
      results_dir,
      enable_step3=False,
      enable_step4=False,
    )

    result = runner.invoke(
      app,
      [
        "pii-eval",
        "--dataset-path",
        str(FIXTURE_PATH),
        "--all-modes",
        "--config",
        str(config_path),
      ],
    )

    assert result.exit_code == 0, result.stdout
    run_dirs = list(results_dir.glob("PII-EVAL-*"))
    assert len(run_dirs) == 1
    run_dir = run_dirs[0]
    assert (run_dir / "snapshot.yaml").exists()
    assert (run_dir / "pii_eval_summary.json").exists()
    assert (run_dir / "pii_eval_by_tag.csv").exists()
    assert (run_dir / "pii_eval_errors.csv").exists()

    with open(run_dir / "pii_eval_summary.json", "r", encoding="utf-8") as file:
      summary = json.load(file)

    assert summary["requested_modes"] == ["step1", "step1_2", "step1_2_3", "full"]
    assert set(summary["mode_results"]) == {"step1", "step1_2", "step1_2_3", "full"}
    assert summary["artifact_policy"] == "masked_only"

  def test_single_mode_metrics_use_exact_span_and_label_match(self, tmp_path) -> None:
    runner = PIIBenchmarkRunner(_build_config(tmp_path))
    generated = runner.evaluate(
      dataset_path=FIXTURE_PATH,
      modes=["step1"],
      run_id="PII-EVAL-TEST",
      output_dir=tmp_path,
    )

    with open(generated["json"], "r", encoding="utf-8") as file:
      summary = json.load(file)

    assert summary["mode"] == "step1"
    assert summary["overall_micro_precision"] == 1.0
    assert summary["overall_micro_recall"] == 1.0
    assert summary["overall_micro_f1"] == 1.0
    assert summary["overall_macro_precision"] == 1.0
    assert summary["overall_macro_recall"] == 1.0
    assert summary["overall_macro_f1"] == 1.0
    assert summary["per_tag_metrics"]["QT_MOBILE"]["support"] == 1
    assert summary["per_tag_metrics"]["TMI_EMAIL"]["support"] == 2

  def test_label_mismatch_is_recorded_with_masked_snippet(self, tmp_path) -> None:
    runner = PIIBenchmarkRunner(_build_config(tmp_path))
    sample = EvalSample(
      sample_id="sample-001",
      text="Send mail to hong@example.com today.",
      entities=(
        EvalEntity(
          sample_id="sample-001",
          start=13,
          end=29,
          label="TMI_EMAIL",
          text="hong@example.com",
          route="gold",
          source="gold",
        ),
      ),
    )
    predictions = [
      EvalEntity(
        sample_id="sample-001",
        start=13,
        end=29,
        label="QT_MOBILE",
        text="hong@example.com",
        route="STEP1_RAW",
        source="regex",
      )
    ]

    compared = runner._compare_entities(sample, predictions)

    assert compared["fp"]["QT_MOBILE"] == 1
    assert compared["fn"]["TMI_EMAIL"] == 1
    assert compared["errors"][0]["error_type"] == "label_mismatch"
    assert compared["errors"][0]["gold_label"] == "TMI_EMAIL"
    assert compared["errors"][0]["pred_label"] == "QT_MOBILE"
    assert "hong@example.com" not in compared["errors"][0]["masked_snippet"]

  def test_unknown_gold_label_raises_explicit_normalization_error(self, tmp_path) -> None:
    dataset_path = tmp_path / "unknown-label.jsonl"
    dataset_path.write_text(
      json.dumps(
        {
          "sample_id": "sample-001",
          "text": "Call me.",
          "entities": [{"start": 0, "end": 4, "label": "UNKNOWN_TAG"}],
        },
        ensure_ascii=False,
      ),
      encoding="utf-8",
    )

    with pytest.raises(LabelNormalizationError):
      load_eval_dataset(dataset_path)

  def test_step3_load_failure_is_recorded_without_aborting_eval(
    self,
    monkeypatch,
    tmp_path,
  ) -> None:
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(_: str, **__: object) -> object:
      raise RuntimeError("hf model load failed")

    transformers_module.pipeline = fake_pipeline
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)

    runner = PIIBenchmarkRunner(_build_config(tmp_path))
    generated = runner.evaluate(
      dataset_path=FIXTURE_PATH,
      modes=["step1_2_3"],
      run_id="PII-EVAL-TEST",
      output_dir=tmp_path,
    )

    with open(generated["json"], "r", encoding="utf-8") as file:
      summary = json.load(file)

    runtime_status = summary["runtime_status"]
    assert runtime_status["step3"]["load_status"] == "failed"
    assert "hf model load failed" in runtime_status["step3"]["error"]
    assert summary["overall_micro_f1"] == 1.0

  def test_full_mode_records_mock_conservative_step4(self, monkeypatch, tmp_path) -> None:
    dataset_path = tmp_path / "per-only.jsonl"
    dataset_path.write_text(
      json.dumps(
        {
          "sample_id": "sample-001",
          "text": "John joined today.",
          "entities": [{"start": 0, "end": 4, "label": "PER"}],
        },
        ensure_ascii=False,
      ),
      encoding="utf-8",
    )

    def fake_warm_up(self) -> None:
      self.pipeline = object()
      self.model_source = "hub"
      self.load_status = "ready"
      self.error_message = ""
      self.resolved_model_identifier = self.model_path

    def fake_detect(self, text: str) -> list[NERMatch]:
      return [
        NERMatch(
          tag="PER",
          text="John",
          start=0,
          end=4,
          confidence=0.95,
        )
      ]

    monkeypatch.setattr(NERDetector, "warm_up", fake_warm_up)
    monkeypatch.setattr(NERDetector, "detect", fake_detect)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    runner = PIIBenchmarkRunner(_build_config(tmp_path))
    generated = runner.evaluate(
      dataset_path=dataset_path,
      modes=["full"],
      run_id="PII-EVAL-TEST",
      output_dir=tmp_path,
    )

    with open(generated["json"], "r", encoding="utf-8") as file:
      summary = json.load(file)

    runtime_status = summary["runtime_status"]
    assert runtime_status["step3"]["load_status"] == "ready"
    assert runtime_status["step4"]["mode"] == "mock_conservative"
    assert runtime_status["step4"]["reason_counts"]["mock_conservative"] == 1
    assert summary["overall_micro_f1"] == 1.0

  def test_error_csv_omits_raw_pii_values(self, tmp_path) -> None:
    runner = PIIBenchmarkRunner(_build_config(tmp_path))

    def fake_predict_entities(
      sample: EvalSample,
      mode: str,
      detector: object,
    ) -> tuple[list[EvalEntity], dict]:
      return (
        [
          EvalEntity(
            sample_id=sample.sample_id,
            start=22,
            end=38,
            label="QT_MOBILE",
            text="hong@example.com",
            route="STEP1_RAW",
            source="regex",
          )
        ],
        runner._build_step1_runtime_status(1),
      )

    runner._predict_entities = fake_predict_entities  # type: ignore[method-assign]
    generated = runner.evaluate(
      dataset_path=FIXTURE_PATH,
      modes=["step1"],
      run_id="PII-EVAL-TEST",
      output_dir=tmp_path,
    )

    errors_csv = generated["errors_csv"].read_text(encoding="utf-8")
    assert "hong@example.com" not in errors_csv
    assert "label_mismatch" in errors_csv
