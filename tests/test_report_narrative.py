"""narrative.py 해석 레이어(지표 readout · 논지 문장) 단위 테스트.

재설계된 리포트는 '모든 숫자에 평문 한 줄 해석을 붙인다'는 원칙(원칙2)을 narrative.py
가 담당한다. 여기서는 build_report_narrative 가 시나리오별 지표 readout 과 대조군 대비
논지 문장을 올바르게 만드는지 검증한다. 실제 모델·데이터셋 없이 결정론적으로 동작한다.
"""

from __future__ import annotations

from rag.report.narrative import build_report_narrative


def _summary() -> dict:
  """readout·thesis 검증용 최소 요약 dict(실제 실험값 형태)."""
  return {
    "risk_level": "CRITICAL - Immediate action required",
    "scenario_results": {
      "R2": {
        "scenario": "R2", "total": 480, "success_count": 24, "success_rate": 0.05,
        "risk_score": 0.24, "verbatim_doc_diversity": 9, "refusal_rate": 0.825,
        "avg_high_pii_on_success": 2.17,
      },
      "R4": {
        "scenario": "R4", "total_pairs": 200, "success_count": 77,
        "success_rate": 0.385, "risk_score": 0.43, "avg_abs_delta_on_hit": 0.469,
      },
      "R9": {
        "scenario": "R9", "poisoned_total": 120, "success_count": 39,
        "success_rate": 0.325, "risk_score": 0.55, "intensity": 0.769,
      },
      "NORMAL": {"scenario": "NORMAL", "total": 360, "pii_response_count": 32},
    },
    "normal_vs_attack_pii_comparison": {
      "R2": {"pii_total_ratio": 3.4285, "pii_delta_total": 289.0},
      "R4": {"pii_total_ratio": 2.7647, "pii_delta_total": 210.0},
    },
  }


class TestMetricReadouts:
  def test_each_scenario_has_headline_readout(self):
    nar = build_report_narrative(_summary())
    by = {f["scenario"]: f for f in nar["findings"]}
    assert "success_rate" in by["R2"]["readouts"]
    assert "success_rate" in by["R4"]["readouts"]
    assert "success_rate" in by["R9"]["readouts"]
    assert "pii_response_count" in by["NORMAL"]["readouts"]

  def test_readout_contains_concrete_numbers(self):
    nar = build_report_narrative(_summary())
    by = {f["scenario"]: f for f in nar["findings"]}
    # 숫자를 담은 평문 문장이어야 한다(사용자가 해석하지 않게).
    assert "24" in by["R2"]["readouts"]["success_rate"]
    assert "77" in by["R4"]["readouts"]["success_rate"]
    assert "39" in by["R9"]["readouts"]["success_rate"]

  def test_zero_valued_aux_metrics_are_omitted(self):
    s = _summary()
    s["scenario_results"]["R2"]["refusal_rate"] = 0
    s["scenario_results"]["R2"]["verbatim_doc_diversity"] = 0
    nar = build_report_narrative(s)
    r2 = next(f for f in nar["findings"] if f["scenario"] == "R2")
    # 의미 없는(0) 보조 지표는 빈 문장으로 노출되지 않도록 아예 제외.
    assert "refusal_rate" not in r2["readouts"]
    assert "verbatim_doc_diversity" not in r2["readouts"]
    # 대표 지표는 항상 존재.
    assert "success_rate" in r2["readouts"]


class TestThesis:
  def test_headline_picks_strongest_ratio(self):
    nar = build_report_narrative(_summary())
    th = nar["thesis"]
    assert th["headline"]
    # R2(3.4배) > R4(2.7배) 이므로 headline 은 R2 를 가리켜야 한다.
    assert "R2" in th["headline"]
    assert "3.4배" in th["headline"]
    assert set(th["by_scenario"].keys()) == {"R2", "R4"}

  def test_no_baseline_returns_empty_thesis(self):
    s = _summary()
    s["normal_vs_attack_pii_comparison"] = {}
    nar = build_report_narrative(s)
    assert nar["thesis"] == {}
