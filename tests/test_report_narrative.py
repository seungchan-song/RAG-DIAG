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


class TestDefenseActions:
  """방어 조치는 '계층 + 근거의 성격(실측/미검증)'을 반드시 갖춰야 한다."""

  def test_successful_scenarios_get_layered_actions(self):
    nar = build_report_narrative(_summary())
    by = {f["scenario"]: f for f in nar["findings"]}
    for scen in ("R2", "R4", "R9"):
      actions = by[scen]["actions"]
      assert actions, f"{scen} 에 방어 조치가 비어 있다"
      for a in actions:
        assert a["layer"]  # 어느 계층을 손대는지 항상 밝힌다
        assert a["kind"] in {"verified", "warning", "advice", "maintain"}
        assert a["title"] and a["detail"]
    # 하위호환 필드(remediation)는 조치 제목 리스트여야 한다.
    assert by["R2"]["remediation"] == [a["title"] for a in by["R2"]["actions"]]

  def test_none_band_switches_to_maintain(self):
    s = _summary()
    # R2 성공을 0 으로 만들어 band=none → '고치세요'가 아니라 '유지·재진단'.
    s["scenario_results"]["R2"]["success_rate"] = 0
    s["scenario_results"]["R2"]["success_count"] = 0
    nar = build_report_narrative(s)
    r2 = next(f for f in nar["findings"] if f["scenario"] == "R2")
    assert [a["kind"] for a in r2["actions"]] == ["maintain"]


def _summary_with_reranker() -> dict:
  """리랭커 OFF→ON 실측이 포함된 요약(R2 는 개선, R4 는 악화된 실제 형태)."""
  s = _summary()
  s["reranker_on_off_comparison"] = {
    "R2": {
      "matched_query_count": 240, "base_success_count": 17, "paired_success_count": 7,
      "base_pii_total": 257, "paired_pii_total": 151,
    },
    "R4": {
      "matched_query_count": 100, "base_success_count": 35, "paired_success_count": 42,
      "base_pii_total": 133, "paired_pii_total": 138,
    },
  }
  return s


class TestMeasuredEvidence:
  """리랭커 실측이 있으면 조치에 '측정된 효과'가 근거로 붙어야 한다."""

  def test_improving_scenario_gets_verified_action_first(self):
    nar = build_report_narrative(_summary_with_reranker())
    r2 = next(f for f in nar["findings"] if f["scenario"] == "R2")
    first = r2["actions"][0]
    assert first["kind"] == "verified"
    assert "17건 → 7건" in first["measured"][0]
    assert "59% 감소" in first["measured"][0]
    # 다른 시나리오(R4)가 악화됐으므로 트레이드오프를 숨기지 않는다.
    assert "멤버십 추론" in first["caveat"]

  def test_worsening_scenario_is_reported_as_warning(self):
    nar = build_report_narrative(_summary_with_reranker())
    r4 = next(f for f in nar["findings"] if f["scenario"] == "R4")
    first = r4["actions"][0]
    assert first["kind"] == "warning"
    assert "35건 → 42건" in first["measured"][0]

  def test_scenario_without_measurement_has_no_measured_lines(self):
    nar = build_report_narrative(_summary_with_reranker())
    r9 = next(f for f in nar["findings"] if f["scenario"] == "R9")
    # R9 는 비교 데이터가 없으므로 전부 '미검증 권고'여야 한다.
    assert all(a["kind"] == "advice" for a in r9["actions"])
    assert all(not a["measured"] for a in r9["actions"])

  def test_defense_effects_exposed_for_report_section(self):
    nar = build_report_narrative(_summary_with_reranker())
    eff = nar["defense_effects"]
    assert eff["R2"]["direction"] == "improve"
    assert eff["R4"]["direction"] == "worsen"

  def test_no_comparison_data_yields_empty_effects(self):
    nar = build_report_narrative(_summary())
    assert nar["defense_effects"] == {}
