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
    # 표시용 배수·초과분은 응답 수를 맞춘 값(pii_rate_ratio / pii_excess_count)만 쓴다.
    # 원시 총계(pii_total_ratio / pii_delta_total)는 질의를 더 많이 쏜 시나리오를
    # 실제보다 위험해 보이게 만들어서 화면에 노출하지 않는다.
    "normal_vs_attack_pii_comparison": {
      "R2": {
        "pii_total_ratio": 3.4285, "pii_delta_total": 289.0,
        "pii_rate_ratio": 2.5714, "pii_excess_count": 249,
        "baseline_response_count": 360, "attack_response_count": 480,
      },
      "R4": {
        "pii_total_ratio": 2.7647, "pii_delta_total": 210.0,
        "pii_rate_ratio": 2.4882, "pii_excess_count": 198,
        "baseline_response_count": 360, "attack_response_count": 400,
      },
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
    # 정규화 배수 R2(2.6배) > R4(2.5배) 이므로 headline 은 R2 를 가리켜야 한다.
    # 리포트 노출 문구에서는 코드(R2) 대신 시나리오 이름을 쓴다(사용자가 코드를 모른다).
    assert "검색 데이터 유출" in th["headline"]
    assert "2.6배" in th["headline"]
    # 원시 총계 배수(3.4배)가 새어 나오면 안 된다 — R2 는 질의를 33% 더 쐈을 뿐인데
    # 그 차이가 '더 샜다'로 둔갑한 값이다.
    assert "3.4배" not in th["headline"]
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


class TestActionPlan:
  """조치를 시나리오가 아니라 '조치'를 단위로 합치는 실행 계획.

  이 구조가 깨지면 리포트가 다시 산만해진다 — 같은 조치가 시나리오 카드마다 반복되고,
  리랭커처럼 효과가 엇갈리는 설정은 정반대 조치가 동시에 제시된다(재설계 이전 상태).
  """

  def test_same_action_across_scenarios_is_merged_once(self):
    nar = build_report_narrative(_summary_with_reranker())
    steps = nar["action_plan"]["steps"]
    titles = [s["title"] for s in steps]
    # 제목이 중복되면 합치기가 깨진 것이다.
    assert len(titles) == len(set(titles))
    # R2 와 NORMAL 의 PII 마스킹은 merge 키로 한 항목이 되어야 한다.
    masking = next(s for s in steps if "마스킹" in s["title"])
    assert set(masking["scenarios"]) == {"R2", "NORMAL"}

  def test_reranker_becomes_one_decision_not_scattered_actions(self):
    nar = build_report_narrative(_summary_with_reranker())
    plan = nar["action_plan"]
    # 실측 기반 리랭커 항목은 steps 에 남아 있으면 안 된다(의사결정으로 승격).
    assert all("리랭커" not in s["title"] for s in plan["steps"])
    decision = plan["decisions"][0]
    assert decision["badge"] == "warning"  # 좋아진 쪽·나빠진 쪽이 공존
    assert [i["scenario"] for i in decision["improves"]] == ["R2"]
    assert [w["scenario"] for w in decision["worsens"]] == ["R4"]

  def test_order_follows_leakage_not_success_rate_alone(self):
    """성공률만으로 줄 세우면 '가장 많이 새는 곳'의 조치가 뒤로 밀린다."""
    s = _summary()
    # R2 는 성공률 5%(최저)지만 PII 는 408건(최다)이다.
    s["pii_leakage_profile"] = {
      "R2": {"total_pii_count": 408}, "R4": {"total_pii_count": 329},
      "R9": {"total_pii_count": 20}, "NORMAL": {"total_pii_count": 119},
    }
    steps = build_report_narrative(s)["action_plan"]["steps"]
    r2_rank = min(st["rank"] for st in steps if "R2" in st["scenarios"])
    r9_rank = min(st["rank"] for st in steps if "R9" in st["scenarios"])
    # 성공률은 R9(32.5%) > R2(5%) 지만, 유출량 때문에 R2 조치가 앞서야 한다.
    assert r2_rank < r9_rank

  def test_steps_carry_their_own_evidence(self):
    nar = build_report_narrative(_summary_with_reranker())
    for step in nar["action_plan"]["steps"]:
      # 각 항목이 자기 순위의 근거(어느 시나리오에서 얼마나 샜나)를 들고 있어야 한다.
      assert step["impact"] and all(step["impact"])
      assert step["rank"] >= 1


class TestHeadlineMetrics:
  def test_verdict_carries_three_supporting_numbers(self):
    s = _summary()
    s["pii_leakage_profile"] = {
      "R2": {
        "total_pii_count": 408,
        "total_responses": 480,
        "responses_with_pii": 66,
        "pii_by_tag": {"QT_RRN": 55, "QT_MOBILE": 200, "PER": 153},
      },
      "NORMAL": {"total_pii_count": 119, "total_responses": 360, "responses_with_pii": 32},
    }
    metrics = build_report_narrative(s)["overall"]["metrics"]
    assert len(metrics) == 3
    # ① 첫 칸은 '뚫렸는가' — 최고 종합 위험도 + 그 공격의 성공률.
    assert metrics[0]["label"] == "최고 종합 위험도"
    assert "공격 성공률" in metrics[0]["sub"]
    assert metrics[1]["value"] == "408건"          # 공격 응답 PII 총량(NORMAL 제외)
    # 대조군 대비 초과 유출은 정규화 값(+249)이어야 한다. 원시 차분(+289)이 찍히면
    # 질의를 33% 더 쏜 것이 그대로 '더 샜다'로 둔갑한 것이다.
    assert metrics[2]["value"] == "+249건"
    # 값이 '가장 심한 한 시나리오'의 몫이라는 사실이 라벨에 드러나야 전체 합계로 안 읽힌다.
    assert "검색 데이터 유출" in metrics[2]["label"]

  def test_metrics_omitted_when_no_leakage_data(self):
    metrics = build_report_narrative(_summary())["overall"]["metrics"]
    # pii_leakage_profile 이 없으면 유출량 지표는 만들지 않는다(빈 값 노출 금지).
    assert all(m["label"] != "공격 응답에 노출된 개인정보" for m in metrics)


class TestRiskScaleConsistency:
  """총평 등급 · 시나리오 배지 · 종합 위험도 점수가 같은 눈금을 쓰는지 고정한다.

  예전에는 총평이 성공률 임계값, 배지가 또 다른 성공률 임계값, 화면의 큰 숫자는
  종합 위험도라 셋이 서로 어긋났다("총평 위험 / 모든 행 주의 / 최고 57점").
  """

  def test_badge_follows_risk_score_not_success_rate(self):
    s = _summary()
    # 성공률은 5%(낮음)인데 위험도는 0.55(높음)인 경우. 배지는 위험도를 따라야 한다.
    s["scenario_results"]["R2"]["success_rate"] = 0.05
    s["scenario_results"]["R2"]["risk_score"] = 0.55
    by = {f["scenario"]: f for f in build_report_narrative(s)["findings"]}
    assert by["R2"]["severity"] == "high"

  def test_overall_level_matches_worst_scenario_badge(self):
    from rag.report.narrative import overall_risk_level, risk_score_band

    s = _summary()
    s["risk_level"] = overall_risk_level(s["scenario_results"])
    nar = build_report_narrative(s)
    attacks = [f for f in nar["findings"] if f["scenario"] != "NORMAL"]
    worst = max(attacks, key=lambda f: f["risk_score"])
    # 총평 배지와 가장 위험한 시나리오의 배지가 다르면 화면이 자기모순에 빠진다.
    assert nar["overall"]["badge"] == risk_score_band(worst["risk_score"])

  def test_bands_are_monotonic(self):
    from rag.report.narrative import risk_score_band

    assert risk_score_band(0.50) == "high"
    assert risk_score_band(0.49) == "med"
    assert risk_score_band(0.20) == "med"
    assert risk_score_band(0.19) == "low"

  def test_verdict_wording_matches_badge_label(self):
    """총평 문장의 첫 단어가 배지 라벨과 같아야 한다.

    같은 판정을 '위험'(배지)과 '높음'(문장) 두 단어로 부르면, 사용자는 서로 다른
    두 등급이 있다고 읽는다.
    """
    from rag.report.narrative import _RISK_LEVEL_VERDICT, RISK_BAND_LABELS

    for _level, (verdict, badge) in _RISK_LEVEL_VERDICT.items():
      assert verdict.split(" ")[0] == RISK_BAND_LABELS[badge]
