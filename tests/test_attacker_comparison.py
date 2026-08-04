"""ReportGenerator._build_attacker_comparison 회귀 테스트.

옵션 B 매트릭스에서 R2/R4 모두 A1↔A2 비교 페어를 생성하는지 검증한다.
"""

from __future__ import annotations

from rag.adapters.base import CAPABILITY_LABELS, Capability
from rag.attack.query_generator import (
  ATTACKER_PROFILES,
  AttackQueryGenerator,
  describe_attacker,
)
from rag.report.generator import ReportGenerator


def _make_result(
  *,
  scenario: str,
  attacker: str,
  query_id: str,
  success: bool,
  pii_total: int = 0,
  ground_truth_b: int | None = None,
  response: str = "resp",
) -> dict:
  meta = {
    "attacker": attacker,
    "query_id": query_id,
    "env": "clean",
    "reranker_state": "off",
  }
  if ground_truth_b is not None:
    meta["ground_truth_b"] = ground_truth_b
  return {
    "environment_type": "clean",
    "query_id": query_id,
    "success": success,
    "score": 0.9 if success else 0.1,
    "response": response,
    "pii_summary": {"total": pii_total},
    "metadata": meta,
  }


def _gen(tmp_path) -> ReportGenerator:
  return ReportGenerator({"report": {"output_dir": str(tmp_path), "output_formats": []}})


def test_attacker_pairs_contains_only_r2():
  """R2 만 A1↔A2 비교 대상. R4 는 MIA 정의상 A2 단독 운영이라 비교 제외."""
  assert ReportGenerator.ATTACKER_PAIRS == {"R2": ("A1", "A2")}


def test_r2_attacker_comparison_pairs(tmp_path):
  gen = _gen(tmp_path)
  scenario_results = {
    "R2": {
      "results": [
        _make_result(scenario="R2", attacker="A1", query_id="R2:q1", success=False, pii_total=0),
        _make_result(scenario="R2", attacker="A2", query_id="R2:q1", success=True, pii_total=3),
      ]
    }
  }
  cmp = gen._build_attacker_comparison("rid", scenario_results)
  assert "R2" in cmp
  summary = cmp["R2"]
  assert summary["matched_query_count"] == 1
  assert summary["base_success_count"] == 0
  assert summary["paired_success_count"] == 1
  assert summary["paired_pii_total"] == 3


def test_r4_excluded_from_attacker_comparison(tmp_path):
  """R4 는 ATTACKER_PAIRS 에서 빠져 있으므로 A1, A2 결과가 모두 있어도 비교 키가 생성되지 않는다."""
  gen = _gen(tmp_path)
  scenario_results = {
    "R4": {
      "results": [
        _make_result(scenario="R4", attacker="A1", query_id="R4:doc1:b-1:tpl-00:rep-00", success=False, ground_truth_b=1),
        _make_result(scenario="R4", attacker="A2", query_id="R4:doc1:b-1:tpl-00:rep-00", success=True, ground_truth_b=1, pii_total=2),
      ]
    }
  }
  cmp = gen._build_attacker_comparison("rid", scenario_results)
  assert "R4" not in cmp


def test_no_comparison_when_only_one_attacker(tmp_path):
  """A1 단독 실행 시 비교 데이터가 비어 있어야 한다."""
  gen = _gen(tmp_path)
  scenario_results = {
    "R2": {
      "results": [
        _make_result(scenario="R2", attacker="A1", query_id="R2:q1", success=True),
      ]
    }
  }
  cmp = gen._build_attacker_comparison("rid", scenario_results)
  assert cmp == {}


def test_attacker_profiles_cover_every_valid_attacker():
  """ATTACKER_PROFILES 와 공격자 화이트리스트/매트릭스가 갈라지지 않아야 한다.

  갈라지면 리포트의 '가정한 공격자 권한' 이 조용히 빈칸으로 렌더되어, 사용자는
  그 시나리오가 아무 권한도 가정하지 않은 것처럼 읽게 된다.
  """
  assert set(ATTACKER_PROFILES) == set(AttackQueryGenerator.VALID_ATTACKERS)
  for attackers in AttackQueryGenerator.SCENARIO_ATTACKER_MATRIX.values():
    assert attackers <= set(ATTACKER_PROFILES)
  # grants 는 어댑터 능력 어휘여야 한다 — 자체 문자열을 쓰면 두 용어가 다시 갈라진다.
  for profile in ATTACKER_PROFILES.values():
    assert profile["grants"] <= set(Capability)
    assert Capability.QUERY in profile["grants"]


def test_describe_attacker_translates_to_capability_labels():
  """공격자 코드가 한국어 라벨 + 능력 라벨로 번역된다(모르는 코드는 None)."""
  a2 = describe_attacker("a2")
  assert a2 == {
    "code": "A2",
    "label": "내용 인지 관찰자",
    # 공통 능력인 QUERY 가 항상 먼저 온다 ("질의 + α" 형태로 차이가 드러나게).
    "grants": [CAPABILITY_LABELS[Capability.QUERY], CAPABILITY_LABELS[Capability.DOC_LABELS]],
    "desc": ATTACKER_PROFILES["A2"]["desc"],
  }
  assert describe_attacker("A9") is None


def test_execution_reliability_carries_attacker_profiles(tmp_path):
  """시나리오 요약에 공격자 프로필이 실려 대시보드가 렌더할 수 있어야 한다."""
  gen = _gen(tmp_path)
  scenario_results = {
    "R2": {
      "results": [
        _make_result(scenario="R2", attacker="A2", query_id="R2:q1", success=True),
        _make_result(scenario="R2", attacker="A1", query_id="R2:q1", success=False),
      ]
    }
  }
  profiles = gen._build_execution_reliability_summary(scenario_results)["scenarios"]["R2"][
    "attacker_profiles"
  ]
  assert [p["code"] for p in profiles] == ["A1", "A2"]


def test_normalize_query_id_r4s_prefix(tmp_path):
  """R4 sensitive(R4S:) 와 generic(R4:) 이 섞여 있어도 동일 query 로 정규화된다."""
  gen = _gen(tmp_path)
  assert gen._normalize_query_id("R4S:doc1:b-1:tpl-00:rep-00", "R4") == "R4:doc1:b-1:tpl-00:rep-00"
  assert gen._normalize_query_id("R4:doc1:b-1:tpl-00:rep-00", "R4") == "R4:doc1:b-1:tpl-00:rep-00"
  assert gen._normalize_query_id("R2:q1", "R2") == "R2:q1"
