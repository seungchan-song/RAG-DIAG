"""공격자 프로필(ATTACKER_PROFILES)과 시나리오 매트릭스 회귀 테스트.

예전에는 여기서 `_build_attacker_comparison`(R2 의 A1↔A2 페어 비교)도 검증했지만,
2026-08-12 에 R2 를 A2 단독으로 좁히면서 비교 로직 자체를 삭제했다. 근거는
`query_generator.py:SCENARIO_ATTACKER_MATRIX` 주석 참조.
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
  attacker: str,
  query_id: str,
  success: bool,
  pii_total: int = 0,
) -> dict:
  return {
    "environment_type": "clean",
    "query_id": query_id,
    "success": success,
    "score": 0.9 if success else 0.1,
    "response": "resp",
    "pii_summary": {"total": pii_total},
    "metadata": {
      "attacker": attacker,
      "query_id": query_id,
      "env": "clean",
      "reranker_state": "off",
    },
  }


def _gen(tmp_path) -> ReportGenerator:
  return ReportGenerator({"report": {"output_dir": str(tmp_path), "output_formats": []}})


def test_r2_runs_aware_observer_only():
  """R2 는 A2 단독이다.

  A1 을 되돌리면 서로 다른 위협 모델 둘이 하나의 R2 성공률로 평균되며(실측
  7.9%→7.0%), 리포트는 그 차이를 쓰지 않으므로 셀당 30질의가 그냥 버려진다.
  되살릴 때는 리포트에 A1 지표를 쓸 자리를 먼저 만들 것.
  """
  assert AttackQueryGenerator.SCENARIO_ATTACKER_MATRIX["R2"] == {"A2"}
  assert AttackQueryGenerator.CANONICAL_ATTACKER["R2"] == "A2"


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
    "R2": {"results": [_make_result(attacker="A2", query_id="R2:q1", success=True)]},
    "R9": {"results": [_make_result(attacker="A3", query_id="R9:q1", success=False)]},
  }
  reliability = gen._build_execution_reliability_summary(scenario_results)["scenarios"]
  assert [p["code"] for p in reliability["R2"]["attacker_profiles"]] == ["A2"]
  assert [p["code"] for p in reliability["R9"]["attacker_profiles"]] == ["A3"]
