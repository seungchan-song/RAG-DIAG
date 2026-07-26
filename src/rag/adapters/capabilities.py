"""
시나리오 × 능력 매핑과 실행 계획(run / degrade / skip) 결정.

어댑터가 노출한 능력에 따라 각 시나리오를 어떻게 돌릴지 결정한다.
  - run     : 필요한 능력이 모두 있어 완전판으로 실행.
  - degrade : 필수 능력은 있으나 "권장" 능력이 없어 축소(블랙박스) 진단으로 실행.
  - skip    : 필수 능력이 없어 실행 자체가 불가능(사유를 리포트에 명시).

Notion "시나리오 × 어댑터 마스터 표" 를 그대로 코드화한 것이다. 코드가 source of truth 이며,
CLI 실행 루프가 이 계획을 읽어 자동 skip/degrade + 사유 기록을 수행하도록 연결하는 것이
다음 통합 단계다(이 모듈은 그 판정 로직을 순수 함수로 먼저 제공한다).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rag.adapters.base import CAPABILITY_LABELS, Capability

# === 시나리오별 필수 능력 (없으면 skip) ===
# 이 능력이 빠지면 시나리오 정의 자체가 성립하지 않는다.
#   - R4: 반사실 비교(d* 포함/제외 두 세계)가 정의라 INDEX_REBUILD 없이는 불가능.
#   - 그 외: 응답만 있으면 최소 판정/집계는 가능하므로 QUERY 만 필수.
SCENARIO_REQUIRED_CAPABILITIES: dict[str, set[Capability]] = {
  "NORMAL": {Capability.QUERY},
  "R7": {Capability.QUERY},
  "R2": {Capability.QUERY},
  "R4": {Capability.QUERY, Capability.INDEX_REBUILD},
  "R9": {Capability.QUERY},
}

# === 시나리오별 권장 능력 (없으면 degrade) ===
# 필수는 아니지만, 없으면 "완전판" 진단이 안 되고 블랙박스 수준으로 축소된다.
#   - R7: system_prompt 가 없으면 평가 정답이 비어 있어 유사도 판정이 무의미 → 축소.
#   - R2: 검색 원문·민감 라벨이 없으면 ROUGE 대조를 못 하고 응답 PII 유출만 측정 → 축소.
#   - R9: 문서 주입 능력이 없으면 사전 poison 인덱스에 의존해야 함(판정 자체는 블랙박스).
SCENARIO_RECOMMENDED_CAPABILITIES: dict[str, set[Capability]] = {
  "NORMAL": set(),
  "R7": {Capability.SYSTEM_PROMPT},
  "R2": {Capability.RETRIEVAL_TRACE, Capability.DOC_LABELS},
  "R4": set(),
  "R9": {Capability.INDEX_WRITE},
}

# 실행 계획 결정 문자열.
DECISION_RUN = "run"
DECISION_DEGRADE = "degrade"
DECISION_SKIP = "skip"


@dataclass
class CapabilityPlan:
  """
  한 시나리오를 특정 어댑터에서 어떻게 실행할지에 대한 판정 결과.

  Attributes:
    scenario: 대상 시나리오 이름(대문자 정규화).
    decision: run / degrade / skip 중 하나.
    missing_required: 부족한 필수 능력 집합(있으면 skip 사유).
    missing_recommended: 부족한 권장 능력 집합(있으면 degrade 사유).
    reason: 사람이 읽을 수 있는 한국어 사유(리포트·로그 노출용).
  """

  scenario: str
  decision: str
  missing_required: set[Capability] = field(default_factory=set)
  missing_recommended: set[Capability] = field(default_factory=set)
  reason: str = ""

  @property
  def should_run(self) -> bool:
    """실행 가능(run 또는 degrade) 여부."""
    return self.decision != DECISION_SKIP

  @property
  def degraded(self) -> bool:
    """축소 진단 여부."""
    return self.decision == DECISION_DEGRADE


def _labels(capabilities: set[Capability]) -> str:
  """능력 집합을 한국어 라벨 문자열로 변환합니다(정렬해 재현성 보장)."""
  return ", ".join(
    CAPABILITY_LABELS.get(cap, cap.value) for cap in sorted(capabilities, key=lambda c: c.value)
  )


def resolve_capabilities(target: Any) -> set[Capability]:
  """
  어댑터에서 능력 집합을 안전하게 추출합니다.

  capabilities 속성이 없거나(잘못 구현) 순회 불가하면 빈 집합을 돌려준다.

  Args:
    target: 어댑터 인스턴스 또는 capabilities 속성을 가진 객체.

  Returns:
    set[Capability]: 노출 능력 집합.
  """
  raw = getattr(target, "capabilities", set())
  try:
    return set(raw)
  except TypeError:
    return set()


def plan_scenario_execution(target: Any, scenario: str) -> CapabilityPlan:
  """
  어댑터가 노출한 능력을 근거로 시나리오 실행 계획을 결정합니다.

  Args:
    target: 진단 대상 어댑터(capabilities 속성 보유).
    scenario: 시나리오 이름(대소문자 무관).

  Returns:
    CapabilityPlan: run / degrade / skip 결정과 한국어 사유.
  """
  key = scenario.upper()
  available = resolve_capabilities(target)
  required = SCENARIO_REQUIRED_CAPABILITIES.get(key, {Capability.QUERY})
  recommended = SCENARIO_RECOMMENDED_CAPABILITIES.get(key, set())

  missing_required = required - available
  missing_recommended = recommended - available

  if missing_required:
    return CapabilityPlan(
      scenario=key,
      decision=DECISION_SKIP,
      missing_required=missing_required,
      missing_recommended=missing_recommended,
      reason=f"필수 능력 부족으로 실행 불가: {_labels(missing_required)}",
    )

  if missing_recommended:
    return CapabilityPlan(
      scenario=key,
      decision=DECISION_DEGRADE,
      missing_recommended=missing_recommended,
      reason=f"권장 능력 부족으로 축소 진단: {_labels(missing_recommended)}",
    )

  return CapabilityPlan(
    scenario=key,
    decision=DECISION_RUN,
    reason="필요 능력을 모두 충족하여 완전판으로 실행",
  )
