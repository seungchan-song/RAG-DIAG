"""PII classification helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from loguru import logger

from rag.pii.step1_regex import PIIMatch
from rag.pii.step3_ner import NERMatch

HIGH_RISK_TAGS = {
  "QT_ARN",
  "QT_CARD",
  "QT_MOBILE",
  "QT_PASSPORT",
  "QT_PHONE",
  "QT_RRN",
  "TMI_EMAIL",
}

# 위험 등급(3단계) — 리포트에서 "몇 건 샜나"가 아니라 "무엇이 샜나"로 비교하기 위한 축.
# 개인정보보호법 제24조(고유식별정보)·제23조(민감정보) 기준을 따른다.
#   identifier : 고유식별정보 + 금융정보. 한 건만 새도 본인 특정·도용이 가능하다.
#   contact    : 직접 연락·위치 추적이 가능한 식별자.
#   context    : 그 자체로는 특정이 어렵지만 결합하면 신원을 좁히는 문맥 정보(기본값).
# HIGH_RISK_TAGS(위험도 intensity 계산용, 이진 판정)와는 목적이 다른 별개 축이다.
# 여기 없는 태그는 전부 context 로 떨어지므로, 새 태그가 생겨도 집계가 깨지지 않는다.
PII_RISK_TIERS: dict[str, set[str]] = {
  "identifier": {
    "QT_RRN",
    "QT_ARN",
    "QT_FOREIGN",
    "QT_PASSPORT",
    "QT_DRIVER",
    "QT_DL",
    "QT_LICENSE",
    "QT_CARD",
    "QT_ACCOUNT",
  },
  "contact": {
    "QT_MOBILE",
    "QT_PHONE",
    "QT_EMAIL",
    "TMI_EMAIL",
    "QT_ADDR",
    "QT_CAR",
    "QT_IP",
  },
}
RISK_TIER_ORDER = ("identifier", "contact", "context")


def risk_tier(tag: str) -> str:
  """PII 태그의 위험 등급을 반환한다(identifier/contact/context)."""
  for tier, tags in PII_RISK_TIERS.items():
    if tag in tags:
      return tier
  return "context"


def count_by_risk_tier(by_tag: dict[str, int]) -> dict[str, int]:
  """태그별 건수 dict 를 위험 등급별 건수 dict 로 접는다.

  Args:
    by_tag: {태그: 건수} (PIIClassifier.to_summary 의 `by_tag` 형태).

  Returns:
    {"identifier": n, "contact": n, "context": n} — 항상 3개 키를 모두 포함한다
    (0 인 등급이 빠지면 리포트 표에 칸이 사라져 비교가 어긋난다).
  """
  counts = dict.fromkeys(RISK_TIER_ORDER, 0)
  for tag, count in (by_tag or {}).items():
    counts[risk_tier(str(tag))] += int(count or 0)
  return counts


@dataclass
class ConfirmedPII:
  """One confirmed PII finding."""

  tag: str
  text: str
  start: int
  end: int
  route: str
  source: str
  confidence: float = 1.0


class PIIClassifier:
  """Merge step outputs into one deduplicated confirmed PII list."""

  def classify(
    self,
    regex_validated: list[PIIMatch],
    ner_b1: list[NERMatch],
    sllm_verified: list[NERMatch],
  ) -> list[ConfirmedPII]:
    confirmed: list[ConfirmedPII] = []

    for match in regex_validated:
      route = "A-2" if match.tag in {"QT_RRN", "QT_ARN", "QT_CARD"} else "A-1"
      confirmed.append(
        ConfirmedPII(
          tag=match.tag,
          text=match.text,
          start=match.start,
          end=match.end,
          route=route,
          source="regex",
          confidence=1.0,
        )
      )

    for match in ner_b1:
      confirmed.append(
        ConfirmedPII(
          tag=match.tag,
          text=match.text,
          start=match.start,
          end=match.end,
          route="B-1",
          source="ner",
          confidence=match.confidence,
        )
      )

    for match in sllm_verified:
      confirmed.append(
        ConfirmedPII(
          tag=match.tag,
          text=match.text,
          start=match.start,
          end=match.end,
          route="B-2",
          source="ner+sllm",
          confidence=match.confidence,
        )
      )

    confirmed.sort(key=lambda item: item.start)
    confirmed = self._remove_overlaps(confirmed)

    logger.info(
      "Confirmed {} PII findings (A-1={}, A-2={}, B-1={}, B-2={})",
      len(confirmed),
      sum(1 for item in confirmed if item.route == "A-1"),
      sum(1 for item in confirmed if item.route == "A-2"),
      sum(1 for item in confirmed if item.route == "B-1"),
      sum(1 for item in confirmed if item.route == "B-2"),
    )
    return confirmed

  def _remove_overlaps(self, confirmed: list[ConfirmedPII]) -> list[ConfirmedPII]:
    if not confirmed:
      return []

    result: list[ConfirmedPII] = [confirmed[0]]
    for current in confirmed[1:]:
      previous = result[-1]
      if current.start < previous.end:
        if current.confidence > previous.confidence:
          result[-1] = current
      else:
        result.append(current)
    return result

  def to_summary(self, confirmed: list[ConfirmedPII]) -> dict[str, Any]:
    by_tag: dict[str, int] = {}
    by_route: dict[str, int] = {}
    high_risk_tags: dict[str, int] = {}

    for pii in confirmed:
      by_tag[pii.tag] = by_tag.get(pii.tag, 0) + 1
      by_route[pii.route] = by_route.get(pii.route, 0) + 1
      if pii.tag in HIGH_RISK_TAGS:
        high_risk_tags[pii.tag] = high_risk_tags.get(pii.tag, 0) + 1

    sorted_tags = sorted(by_tag.items(), key=lambda item: (-item[1], item[0]))
    sorted_high_risk_tags = sorted(
      high_risk_tags.items(),
      key=lambda item: (-item[1], item[0]),
    )

    return {
      "total": len(confirmed),
      "by_tag": dict(sorted_tags),
      "by_route": by_route,
      "top3_tags": [tag for tag, _ in sorted_tags[:3]],
      "high_risk_count": sum(high_risk_tags.values()),
      "high_risk_tags": [tag for tag, _ in sorted_high_risk_tags],
      "has_high_risk": bool(high_risk_tags),
      "items": [asdict(item) for item in confirmed],
    }


def is_high_risk_tag(tag: str) -> bool:
  """Return whether the given tag should be treated as high risk."""
  return tag in HIGH_RISK_TAGS
