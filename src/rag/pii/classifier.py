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
    # 우편번호는 주소 계열이라 contact. 사원번호·회원 ID·참가자 ID·계정 ID(33종 신규)는
    # 그 자체로 본인 특정·도용이 되지 않으므로 기본값 context 에 그대로 둔다.
    "ZIPCODE",
  },
}
RISK_TIER_ORDER = ("identifier", "contact", "context")

# PII 태그 → 사용자에게 보여줄 한국어 이름. 사용자 노출 문구의 single source of truth 다.
# QT_/TMI_ 접두사는 우리 탐지 파이프라인의 내부 네임스페이스(정형/비정형)일 뿐인데,
# 마스킹 자리표시자가 이걸 그대로 뱉어서 리포트에 "[TMI_EMAIL]" 같은 은어가 노출됐다.
# 마스커(pii/masker.py)와 대시보드(report/dashboard_template.py:TAG_KO)가 함께 쓴다.
PII_TAG_LABELS: dict[str, str] = {
  # 정형 PII(QT_*) — step1_regex 내장 11종 + 조직별 ID(config) + NER 이 내는 태그
  "QT_RRN": "주민등록번호", "QT_ARN": "외국인등록번호", "QT_FOREIGN": "외국인등록번호",
  "QT_PASSPORT": "여권번호", "QT_DRIVER": "운전면허", "QT_DL": "운전면허",
  "QT_LICENSE": "운전면허", "QT_CARD": "카드번호", "QT_ACCOUNT": "계좌번호",
  "QT_BIZ": "사업자번호", "QT_MOBILE": "휴대전화", "QT_PHONE": "전화번호",
  "QT_EMAIL": "이메일", "QT_ADDR": "주소", "QT_IP": "IP 주소", "QT_CAR": "차량번호",
  "QT_AGE": "나이",
  # 개인정보 33종 개편(2026-08) 신규 식별자
  "EMPLOYEE_ID": "사원번호", "MEMBER_ID": "회원 ID", "PARTICIPANT_ID": "참가자 ID",
  "USER_ID": "계정 ID", "ZIPCODE": "우편번호", "CITY": "도시",
  # 비정형·문맥 PII(TMI_*) 및 NER 태그
  "TMI_EMAIL": "이메일", "TMI_OCCUPATION": "직업·직장", "TMI_SITE": "사이트·계정",
  "TMI_NATIONALITY": "국적",
  # 신체·신념 계열(33종 NER 이 내는 태그). 여기 빠져 있으면 마스킹 자리표시자가
  # `[TMI_BLOOD_TYPE]` 처럼 내부 코드명 그대로 리포트에 실린다 —
  # tests/test_pii_tag_labels.py 가 누락을 막는다.
  "QT_LENGTH": "키", "QT_WEIGHT": "몸무게", "TMI_BLOOD_TYPE": "혈액형",
  "TMI_RELIGION": "종교", "TMI_HEALTH": "건강정보", "TMI_GENDER": "성별",
  "PS_NAME": "이름", "PS_POSITION": "직위", "PS_ORG": "소속",
  "PER": "이름", "LOC": "주소·장소", "ORG": "기관·소속",
  "DAT": "날짜", "TIM": "시간", "AFW": "작품·제품명",
}


def tag_label(tag: str) -> str:
  """PII 태그를 사용자에게 보여줄 한국어 이름으로 바꾼다(모르는 태그는 원문 유지)."""
  return PII_TAG_LABELS.get(str(tag), str(tag))


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
      # A-2 = 체크섬을 실제로 통과한 항목. QT_ARN 은 검증 가능한 체크섬이 없어
      # (step2_checksum docstring 참조) 구조 일치만으로 확정되므로 A-1 이다.
      route = "A-2" if match.tag in {"QT_RRN", "QT_CARD"} else "A-1"
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
    """겹치는 확정 항목 중 하나만 남긴다 — 신뢰도 우선, 같으면 긴 스팬 우선.

    길이를 동점 처리 기준으로 쓰는 이유(2026-08-06):
      정규식 탐지는 전부 confidence=1.0 이라 신뢰도만 비교하면 승자가
      `RegexDetector.PATTERNS` 의 선언 순서로 결정된다. 그 결과
      `051109-3345671`(2002~2006년생 주민등록번호)에서 앞부분 11자를 삼킨
      `QT_PHONE`(선언 순서 2번)이 온전한 `QT_RRN`(5번)을 밀어냈다. 피해는 셋이다.
        · 위험 등급이 identifier → contact 로 강등된다
        · needs_validation 이 False 라 mod11 체크섬이 아예 안 돈다
        · 스팬이 짧아 마스킹이 뒷자리를 놓친다(`**-****-3345671`)
      더 긴 매치가 더 구체적인 패턴이라는 것이 일반 규칙이므로 길이로 가른다.
      (현재 코퍼스에서는 이 조합이 0건이라 리포트 수치는 바뀌지 않는다 —
      2000년대 출생 데이터가 들어올 때를 대비한 잠재 결함 차단이다.)
    """
    if not confirmed:
      return []

    def rank(item: ConfirmedPII) -> tuple[float, int]:
      return (item.confidence, item.end - item.start)

    result: list[ConfirmedPII] = [confirmed[0]]
    for current in confirmed[1:]:
      previous = result[-1]
      if current.start < previous.end:
        if rank(current) > rank(previous):
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
