"""
경로별 PII 확정 로직 모듈

STEP 1~4의 결과를 종합하여 최종 PII 확정 판정을 내립니다.

탐지 경로:
  경로 A-1: 정규식 매칭 성공 + 유효성검증 불필요 → 즉시 PII 확정
  경로 A-2: 정규식 매칭 성공 + 체크섬 통과 → PII 확정
  경로 B-1: NER 탐지 성공 + 고F1 태그 → 즉시 PII 확정
  경로 B-2: NER 탐지 성공 + 저F1 태그 → sLLM 교차검증 통과 시 PII 확정

사용 예시:
  from rag.pii.classifier import PIIClassifier

  classifier = PIIClassifier()
  confirmed = classifier.classify(regex_matches, ner_b1, sllm_verified)
"""

from dataclasses import dataclass
from typing import Any

from loguru import logger

from rag.pii.step1_regex import PIIMatch
from rag.pii.step3_ner import NERMatch


@dataclass
class ConfirmedPII:
  """
  최종 확정된 PII 하나를 나타내는 데이터 클래스입니다.

  Attributes:
    tag: PII 유형 태그 (예: "QT_MOBILE", "PER")
    text: 탐지된 원문 텍스트
    start: 원문에서의 시작 위치
    end: 원문에서의 끝 위치
    route: 확정 경로 ("A-1", "A-2", "B-1", "B-2")
    source: 탐지 출처 ("regex" 또는 "ner")
    confidence: 신뢰도 (정규식은 1.0, NER은 모델 신뢰도)
  """
  tag: str
  text: str
  start: int
  end: int
  route: str
  source: str
  confidence: float = 1.0


class PIIClassifier:
  """
  4개 경로의 PII 탐지 결과를 종합하여 최종 확정하는 클래스입니다.

  정규식(A-1, A-2) + NER(B-1, B-2) 결과를 합쳐서
  중복을 제거하고 최종 PII 목록을 만듭니다.
  """

  def classify(
    self,
    regex_validated: list[PIIMatch],
    ner_b1: list[NERMatch],
    sllm_verified: list[NERMatch],
  ) -> list[ConfirmedPII]:
    """
    모든 경로의 결과를 종합하여 최종 PII 목록을 확정합니다.

    Args:
      regex_validated: STEP 1+2를 거친 정규식 탐지 결과
        - needs_validation=False였던 항목 (경로 A-1)
        - 체크섬 통과한 항목 (경로 A-2)
      ner_b1: STEP 3에서 고F1으로 분류된 NER 결과 (경로 B-1)
      sllm_verified: STEP 4에서 sLLM 검증 통과한 NER 결과 (경로 B-2)

    Returns:
      list[ConfirmedPII]: 최종 확정된 PII 목록
    """
    confirmed: list[ConfirmedPII] = []

    # === 경로 A: 정규식 기반 확정 ===
    for match in regex_validated:
      # needs_validation이 원래 True였는데 지금 False면 → 체크섬 통과 (A-2)
      # 원래 False였으면 → 검증 불필요 (A-1)
      route = "A-1"
      if match.tag in ("QT_RRN", "QT_ARN", "QT_CARD"):
        route = "A-2"  # 체크섬 검증을 거친 항목

      confirmed.append(ConfirmedPII(
        tag=match.tag,
        text=match.text,
        start=match.start,
        end=match.end,
        route=route,
        source="regex",
        confidence=1.0,  # 정규식 + 체크섬 통과 = 확실
      ))

    # === 경로 B-1: NER 고F1 즉시 확정 ===
    for match in ner_b1:
      confirmed.append(ConfirmedPII(
        tag=match.tag,
        text=match.text,
        start=match.start,
        end=match.end,
        route="B-1",
        source="ner",
        confidence=match.confidence,
      ))

    # === 경로 B-2: NER + sLLM 교차검증 통과 ===
    for match in sllm_verified:
      confirmed.append(ConfirmedPII(
        tag=match.tag,
        text=match.text,
        start=match.start,
        end=match.end,
        route="B-2",
        source="ner+sllm",
        confidence=match.confidence,
      ))

    # 위치 기준으로 정렬합니다 (텍스트 순서대로)
    confirmed.sort(key=lambda x: x.start)

    # 중복 제거: 같은 위치에 겹치는 PII가 있으면 신뢰도 높은 것을 우선합니다
    confirmed = self._remove_overlaps(confirmed)

    logger.info(
      f"PII 확정 완료: 총 {len(confirmed)}개 "
      f"(A-1: {sum(1 for c in confirmed if c.route == 'A-1')}, "
      f"A-2: {sum(1 for c in confirmed if c.route == 'A-2')}, "
      f"B-1: {sum(1 for c in confirmed if c.route == 'B-1')}, "
      f"B-2: {sum(1 for c in confirmed if c.route == 'B-2')})"
    )
    return confirmed

  def _remove_overlaps(self, confirmed: list[ConfirmedPII]) -> list[ConfirmedPII]:
    """
    위치가 겹치는 PII 중 신뢰도가 높은 것만 남깁니다.

    예: 정규식이 "010-1234-5678"을 잡고, NER도 같은 부분을 잡았으면
    정규식 결과(confidence=1.0)를 우선합니다.

    Args:
      confirmed: 위치순 정렬된 ConfirmedPII 목록

    Returns:
      list[ConfirmedPII]: 중복이 제거된 목록
    """
    if not confirmed:
      return []

    result: list[ConfirmedPII] = [confirmed[0]]

    for current in confirmed[1:]:
      prev = result[-1]

      # 이전 항목과 현재 항목의 위치가 겹치는지 확인
      if current.start < prev.end:
        # 겹치면 신뢰도가 높은 것을 남깁니다
        if current.confidence > prev.confidence:
          result[-1] = current  # 현재 것으로 교체
        # else: 이전 것을 유지
      else:
        # 겹치지 않으면 둘 다 유지
        result.append(current)

    return result

  def to_summary(self, confirmed: list[ConfirmedPII]) -> dict[str, Any]:
    """
    확정된 PII 목록을 태그별 요약으로 변환합니다.

    Args:
      confirmed: 확정된 PII 목록

    Returns:
      dict: 요약 정보
        - "total": 전체 PII 수
        - "by_tag": 태그별 건수 (예: {"QT_MOBILE": 2, "PER": 1})
        - "by_route": 경로별 건수 (예: {"A-1": 3, "B-2": 1})
        - "items": ConfirmedPII 목록
    """
    by_tag: dict[str, int] = {}
    by_route: dict[str, int] = {}

    for pii in confirmed:
      by_tag[pii.tag] = by_tag.get(pii.tag, 0) + 1
      by_route[pii.route] = by_route.get(pii.route, 0) + 1

    return {
      "total": len(confirmed),
      "by_tag": by_tag,
      "by_route": by_route,
      "items": confirmed,
    }
