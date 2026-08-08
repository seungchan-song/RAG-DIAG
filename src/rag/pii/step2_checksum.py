"""
STEP 2: 체크섬/구조 검증 모듈

STEP 1에서 정규식으로 탐지된 PII 중, 추가 검증이 필요한 항목의
유효성을 체크섬 알고리즘으로 확인합니다.

검증 대상:
  1. 주민등록번호(QT_RRN): 가중치 합산 mod 11 체크섬
  2. 신용카드번호(QT_CARD): Luhn 알고리즘
  3. 외국인등록번호(QT_ARN): **검증하지 않는다** (아래 참조)

외국인등록번호에 체크섬을 걸지 않는 이유 (2026-08-03 실측으로 확정):
  - 구 외국인등록번호(2020-10 이전)는 주민등록번호와 **다른** 검증식을 쓴다
    (mod 11 결과에 +2 후 mod 10). 예전 이 모듈은 "RRN 과 동일"로 처리했는데
    그건 틀린 가정이었다.
  - 2020-10 부터 신규 외국인등록번호는 뒷자리가 임의번호로 바뀌어 **검증번호
    체계 자체가 폐지**됐다. 즉 어떤 공식으로도 검증할 수 없는 번호가 존재한다.
  - 실측: 자체 데이터셋의 외국인등록번호 996건을 두 공식으로 각각 돌린 결과
    주민번호 공식 10.5% / 구 외국인등록번호 공식 10.1% — 둘 다 무작위 수준.
  → 검증하면 진짜 유출을 대량으로 탈락시켜 미탐이 된다. 자릿수·성별코드(5~8)
    구조는 STEP 1 정규식이 이미 강제하므로 그것으로 충분하다고 본다(경로 A-1).

⚠️ 주민등록번호도 2020-10 부터 임의번호화돼 검증번호가 없다. 이 모듈의 mod 11
   은 그 이후 발급 번호를 탈락시킨다. 다만 탈락분은 버려지지 않고 rejection
   채널에 "구조 일치·검증 탈락"으로 남아 리포트에 보이므로, 오탐 제거 효과와
   맞바꿔 현행 유지한다. 실제 최신 번호가 섞인 코퍼스로 재측정할 것.

동작 방식:
  - STEP 1의 PIIMatch 중 needs_validation=True인 항목만 검증합니다
  - 체크섬 통과 → PII 확정 (경로 A-2)
  - 체크섬 실패 → 해당 항목 제거 (오탐으로 판단)

사용 예시:
  from rag.pii.step2_checksum import ChecksumValidator

  validator = ChecksumValidator()
  is_valid = validator.validate_rrn("900101-1234567")  # True/False
  is_valid = validator.validate_card("4532-1234-5678-9012")
"""

import re
from dataclasses import dataclass

from loguru import logger

from rag.pii.step1_regex import PIIMatch


@dataclass
class RejectedPII:
  """
  체크섬/구조 검증에서 탈락한 PII 후보 하나를 나타내는 데이터 클래스입니다.

  정규식 구조는 PII와 일치했지만 체크섬(mod11/Luhn)을 통과하지 못해
  '확정 PII'에서 제외된 항목입니다. 응답에 주민번호처럼 생긴 문자열이
  있는데 탐지 목록에 없으면 미탐(누락)으로 오해할 수 있으므로, 버리지 않고
  사유와 함께 별도 트랙으로 보존해 리포트에 "구조 일치·검증 탈락"으로
  노출합니다.

  Attributes:
    tag: PII 유형 태그 (예: "QT_RRN", "QT_CARD")
    text: 탈락한 원문 텍스트 (저장 전 detector 에서 마스킹 처리됨)
    start: 원문에서의 시작 위치 (인덱스)
    end: 원문에서의 끝 위치 (인덱스)
    reason: 탈락 사유 (예: "checksum_failed")
    validator: 사용한 검증 알고리즘 (예: "mod11", "luhn")
    source: 탐지 출처 ("regex" 고정)
  """
  tag: str
  text: str
  start: int
  end: int
  reason: str
  validator: str
  source: str = "regex"


class ChecksumValidator:
  """
  체크섬 알고리즘으로 PII의 유효성을 검증하는 클래스입니다.

  정규식으로 탐지된 값이 실제 유효한 개인정보인지 확인합니다.
  예를 들어, "123456-1234567" 형태지만 체크섬이 맞지 않으면
  실제 주민등록번호가 아닌 것으로 판단하여 오탐을 줄입니다.
  """

  def validate_rrn(self, text: str) -> bool:
    """
    주민등록번호/외국인등록번호의 체크섬을 검증합니다.

    검증 방법 (mod 11 체크섬):
      1. 앞 12자리에 가중치 [2,3,4,5,6,7,8,9,2,3,4,5]를 각각 곱합니다
      2. 곱한 값을 모두 더합니다
      3. (11 - (합계 mod 11)) mod 10 = 마지막 자리(체크디짓)이면 유효

    Args:
      text: 주민등록번호 문자열 (예: "900101-1234567" 또는 "9001011234567")

    Returns:
      bool: 체크섬이 유효하면 True, 아니면 False
    """
    # 하이픈, 공백, 점 등 구분자를 제거하여 순수 13자리 숫자만 남깁니다
    digits = re.sub(r"[-.\s]", "", text)

    # 13자리가 아니면 유효하지 않음
    if len(digits) != 13 or not digits.isdigit():
      return False

    # 가중치 배열: 앞 12자리에 순서대로 곱할 값
    weights = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]

    # 각 자릿수 × 가중치를 합산합니다
    total = sum(int(digits[i]) * weights[i] for i in range(12))

    # 체크디짓 계산: (11 - (합계 mod 11)) mod 10
    check_digit = (11 - (total % 11)) % 10

    # 마지막 자리(13번째)와 체크디짓이 일치하면 유효
    is_valid = int(digits[12]) == check_digit

    if is_valid:
      logger.debug(f"주민/외국인등록번호 체크섬 통과: {text[:6]}******")
    else:
      logger.debug(f"주민/외국인등록번호 체크섬 실패: {text[:6]}******")

    return is_valid

  def validate_card(self, text: str) -> bool:
    """
    신용카드번호의 유효성을 Luhn 알고리즘으로 검증합니다.

    Luhn 알고리즘 동작 방식:
      1. 오른쪽부터 짝수 번째 자릿수를 2배 합니다
      2. 2배 한 결과가 9보다 크면 9를 뺍니다
      3. 모든 자릿수를 합산합니다
      4. 합계가 10의 배수이면 유효

    예시:
      카드번호: 4532015112830366
      → Luhn 합계 = 40 → 40 % 10 == 0 → 유효!

    Args:
      text: 카드번호 문자열 (예: "4532-1234-5678-9012" 또는 "4532123456789012")

    Returns:
      bool: Luhn 체크가 유효하면 True, 아니면 False
    """
    # 구분자 제거
    digits = re.sub(r"[-.\s]", "", text)

    # 16자리가 아니거나 숫자가 아니면 유효하지 않음
    if len(digits) != 16 or not digits.isdigit():
      return False

    # Luhn 알고리즘 적용
    total = 0
    for i, digit_char in enumerate(reversed(digits)):
      digit = int(digit_char)

      # 오른쪽부터 짝수 번째 자리(인덱스 1, 3, 5...)를 2배 합니다
      if i % 2 == 1:
        digit *= 2
        # 2배 한 결과가 9보다 크면 9를 뺍니다 (또는 각 자릿수 합)
        if digit > 9:
          digit -= 9

      total += digit

    # 합계가 10의 배수이면 유효
    is_valid = total % 10 == 0

    if is_valid:
      logger.debug(f"카드번호 Luhn 체크 통과: {text[:4]}****")
    else:
      logger.debug(f"카드번호 Luhn 체크 실패: {text[:4]}****")

    return is_valid

  def validate(self, pii_match: PIIMatch) -> bool:
    """
    PIIMatch의 태그에 따라 적절한 체크섬 검증을 수행합니다.

    Args:
      pii_match: STEP 1에서 탐지된 PIIMatch 객체

    Returns:
      bool: 체크섬 검증 결과 (True=유효, False=무효)
    """
    if pii_match.tag == "QT_RRN":
      return self.validate_rrn(pii_match.text)
    elif pii_match.tag == "QT_CARD":
      return self.validate_card(pii_match.text)
    else:
      # QT_ARN(외국인등록번호) 포함 — 검증 가능한 체크섬이 없는 태그는 통과시킨다.
      # 사유는 모듈 docstring 참조(검증식이 다르고 2020-10 이후 폐지됨).
      return True

  def _validator_name(self, tag: str) -> str:
    """
    태그에 어떤 체크섬 알고리즘이 적용되는지 사람이 읽을 수 있는 이름으로 반환합니다.

    리포트에 "어떤 검증에서 탈락했는지"를 표시하기 위한 라벨입니다.

    Args:
      tag: PII 유형 태그

    Returns:
      str: 검증 알고리즘 이름 ("mod11" / "luhn" / "none")
    """
    if tag == "QT_RRN":
      return "mod11"
    elif tag == "QT_CARD":
      return "luhn"
    else:
      return "none"

  def partition_valid(
    self,
    matches: list[PIIMatch],
  ) -> tuple[list[PIIMatch], list[RejectedPII]]:
    """
    PIIMatch 목록을 "검증 통과(유효)"와 "체크섬 탈락"으로 분리하여 반환합니다.

    filter_valid 이 유효 항목만 돌려주고 탈락 항목을 조용히 버리는 것과 달리,
    이 메서드는 탈락 항목도 사유와 함께 함께 반환합니다. 응답에 주민번호처럼
    생긴 문자열이 남아 있는데 탐지 목록에 없을 때 미탐으로 오해받지 않도록,
    "구조는 일치했으나 검증 탈락"임을 리포트에 노출하기 위해 사용합니다.

    동작:
      - needs_validation=False인 항목 → 유효로 통과 (경로 A-1)
      - needs_validation=True인 항목 → 체크섬 검증
        - 통과 → 유효 목록에 포함 (경로 A-2)
        - 실패 → 탈락 목록에 RejectedPII 로 기록 (버리지 않음)

    Args:
      matches: STEP 1에서 탐지된 PIIMatch 목록

    Returns:
      tuple[list[PIIMatch], list[RejectedPII]]:
        (검증을 통과한 유효 매치, 체크섬 탈락 항목) 두 목록의 튜플
    """
    valid_matches: list[PIIMatch] = []
    rejected: list[RejectedPII] = []

    for match in matches:
      if not match.needs_validation:
        # 검증 불필요 → 바로 통과 (경로 A-1)
        valid_matches.append(match)
      elif self.validate(match):
        # 체크섬 통과 → 유효 (경로 A-2)
        match.needs_validation = False  # 검증 완료 표시
        valid_matches.append(match)
      else:
        # 체크섬 실패 → 버리지 않고 사유와 함께 탈락 목록에 기록
        rejected.append(
          RejectedPII(
            tag=match.tag,
            text=match.text,
            start=match.start,
            end=match.end,
            reason="checksum_failed",
            validator=self._validator_name(match.tag),
          )
        )
        logger.debug(
          f"체크섬 실패로 탈락(보존): [{match.tag}] {match.text[:8]}..."
        )

    logger.debug(
      f"체크섬 검증 결과: {len(matches)}개 중 유효 {len(valid_matches)}개, "
      f"탈락 {len(rejected)}개"
    )
    return valid_matches, rejected

  def filter_valid(self, matches: list[PIIMatch]) -> list[PIIMatch]:
    """
    PIIMatch 목록에서 체크섬 검증을 통과한 유효한 항목만 반환합니다.

    내부적으로 partition_valid 를 호출하며, 탈락 항목은 버립니다.
    기존 호출자와의 호환을 위한 얇은 래퍼입니다. 탈락 항목까지 함께
    받으려면 partition_valid 를 사용하세요.

    Args:
      matches: STEP 1에서 탐지된 PIIMatch 목록

    Returns:
      list[PIIMatch]: 체크섬 검증을 통과한 유효한 PIIMatch 목록
    """
    valid_matches, _ = self.partition_valid(matches)
    return valid_matches
