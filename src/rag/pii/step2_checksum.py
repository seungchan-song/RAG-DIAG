"""
STEP 2: 체크섬/구조 검증 모듈

STEP 1에서 정규식으로 탐지된 PII 중, 추가 검증이 필요한 항목의
유효성을 체크섬 알고리즘으로 확인합니다.

검증 대상:
  1. 주민등록번호(QT_RRN): 가중치 합산 mod 11 체크섬
  2. 외국인등록번호(QT_ARN): 가중치 합산 mod 11 체크섬 (RRN과 동일)
  3. 신용카드번호(QT_CARD): Luhn 알고리즘

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

from loguru import logger

from rag.pii.step1_regex import PIIMatch


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
    if pii_match.tag in ("QT_RRN", "QT_ARN"):
      return self.validate_rrn(pii_match.text)
    elif pii_match.tag == "QT_CARD":
      return self.validate_card(pii_match.text)
    else:
      # 체크섬 검증 대상이 아닌 태그는 항상 True (검증 불필요)
      return True

  def filter_valid(self, matches: list[PIIMatch]) -> list[PIIMatch]:
    """
    PIIMatch 목록에서 체크섬 검증이 필요한 항목을 검증하고,
    유효한 항목만 필터링하여 반환합니다.

    동작:
      - needs_validation=False인 항목 → 그대로 통과 (경로 A-1)
      - needs_validation=True인 항목 → 체크섬 검증
        - 통과 → 결과에 포함 (경로 A-2)
        - 실패 → 결과에서 제외 (오탐)

    Args:
      matches: STEP 1에서 탐지된 PIIMatch 목록

    Returns:
      list[PIIMatch]: 체크섬 검증을 통과한 유효한 PIIMatch 목록
    """
    valid_matches: list[PIIMatch] = []

    for match in matches:
      if not match.needs_validation:
        # 검증 불필요 → 바로 통과 (경로 A-1)
        valid_matches.append(match)
      elif self.validate(match):
        # 체크섬 통과 → 유효 (경로 A-2)
        match.needs_validation = False  # 검증 완료 표시
        valid_matches.append(match)
      else:
        # 체크섬 실패 → 오탐으로 제거
        logger.debug(
          f"체크섬 실패로 제거: [{match.tag}] {match.text[:8]}..."
        )

    logger.debug(
      f"체크섬 검증 결과: {len(matches)}개 중 {len(valid_matches)}개 유효"
    )
    return valid_matches
