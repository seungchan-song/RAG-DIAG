"""
PII 마스킹 모듈

확정된 PII를 태그별 규칙에 따라 마스킹(가림) 처리합니다.
원문 텍스트에서 개인정보 부분을 안전하게 대체합니다.

마스킹 규칙 (태그별):
  - QT_RRN (주민등록번호): 앞 6자리 보존 → "900101-*******"
  - QT_ARN (외국인등록번호): 앞 6자리 보존 → "900101-*******"
  - QT_CARD (카드번호): 끝 4자리 보존 → "****-****-****-9012"
  - QT_MOBILE (휴대폰): 뒷 4자리 보존 → "010-****-5678"
  - QT_PHONE (전화번호): 뒷 4자리 보존 → "02-****-5678"
  - TMI_EMAIL (이메일): 로컬파트 마스킹 → "h***@example.com"
  - PER (이름): 성씨 보존 → "홍**"
  - 기타: 전체 마스킹 → "[PII_태그]"

사용 예시:
  from rag.pii.masker import PIIMasker

  masker = PIIMasker()
  masked_text = masker.mask_text(original_text, confirmed_piis)
"""

import re

from loguru import logger

from rag.pii.classifier import ConfirmedPII


class PIIMasker:
  """
  확정된 PII를 마스킹 처리하는 클래스입니다.

  각 PII 태그별로 적절한 마스킹 규칙을 적용하여
  최소한의 정보는 보존하면서 개인정보를 보호합니다.
  """

  def mask_single(self, pii: ConfirmedPII) -> str:
    """
    단일 PII 항목을 마스킹합니다.

    태그에 따라 적절한 마스킹 규칙을 적용합니다.

    Args:
      pii: 마스킹할 ConfirmedPII 객체

    Returns:
      str: 마스킹된 문자열
    """
    text = pii.text
    tag = pii.tag

    if tag in ("QT_RRN", "QT_ARN"):
      return self._mask_rrn(text)
    elif tag == "QT_CARD":
      return self._mask_card(text)
    elif tag == "QT_MOBILE":
      return self._mask_mobile(text)
    elif tag == "QT_PHONE":
      return self._mask_phone(text)
    elif tag == "TMI_EMAIL":
      return self._mask_email(text)
    elif tag == "PER":
      return self._mask_name(text)
    else:
      # 기타 태그는 전체 마스킹
      return f"[{tag}]"

  def mask_text(self, text: str, piis: list[ConfirmedPII]) -> str:
    """
    원문 텍스트에서 모든 확정 PII를 마스킹합니다.

    PII 위치를 뒤에서부터 치환하여 인덱스가 밀리지 않게 합니다.

    Args:
      text: 원문 텍스트
      piis: 확정된 PII 목록 (위치 정보 포함)

    Returns:
      str: PII가 마스킹된 텍스트
    """
    # 뒤에서부터 치환해야 앞쪽 인덱스가 밀리지 않습니다
    sorted_piis = sorted(piis, key=lambda p: p.start, reverse=True)

    masked = text
    for pii in sorted_piis:
      replacement = self.mask_single(pii)
      masked = masked[:pii.start] + replacement + masked[pii.end:]

    masked_count = len(piis)
    if masked_count > 0:
      logger.info(f"PII 마스킹 완료: {masked_count}개 항목 처리")

    return masked

  def _mask_rrn(self, text: str) -> str:
    """
    주민등록번호/외국인등록번호 마스킹: 앞 6자리 보존

    예: "900101-1234567" → "900101-*******"
    """
    digits = re.sub(r"[-.\s]", "", text)
    if len(digits) >= 6:
      return digits[:6] + "-*******"
    return "[QT_RRN]"

  def _mask_card(self, text: str) -> str:
    """
    카드번호 마스킹: 끝 4자리 보존

    예: "4532-1234-5678-9012" → "****-****-****-9012"
    """
    digits = re.sub(r"[-.\s]", "", text)
    if len(digits) >= 4:
      last4 = digits[-4:]
      return f"****-****-****-{last4}"
    return "[QT_CARD]"

  def _mask_mobile(self, text: str) -> str:
    """
    휴대전화번호 마스킹: 뒷 4자리 보존

    예: "010-1234-5678" → "010-****-5678"
    """
    digits = re.sub(r"[-.\s]", "", text)
    if len(digits) >= 4:
      last4 = digits[-4:]
      return f"010-****-{last4}"
    return "[QT_MOBILE]"

  def _mask_phone(self, text: str) -> str:
    """
    일반전화번호 마스킹: 뒷 4자리 보존

    예: "02-1234-5678" → "**-****-5678"
    """
    digits = re.sub(r"[-.\s]", "", text)
    if len(digits) >= 4:
      last4 = digits[-4:]
      return f"**-****-{last4}"
    return "[QT_PHONE]"

  def _mask_email(self, text: str) -> str:
    """
    이메일 마스킹: 로컬파트 첫 글자 보존 + 도메인 유지

    예: "hong@example.com" → "h***@example.com"
    """
    parts = text.split("@")
    if len(parts) == 2:
      local = parts[0]
      domain = parts[1]
      if len(local) >= 1:
        return f"{local[0]}***@{domain}"
    return "[TMI_EMAIL]"

  def _mask_name(self, text: str) -> str:
    """
    사람 이름 마스킹: 성씨(첫 글자) 보존

    예: "홍길동" → "홍**"
        "김영희" → "김**"
    """
    if len(text) >= 1:
      return text[0] + "*" * (len(text) - 1)
    return "[PER]"
