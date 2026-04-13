"""
PII 탐지 모듈 단위 테스트

STEP 1(정규식), STEP 2(체크섬), 경로별 분류, 마스킹을 테스트합니다.
"""


from rag.pii.step1_regex import PIIMatch, RegexDetector
from rag.pii.step2_checksum import ChecksumValidator

# ============================================================
# STEP 1: 정규식 탐지 테스트
# ============================================================

class TestRegexDetector:
  """RegexDetector의 패턴 매칭을 검증합니다."""

  def setup_method(self):
    self.detector = RegexDetector()

  # --- 휴대전화번호 ---
  def test_mobile_with_hyphen(self):
    matches = self.detector.detect("전화번호는 010-1234-5678입니다.")
    tags = [m.tag for m in matches]
    assert "QT_MOBILE" in tags

  def test_mobile_without_separator(self):
    matches = self.detector.detect("연락처: 01012345678")
    tags = [m.tag for m in matches]
    assert "QT_MOBILE" in tags

  # --- 이메일 ---
  def test_email(self):
    matches = self.detector.detect("이메일: hong@example.com")
    tags = [m.tag for m in matches]
    assert "TMI_EMAIL" in tags

  def test_email_complex(self):
    matches = self.detector.detect("test.user+tag@company.co.kr")
    tags = [m.tag for m in matches]
    assert "TMI_EMAIL" in tags

  # --- 주민등록번호 ---
  def test_rrn_pattern(self):
    matches = self.detector.detect("주민번호: 901015-1234567")
    tags = [m.tag for m in matches]
    assert "QT_RRN" in tags

  def test_rrn_needs_validation(self):
    matches = self.detector.detect("901015-1234567")
    rrn_matches = [m for m in matches if m.tag == "QT_RRN"]
    assert len(rrn_matches) > 0
    assert rrn_matches[0].needs_validation is True

  # --- 카드번호 ---
  def test_card_with_hyphen(self):
    matches = self.detector.detect("카드: 4532-1234-5678-9012")
    tags = [m.tag for m in matches]
    assert "QT_CARD" in tags

  # --- 여권번호 ---
  def test_passport(self):
    matches = self.detector.detect("여권번호: M12345678")
    tags = [m.tag for m in matches]
    assert "QT_PASSPORT" in tags

  # --- IP 주소 ---
  def test_ip_address(self):
    matches = self.detector.detect("서버 IP: 192.168.0.1")
    tags = [m.tag for m in matches]
    assert "QT_IP" in tags

  # --- 주소 ---
  def test_address(self):
    matches = self.detector.detect("서울특별시 광진구 능동로 209")
    tags = [m.tag for m in matches]
    assert "QT_ADDR" in tags

  # --- 탐지 결과 없음 ---
  def test_no_pii(self):
    matches = self.detector.detect("오늘 날씨가 좋습니다.")
    # PII가 없으면 빈 리스트여야 합니다
    # 일부 짧은 숫자 패턴이 매칭될 수 있지만 핵심 PII는 없어야 합니다
    core_tags = {"QT_MOBILE", "TMI_EMAIL", "QT_RRN", "QT_CARD"}
    detected_tags = {m.tag for m in matches}
    assert not (core_tags & detected_tags)

  # --- 여러 PII 동시 탐지 ---
  def test_multiple_pii(self):
    text = (
      "홍길동의 전화번호는 010-1234-5678이고 "
      "이메일은 hong@example.com입니다."
    )
    matches = self.detector.detect(text)
    tags = {m.tag for m in matches}
    assert "QT_MOBILE" in tags
    assert "TMI_EMAIL" in tags

  # --- PIIMatch 위치 정보 ---
  def test_match_position(self):
    text = "메일: hong@example.com"
    matches = self.detector.detect(text)
    email_matches = [m for m in matches if m.tag == "TMI_EMAIL"]
    assert len(email_matches) > 0
    m = email_matches[0]
    assert text[m.start:m.end] == m.text


# ============================================================
# STEP 2: 체크섬 검증 테스트
# ============================================================

class TestChecksumValidator:
  """ChecksumValidator의 체크섬 알고리즘을 검증합니다."""

  def setup_method(self):
    self.validator = ChecksumValidator()

  # --- 주민등록번호 체크섬 ---
  def test_rrn_invalid(self):
    # 가상의 번호 - 체크섬이 맞지 않아야 합니다
    assert self.validator.validate_rrn("901015-1234567") is False

  def test_rrn_wrong_length(self):
    assert self.validator.validate_rrn("12345") is False

  def test_rrn_non_numeric(self):
    assert self.validator.validate_rrn("abcdef-ghijklm") is False

  # --- 카드번호 Luhn ---
  def test_card_invalid(self):
    assert self.validator.validate_card("1234-5678-9012-3456") is False

  def test_card_wrong_length(self):
    assert self.validator.validate_card("1234") is False

  # --- filter_valid ---
  def test_filter_removes_invalid_rrn(self):
    """체크섬 실패한 주민번호는 필터링되어야 합니다."""
    matches = [
      PIIMatch(
        tag="QT_RRN", text="901015-1234567",
        start=0, end=14, needs_validation=True,
      ),
      PIIMatch(
        tag="TMI_EMAIL", text="test@example.com",
        start=20, end=36, needs_validation=False,
      ),
    ]
    valid = self.validator.filter_valid(matches)
    tags = [m.tag for m in valid]
    # 이메일은 통과, 잘못된 주민번호는 제거
    assert "TMI_EMAIL" in tags
    assert "QT_RRN" not in tags

  def test_filter_keeps_no_validation_items(self):
    """needs_validation=False 항목은 무조건 통과해야 합니다."""
    matches = [
      PIIMatch(
        tag="QT_MOBILE", text="010-1234-5678",
        start=0, end=13, needs_validation=False,
      ),
    ]
    valid = self.validator.filter_valid(matches)
    assert len(valid) == 1
    assert valid[0].tag == "QT_MOBILE"


# ============================================================
# 마스킹 테스트
# ============================================================

class TestPIIMasker:
  """PIIMasker의 태그별 마스킹 규칙을 검증합니다."""

  def setup_method(self):
    from rag.pii.masker import PIIMasker
    self.masker = PIIMasker()

  def test_mask_rrn(self):
    from rag.pii.classifier import ConfirmedPII
    pii = ConfirmedPII(
      tag="QT_RRN", text="901015-1234567",
      start=0, end=14, route="A-2", source="regex",
    )
    masked = self.masker.mask_single(pii)
    # 앞 6자리 보존, 나머지 마스킹
    assert "901015" in masked
    assert "1234567" not in masked

  def test_mask_mobile(self):
    from rag.pii.classifier import ConfirmedPII
    pii = ConfirmedPII(
      tag="QT_MOBILE", text="010-1234-5678",
      start=0, end=13, route="A-1", source="regex",
    )
    masked = self.masker.mask_single(pii)
    # 뒷 4자리 보존
    assert "5678" in masked

  def test_mask_email(self):
    from rag.pii.classifier import ConfirmedPII
    pii = ConfirmedPII(
      tag="TMI_EMAIL", text="hong@example.com",
      start=0, end=16, route="A-1", source="regex",
    )
    masked = self.masker.mask_single(pii)
    # 로컬파트 첫 글자 보존, 도메인 보존
    assert "h" in masked
    assert "example.com" in masked

  def test_mask_text_replaces_pii(self):
    from rag.pii.classifier import ConfirmedPII
    original = "전화번호: 010-1234-5678"
    piis = [
      ConfirmedPII(
        tag="QT_MOBILE", text="010-1234-5678",
        start=6, end=19, route="A-1", source="regex",
      ),
    ]
    masked = self.masker.mask_text(original, piis)
    assert "010-1234-5678" not in masked
    assert "5678" in masked
