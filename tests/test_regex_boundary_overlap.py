"""STEP 1 정규식 경계 · 겹침 해소 회귀 테스트.

두 가지를 고정한다.

① 숫자열 중간에서 매치가 끝나면 안 된다.
경계(`ASCII_LEFT_BOUNDARY`/`ASCII_RIGHT_BOUNDARY`)가 없던 시절 일반전화 패턴
`0[2-6][1-5]?…` 이 계좌·카드번호의 일부를 물어갔다. 우리 코퍼스 실측(2026-08-06):
확정 기준 QT_PHONE 586 → 528, 즉 58건이 오탐이었고 진짜 전화번호는 하나도
잃지 않았다. 예: `1002-345-678901`(계좌) → `02-345-6789`,
`4042-1377-5519-0958`(카드) → `042-1377-5519`.

② 겹치면 신뢰도 우선, 같으면 긴 스팬 우선.
정규식은 전부 confidence=1.0 이라 신뢰도만 비교하면 승자가 `PATTERNS` 선언 순서로
정해진다. 그래서 2002~2006년생 주민등록번호에서 앞 11자를 삼킨 QT_PHONE 이 온전한
QT_RRN 을 밀어냈다 — 등급이 고유식별 → 연락처로 강등되고, mod11 체크섬이 아예 안
돌고, 마스킹이 뒷자리를 놓쳤다(`**-****-3345671`).
"""

from __future__ import annotations

from rag.pii.classifier import PIIClassifier, risk_tier
from rag.pii.masker import PIIMasker
from rag.pii.step1_regex import RegexDetector
from rag.pii.step2_checksum import ChecksumValidator


def _confirm(text: str):
  """정규식 → 체크섬 → 분류(겹침 해소) 까지 실제 경로로 태운다."""
  detector = RegexDetector()
  validated, _rejected = ChecksumValidator().partition_valid(detector.detect(text))
  return PIIClassifier().classify(validated, [], [])


def _tags(text: str) -> set[str]:
  return {item.tag for item in _confirm(text)}


class TestBoundaryStopsPartialNumberMatches:
  def test_account_number_is_not_detected_as_landline(self):
    """계좌번호 중간의 `02-345-6789` 를 전화번호로 잡지 않는다."""
    assert "QT_PHONE" not in _tags("퇴직금 지급 은행 계좌 1002-345-678901 입니다.")

  def test_card_number_is_not_also_detected_as_landline(self):
    """카드번호를 카드로만 잡고, 그 일부를 전화번호로 중복 계상하지 않는다."""
    tags = _tags("신용카드 승인 실패: 4042-1377-5519-0958 건")
    assert "QT_PHONE" not in tags

  def test_real_landline_still_detected(self):
    """오탐을 막느라 진짜 전화번호까지 잃으면 안 된다."""
    assert "QT_PHONE" in _tags("대표번호는 02-1234-5678 입니다.")
    assert "QT_PHONE" in _tags("문의: 031-123-4567")

  def test_korean_particle_does_not_break_detection(self):
    """조사가 붙어도 탐지된다 — 경계를 ASCII 로만 잡은 이유."""
    assert "QT_PHONE" in _tags("연락처는 02-1234-5678로 주세요.")
    assert "QT_MOBILE" in _tags("휴대폰 010-1234-5678은 본인 명의입니다.")


class TestOverlapPrefersLongerSpanOnTie:
  # 2002~2006년생 주민등록번호. 앞 6자리가 `0[2-6][1-5]?` 에 걸려 예전에는
  # QT_PHONE 이 이 값을 가로챘다.
  RRN_TEXT = "직원 김민수 051109-3345671 자료"

  def test_resident_number_wins_over_partial_phone_match(self):
    confirmed = _confirm(self.RRN_TEXT)
    tags = {item.tag for item in confirmed}
    assert "QT_RRN" in tags
    assert "QT_PHONE" not in tags

  def test_resident_number_keeps_identifier_risk_tier(self):
    """등급이 고유식별(identifier)로 유지돼야 리포트 차분이 맞는다."""
    assert risk_tier("QT_RRN") == "identifier"
    confirmed = _confirm(self.RRN_TEXT)
    assert any(risk_tier(item.tag) == "identifier" for item in confirmed)

  def test_masking_covers_the_whole_resident_number(self):
    """마스킹이 뒷자리를 흘리지 않는다.

    스팬이 11자로 잘리면 `**-****-3345671` 처럼 주민번호 뒤 7자리가 산출물에
    평문으로 남았다.
    """
    masked = PIIMasker().mask_text(self.RRN_TEXT, _confirm(self.RRN_TEXT))
    assert "3345671" not in masked
    assert "051109" in masked  # 앞 6자리 보존은 기존 마스킹 정책 그대로

  def test_longer_span_wins_only_on_confidence_tie(self):
    """신뢰도가 다르면 여전히 신뢰도가 이긴다(길이가 신뢰도를 덮지 않는다)."""
    from rag.pii.classifier import ConfirmedPII

    short_high = ConfirmedPII(
      tag="QT_RRN", text="x", start=0, end=4, route="A-2", source="regex", confidence=1.0
    )
    long_low = ConfirmedPII(
      tag="PER", text="y", start=0, end=20, route="B-1", source="ner", confidence=0.9
    )
    kept = PIIClassifier()._remove_overlaps([short_high, long_low])
    assert [item.tag for item in kept] == ["QT_RRN"]
