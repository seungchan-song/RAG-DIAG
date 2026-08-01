"""Tests for PII detection, masking, runtime status, and artifact safety."""

from __future__ import annotations

import sys
import types

from rag.attack.base import AttackResult
from rag.pii.artifacts import sanitize_results_for_storage
from rag.pii.detector import PIIDetector
from rag.pii.step0_normalize import TextNormalizer
from rag.pii.step1_regex import PIIMatch, RegexDetector
from rag.pii.step2_checksum import ChecksumValidator
from rag.pii.step3_ner import NERDetector, NERMatch
from rag.pii.step4_sllm import SLLMVerifier


def _build_pii_config(
  *,
  enable_step3: bool = True,
  enable_step4: bool = True,
  model_path: str = "townboy/kpfbert-kdpii",
) -> dict:
  return {
    "pii": {
      "runtime": {
        "enable_step3": enable_step3,
        "enable_step4": enable_step4,
      },
      "ner": {
        "model_path": model_path,
        "confidence_threshold": 0.8,
      },
      "sllm": {
        "model": "gpt-4o-mini",
        "max_retries": 1,
        "retry_backoff": 1,
      },
    },
    "report": {
      "mask_raw_pii": True,
      "persist_raw_response": False,
    },
  }


class TestRegexDetector:
  def setup_method(self) -> None:
    self.detector = RegexDetector()

  def test_mobile_with_hyphen(self) -> None:
    matches = self.detector.detect("전화번호는 010-1234-5678입니다.")
    assert "QT_MOBILE" in [match.tag for match in matches]

  def test_mobile_without_separator(self) -> None:
    matches = self.detector.detect("연락처 01012345678")
    assert "QT_MOBILE" in [match.tag for match in matches]

  def test_email(self) -> None:
    matches = self.detector.detect("이메일 hong@example.com")
    assert "TMI_EMAIL" in [match.tag for match in matches]

  def test_email_complex(self) -> None:
    matches = self.detector.detect("test.user+tag@company.co.kr")
    assert "TMI_EMAIL" in [match.tag for match in matches]

  def test_rrn_pattern(self) -> None:
    matches = self.detector.detect("주민번호: 901015-1234567")
    assert "QT_RRN" in [match.tag for match in matches]

  def test_rrn_needs_validation(self) -> None:
    matches = self.detector.detect("901015-1234567")
    rrn_matches = [match for match in matches if match.tag == "QT_RRN"]
    assert rrn_matches
    assert rrn_matches[0].needs_validation is True

  def test_card_with_hyphen(self) -> None:
    matches = self.detector.detect("카드: 4532-1234-5678-9012")
    assert "QT_CARD" in [match.tag for match in matches]

  def test_passport(self) -> None:
    matches = self.detector.detect("여권번호: M12345678")
    assert "QT_PASSPORT" in [match.tag for match in matches]

  def test_ip_address(self) -> None:
    matches = self.detector.detect("서버 IP: 192.168.0.1")
    assert "QT_IP" in [match.tag for match in matches]

  def test_address(self) -> None:
    matches = self.detector.detect("서울특별시 광진구 능동로 209")
    assert "QT_ADDR" in [match.tag for match in matches]

  def test_new_33_category_identifiers(self) -> None:
    """개인정보 33종 개편으로 코퍼스에 심긴 고정 포맷 식별자 5종을 잡는지 확인한다.

    이 패턴들이 빠지면 해당 PII 가 유출돼도 리포트에 0건으로 찍힌다(과소보고).
    """
    text = (
      "성명 홍길동 (사원번호 EMP-2024-13579), 회원 MBR1234567, "
      "참가번호 PART-4821, ID: admin_7391, 주소 서울 강남구 테헤란로 12 (우편번호 06234)"
    )
    tags = {match.tag for match in self.detector.detect(text)}
    assert {
      "EMPLOYEE_ID", "MEMBER_ID", "PARTICIPANT_ID", "USER_ID", "ZIPCODE",
    } <= tags

  def test_member_id_not_mistaken_for_passport(self) -> None:
    """MBR1234567 이 여권번호(영문+숫자)로 오분류되지 않아야 한다.

    오분류되면 '고유식별' 위험 등급 건수가 실제보다 부풀려진다.
    """
    from rag.pii.classifier import PIIClassifier

    matches = self.detector.detect("회원 MBR1234567 입니다.")
    confirmed = PIIClassifier().classify(matches, [], [])
    assert [item.tag for item in confirmed] == ["MEMBER_ID"]

  def test_bare_five_digit_number_is_not_zipcode(self) -> None:
    matches = self.detector.detect("이번 분기 예산은 45000 만원입니다.")
    assert "ZIPCODE" not in [match.tag for match in matches]

  def test_no_pii(self) -> None:
    matches = self.detector.detect("오늘 날씨가 좋습니다.")
    core_tags = {"QT_MOBILE", "TMI_EMAIL", "QT_RRN", "QT_CARD"}
    assert not (core_tags & {match.tag for match in matches})

  def test_multiple_pii(self) -> None:
    matches = self.detector.detect(
      "홍길동의 전화번호는 010-1234-5678이고 이메일은 hong@example.com입니다."
    )
    tags = {match.tag for match in matches}
    assert "QT_MOBILE" in tags
    assert "TMI_EMAIL" in tags

  def test_match_position(self) -> None:
    text = "메일: hong@example.com"
    matches = self.detector.detect(text)
    email_match = next(match for match in matches if match.tag == "TMI_EMAIL")
    assert text[email_match.start:email_match.end] == email_match.text


class TestChecksumValidator:
  def setup_method(self) -> None:
    self.validator = ChecksumValidator()

  def test_rrn_invalid(self) -> None:
    assert self.validator.validate_rrn("901015-1234567") is False

  def test_rrn_wrong_length(self) -> None:
    assert self.validator.validate_rrn("12345") is False

  def test_rrn_non_numeric(self) -> None:
    assert self.validator.validate_rrn("abcdef-ghijklm") is False

  def test_card_invalid(self) -> None:
    assert self.validator.validate_card("1234-5678-9012-3456") is False

  def test_card_wrong_length(self) -> None:
    assert self.validator.validate_card("1234") is False

  def test_filter_removes_invalid_rrn(self) -> None:
    matches = [
      PIIMatch(
        tag="QT_RRN",
        text="901015-1234567",
        start=0,
        end=14,
        needs_validation=True,
      ),
      PIIMatch(
        tag="TMI_EMAIL",
        text="test@example.com",
        start=20,
        end=36,
        needs_validation=False,
      ),
    ]
    valid = self.validator.filter_valid(matches)
    assert "TMI_EMAIL" in [match.tag for match in valid]
    assert "QT_RRN" not in [match.tag for match in valid]

  def test_filter_keeps_no_validation_items(self) -> None:
    valid = self.validator.filter_valid(
      [
        PIIMatch(
          tag="QT_MOBILE",
          text="010-1234-5678",
          start=0,
          end=13,
          needs_validation=False,
        ),
      ]
    )
    assert len(valid) == 1
    assert valid[0].tag == "QT_MOBILE"

  def test_partition_valid_captures_rejected_rrn(self) -> None:
    matches = [
      PIIMatch(
        tag="QT_RRN",
        text="901015-1234567",
        start=0,
        end=14,
        needs_validation=True,
      ),
      PIIMatch(
        tag="TMI_EMAIL",
        text="test@example.com",
        start=20,
        end=36,
        needs_validation=False,
      ),
    ]
    valid, rejected = self.validator.partition_valid(matches)

    # 유효 목록에는 이메일만 남고, 체크섬 탈락 주민번호는 rejected 로 분리된다.
    assert [match.tag for match in valid] == ["TMI_EMAIL"]
    assert len(rejected) == 1
    assert rejected[0].tag == "QT_RRN"
    assert rejected[0].reason == "checksum_failed"
    assert rejected[0].validator == "mod11"


class TestStep0Normalizer:
  def setup_method(self) -> None:
    self.normalizer = TextNormalizer(_build_pii_config())

  def test_clean_text_is_unchanged(self) -> None:
    result = self.normalizer.normalize("연락처는 010-1234-5678 입니다.")
    assert result.changed is False
    assert result.applied == []

  def test_fullwidth_digits_folded(self) -> None:
    result = self.normalizer.normalize("０１０－１２３４－５６７８")
    assert result.normalized_text == "010-1234-5678"
    assert "compat" in result.applied

  def test_zero_width_removed(self) -> None:
    result = self.normalizer.normalize("0​1​0​1234​5678")
    assert result.normalized_text == "01012345678"
    assert "invisible" in result.applied

  def test_jamo_composition(self) -> None:
    result = self.normalizer.normalize("ㅎㅗㅇㄱㅣㄹㄷㅗㅇ")
    assert result.normalized_text == "홍길동"
    assert "jamo" in result.applied
    # 음절 3개가 자모 9개에서 나왔으므로 원문 스팬으로 되돌리면 전체를 덮는다.
    assert result.to_original_span(0, 3) == (0, 9)

  def test_emoticon_consonants_are_preserved(self) -> None:
    # 모음이 없는 자음 나열은 결합되지 않아 흔한 이모티콘이 보존된다.
    result = self.normalizer.normalize("아 진짜 ㅋㅋㅋ")
    assert result.changed is False

  def test_spaced_digits_gated_and_stripped(self) -> None:
    # 규칙적 숫자 공백열(5자리 이상)이면 숫자 사이 공백을 제거한다.
    result = self.normalizer.normalize("0 1 0 1 2")
    assert result.normalized_text == "01012"
    assert "digit_sep" in result.applied

  def test_prose_spacing_not_stripped(self) -> None:
    # 산문의 우연한 숫자 공백(짧은 열)은 건드리지 않는다.
    result = self.normalizer.normalize("방 302 호실 5명")
    assert result.changed is False

  def test_disabled_returns_identity(self) -> None:
    config = _build_pii_config()
    config["pii"]["runtime"]["enable_step0"] = False
    normalizer = TextNormalizer(config)
    result = normalizer.normalize("０１０")
    assert result.normalized_text == "０１０"
    assert result.changed is False


class TestPIIMasker:
  def setup_method(self) -> None:
    from rag.pii.masker import PIIMasker

    self.masker = PIIMasker()

  def test_mask_rrn(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    masked = self.masker.mask_single(
      ConfirmedPII(
        tag="QT_RRN",
        text="901015-1234567",
        start=0,
        end=14,
        route="A-2",
        source="regex",
      )
    )
    assert "901015" in masked
    assert "1234567" not in masked

  def test_mask_mobile(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    masked = self.masker.mask_single(
      ConfirmedPII(
        tag="QT_MOBILE",
        text="010-1234-5678",
        start=0,
        end=13,
        route="A-1",
        source="regex",
      )
    )
    assert "5678" in masked

  def test_mask_email(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    masked = self.masker.mask_single(
      ConfirmedPII(
        tag="TMI_EMAIL",
        text="hong@example.com",
        start=0,
        end=16,
        route="A-1",
        source="regex",
      )
    )
    assert "h" in masked
    assert "example.com" in masked

  def test_mask_text_replaces_pii(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    original = "전화번호: 010-1234-5678"
    masked = self.masker.mask_text(
      original,
      [
        ConfirmedPII(
          tag="QT_MOBILE",
          text="010-1234-5678",
          start=6,
          end=19,
          route="A-1",
          source="regex",
        ),
      ],
    )
    assert "010-1234-5678" not in masked
    assert "5678" in masked


class TestNERDetectorRuntime:
  def test_prefers_local_model_path_when_present(self, monkeypatch, tmp_path) -> None:
    local_model_dir = tmp_path / "local-kdpii"
    local_model_dir.mkdir()

    captured: dict[str, str] = {}
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(*, model: str, tokenizer: str, **_: object):  # type: ignore[override]
      captured["model"] = model
      captured["tokenizer"] = tokenizer
      return lambda text: []

    transformers_module.pipeline = lambda task, **kwargs: fake_pipeline(**kwargs)
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)

    detector = NERDetector(
      _build_pii_config(model_path=str(local_model_dir))
    )
    detector.warm_up()
    status = detector.get_runtime_status()

    assert status["model_source"] == "local"
    assert status["load_status"] == "ready"
    assert status["resolved_model_identifier"] == str(local_model_dir)
    assert captured["model"] == str(local_model_dir)

  def test_records_failed_status_when_model_load_fails(self, monkeypatch) -> None:
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(_: str, **__: object) -> object:
      raise RuntimeError("hf download failed")

    transformers_module.pipeline = fake_pipeline
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)

    detector = NERDetector(_build_pii_config())
    detector.warm_up()
    status = detector.get_runtime_status()

    assert status["model_source"] == "hub"
    assert status["load_status"] == "failed"
    assert "hf download failed" in status["error"]


class TestSLLMVerifierRuntime:
  def test_mock_conservative_without_api_key(self, monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    verifier = SLLMVerifier(_build_pii_config())
    matches = [
      NERMatch(
        tag="PER",
        text="홍길동",
        start=0,
        end=3,
        confidence=0.91,
      )
    ]
    verified = verifier.verify_batch(matches, "홍길동이 방문했다.")
    status = verifier.get_runtime_status(
      candidate_count=len(matches),
      verified_count=len(verified),
      reason="mock_conservative",
    )

    assert len(verified) == 1
    assert status["mode"] == "mock_conservative"
    assert status["reason"] == "mock_conservative"


class TestPIIHardening:
  def test_detector_marks_step3_unavailable_without_crashing(self, monkeypatch) -> None:
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(_: str, **__: object) -> object:
      raise RuntimeError("model missing")

    transformers_module.pipeline = fake_pipeline
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    detector = PIIDetector(_build_pii_config())
    detector.warm_up()
    result = detector.detect("홍길동은 example@example.com으로 연락했다.")

    assert result["runtime_status"]["step3"]["load_status"] == "failed"
    assert result["runtime_status"]["step4"]["reason"] == "step3_unavailable"
    assert result["summary"]["total"] >= 1

  def test_sanitize_results_masks_response_and_attaches_pii_metadata(self) -> None:
    raw_response = "연락처는 010-1234-5678이고 이메일은 hong@example.com입니다."
    results = [
      AttackResult(
        scenario="R2",
        query="테스트 질의",
        response=raw_response,
      )
    ]

    sanitized = sanitize_results_for_storage(
      results,
      _build_pii_config(enable_step3=False, enable_step4=False),
    )[0]

    assert sanitized.response == sanitized.response_masked
    assert sanitized.masking_applied is True
    assert "010-1234-5678" not in sanitized.response
    assert "hong@example.com" not in sanitized.response
    assert sanitized.pii_summary["total"] >= 2
    assert sanitized.pii_summary["has_high_risk"] is True
    assert sanitized.pii_runtime_status["step3"]["load_status"] == "skipped"
    assert sanitized.pii_runtime_status["step4"]["reason"] == "disabled"
    assert sanitized.metadata["response_storage_mode"] == "masked"
    assert all("text" not in finding for finding in sanitized.pii_findings)
    assert all("masked_text" in finding for finding in sanitized.pii_findings)

  def test_detector_reports_checksum_rejected_without_confirming(self) -> None:
    # step3/step4 를 꺼서 정규식+체크섬 경로만 남긴 뒤, 체크섬 미통과 주민번호가
    # 확정 목록이 아니라 rejected 트랙에 사유와 함께 보존되는지 검증한다.
    detector = PIIDetector(_build_pii_config(enable_step3=False, enable_step4=False))
    detector.warm_up()
    result = detector.detect("주민번호 901015-1234567, 이메일 hong@example.com")

    # 확정 목록에는 주민번호가 없어야 한다(체크섬 탈락 → 확정 제외).
    assert all(finding["tag"] != "QT_RRN" for finding in result["findings"])
    assert any(finding["tag"] == "TMI_EMAIL" for finding in result["findings"])
    # 클린 텍스트라 정규화가 손대지 않았으므로 복원 플래그는 False 여야 한다(오탐 방지).
    email = next(f for f in result["findings"] if f["tag"] == "TMI_EMAIL")
    assert email["recovered"] is False

    # rejected 트랙에 사유·검증기·마스킹과 함께 보존되어야 한다.
    assert len(result["rejected"]) == 1
    rejected = result["rejected"][0]
    assert rejected["tag"] == "QT_RRN"
    assert rejected["reason"] == "checksum_failed"
    assert rejected["validator"] == "mod11"
    assert rejected["status"] == "structurally_matched_unverified"
    assert "text" not in rejected  # 원문 키는 노출하지 않는다
    assert "1234567" not in rejected["masked_text"]  # 뒷자리 마스킹

    # 집계 왜곡 방지: rejected 는 확정 탐지 총계와 분리되어 카운트된다.
    assert result["runtime_status"]["step2"]["rejected_count"] == 1

  def test_sanitize_results_preserves_checksum_rejected(self) -> None:
    results = [
      AttackResult(
        scenario="R2",
        query="테스트 질의",
        response="주민번호 901015-1234567 참고 바랍니다.",
      )
    ]

    sanitized = sanitize_results_for_storage(
      results,
      _build_pii_config(enable_step3=False, enable_step4=False),
    )[0]

    assert len(sanitized.pii_rejected) == 1
    rejected = sanitized.pii_rejected[0]
    assert rejected["tag"] == "QT_RRN"
    assert rejected["reason"] == "checksum_failed"
    assert "text" not in rejected
    assert "1234567" not in rejected["masked_text"]

  def test_step0_recovers_fullwidth_phone(self) -> None:
    # 전각으로 변형된 휴대폰 번호가 STEP 0 정규화 후 정규식에 다시 잡히는지 검증한다.
    detector = PIIDetector(_build_pii_config(enable_step3=False, enable_step4=False))
    detector.warm_up()
    result = detector.detect_and_mask("연락처는 ０１０－１２３４－５６７８ 입니다.")

    tags = [finding["tag"] for finding in result["findings"]]
    assert "QT_MOBILE" in tags
    assert result["runtime_status"]["step0"]["changed"] is True
    # 전각 → 반각 복원으로 잡힌 항목이므로 recovered 플래그가 True 여야 한다(리포트 노출용).
    mobile = next(f for f in result["findings"] if f["tag"] == "QT_MOBILE")
    assert mobile["recovered"] is True
    # 원문(전각) 구간이 정규화된 마스킹 표현으로 치환되어 뒷자리가 그대로 남지 않는다.
    assert "１２３４" not in result["masked_text"]
    assert "010-****-5678" in result["masked_text"]

  def test_step0_fullwidth_invalid_rrn_flows_to_rejection(self) -> None:
    # STEP 0 가 구조를 복원했지만 체크섬이 실패하면 rejection 채널로 흘러가는지 검증한다.
    detector = PIIDetector(_build_pii_config(enable_step3=False, enable_step4=False))
    detector.warm_up()
    result = detector.detect("주민번호 ９０１０１５－１２３４５６７ 참고")

    rejected_tags = [item["tag"] for item in result["rejected"]]
    assert "QT_RRN" in rejected_tags
    assert all(finding["tag"] != "QT_RRN" for finding in result["findings"])
