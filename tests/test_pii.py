"""Tests for PII detection, masking, runtime status, and artifact safety."""

from __future__ import annotations

import sys
import types

from rag.attack.base import AttackResult
from rag.pii.artifacts import sanitize_results_for_storage
from rag.pii.detector import PIIDetector
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
