"""Unified PII detection and masking pipeline."""

from __future__ import annotations

from typing import Any

from loguru import logger

from rag.pii.classifier import PIIClassifier, is_high_risk_tag
from rag.pii.masker import PIIMasker
from rag.pii.step1_regex import RegexDetector
from rag.pii.step2_checksum import ChecksumValidator
from rag.pii.step3_ner import NERDetector
from rag.pii.step4_sllm import SLLMVerifier


class PIIDetector:
  """Run Step 1-4 PII detection and build storage-safe outputs."""

  def __init__(self, config: dict[str, Any]) -> None:
    self.regex_detector = RegexDetector()
    self.checksum_validator = ChecksumValidator()
    self.ner_detector = NERDetector(config)
    self.sllm_verifier = SLLMVerifier(config)
    self.classifier = PIIClassifier()
    self.masker = PIIMasker()

  def warm_up(self) -> None:
    """Warm up optional model-backed steps."""
    self.ner_detector.warm_up()

  def detect(self, text: str) -> dict[str, Any]:
    """Detect PII in a single text and return safe runtime metadata."""
    logger.debug("Starting PII detection for text of length {}", len(text))

    regex_matches = self.regex_detector.detect(text)
    # 체크섬 탈락 항목을 버리지 않고 함께 받아 "구조 일치·검증 탈락"으로 노출한다.
    regex_validated, regex_rejected = self.checksum_validator.partition_valid(
      regex_matches
    )

    ner_matches = self.ner_detector.detect(text)
    ner_b1, ner_b2 = self.ner_detector.split_by_route(ner_matches)

    step4_reason = ""
    if not self.sllm_verifier.enabled:
      sllm_verified: list[Any] = []
      step4_reason = "disabled"
    elif not self.ner_detector.is_available():
      sllm_verified = []
      step4_reason = "step3_unavailable"
    elif not ner_b2:
      sllm_verified = []
      step4_reason = "no_step3_candidates"
    else:
      sllm_verified = self.sllm_verifier.verify_batch(ner_b2, text)
      step4_reason = (
        "mock_conservative"
        if self.sllm_verifier.mode == "mock_conservative"
        else "verified"
      )

    confirmed = self.classifier.classify(regex_validated, ner_b1, sllm_verified)
    summary = self.classifier.to_summary(confirmed)
    findings = self._build_public_findings(confirmed)
    rejected = self._build_public_rejected(regex_rejected)

    return {
      "confirmed": confirmed,
      "summary": summary,
      "findings": findings,
      "rejected": rejected,
      "runtime_status": {
        "step1": {"detected_count": len(regex_matches)},
        "step2": {
          "validated_count": len(regex_validated),
          "rejected_count": len(regex_rejected),
        },
        "step3": self.ner_detector.get_runtime_status(
          match_count=len(ner_matches),
          route_b1_count=len(ner_b1),
          route_b2_count=len(ner_b2),
        ),
        "step4": self.sllm_verifier.get_runtime_status(
          candidate_count=len(ner_b2),
          verified_count=len(sllm_verified),
          reason=step4_reason,
        ),
      },
      "original_text": text,
    }

  def detect_and_mask(self, text: str) -> dict[str, Any]:
    """Detect PII and return a masked text artifact."""
    result = self.detect(text)
    masked_text = self.masker.mask_text(text, result["confirmed"])
    result["masked_text"] = masked_text
    result["masking_applied"] = True
    return result

  def _build_public_findings(self, confirmed: list[Any]) -> list[dict[str, Any]]:
    """Serialize confirmed findings without raw PII values."""
    findings: list[dict[str, Any]] = []
    for item in confirmed:
      findings.append(
        {
          "tag": item.tag,
          "route": item.route,
          "source": item.source,
          "masked_text": self.masker.mask_single(item),
          "start": item.start,
          "end": item.end,
          "confidence": item.confidence,
          "high_risk": is_high_risk_tag(item.tag),
        }
      )
    return findings

  def _build_public_rejected(self, rejected: list[Any]) -> list[dict[str, Any]]:
    """
    체크섬 탈락 항목을 저장 안전한(마스킹된) 형태로 직렬화한다.

    탈락 항목도 원문이 주민번호 모양이면 그대로 저장하면 마스킹 정책 위반이므로,
    확정 PII 와 동일하게 masker 로 마스킹한 뒤 사유 메타데이터를 붙여 반환한다.
    status 는 "확실히 PII 아님"으로 단정하지 않고 "구조 일치·검증 미통과"라는
    중립 표현을 사용한다 — 체크섬 탈락값이 항상 비-PII 라고 보장할 수는 없기
    때문이다(예: 한 자리 깨진 실제 번호). 이 목록은 탐지 건수·위험도 집계에는
    포함하지 않으며 리포트 설명용으로만 쓰인다.
    """
    items: list[dict[str, Any]] = []
    for item in rejected:
      items.append(
        {
          "tag": item.tag,
          # RejectedPII 는 mask_single 이 참조하는 .text/.tag 를 모두 갖고 있어
          # ConfirmedPII 와 동일하게 마스킹된다(구조만 노출, 유효 자릿수 가림).
          "masked_text": self.masker.mask_single(item),
          "start": item.start,
          "end": item.end,
          "reason": item.reason,
          "validator": item.validator,
          "stage": "step2_checksum",
          "status": "structurally_matched_unverified",
        }
      )
    return items
