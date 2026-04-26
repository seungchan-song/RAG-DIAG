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
    regex_validated = self.checksum_validator.filter_valid(regex_matches)

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

    return {
      "confirmed": confirmed,
      "summary": summary,
      "findings": findings,
      "runtime_status": {
        "step1": {"detected_count": len(regex_matches)},
        "step2": {"validated_count": len(regex_validated)},
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
