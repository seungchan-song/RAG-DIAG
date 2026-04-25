"""Helpers for producing storage-safe experiment artifacts."""

from __future__ import annotations

from copy import deepcopy

from rag.attack.base import AttackResult, ExecutionFailureRecord
from rag.pii.detector import PIIDetector


class StorageSanitizer:
  """Reuse one warmed-up detector across multiple result sanitization calls."""

  def __init__(self, config: dict[str, object]) -> None:
    self.config = config
    self.detector = PIIDetector(config)
    try:
      self.detector.warm_up()
    except Exception:
      self.detector = None
    report_config = config.get("report", {}) if isinstance(config, dict) else {}
    self.mask_raw_pii = bool(report_config.get("mask_raw_pii", True))
    self.persist_raw_response = bool(report_config.get("persist_raw_response", False))

  def sanitize_result(self, result: AttackResult) -> AttackResult:
    """Mask one result in place before storage."""
    raw_response = str(result.response or "")
    masked = self._detect_and_mask(raw_response)
    masked_text = str(masked.get("masked_text", "[MASKED_UNAVAILABLE]"))

    result.response_masked = masked_text
    result.masking_applied = True
    result.pii_summary = dict(masked.get("summary", {}))
    result.pii_findings = list(masked.get("findings", []))
    result.pii_runtime_status = dict(masked.get("runtime_status", {}))
    result.metadata = dict(result.metadata)
    result.metadata["masking_applied"] = True
    result.metadata["response_storage_mode"] = (
      "masked"
      if self.mask_raw_pii or not self.persist_raw_response
      else "raw_with_masked_alias"
    )

    if self.mask_raw_pii or not self.persist_raw_response:
      result.response = masked_text

    return result

  def sanitize_results(self, results: list[AttackResult]) -> list[AttackResult]:
    """Mask a batch of results in place."""
    for result in results:
      self.sanitize_result(result)
    return results

  def sanitized_copy(self, result: AttackResult) -> AttackResult:
    """Return a sanitized deep copy of a result."""
    return self.sanitize_result(deepcopy(result))

  def sanitize_text(self, text: str) -> str:
    """Mask one arbitrary text field for failure-safe storage."""
    masked = self._detect_and_mask(str(text or ""))
    return str(masked.get("masked_text", "[MASKED_UNAVAILABLE]"))

  def sanitize_failure(
    self,
    failure: ExecutionFailureRecord,
  ) -> ExecutionFailureRecord:
    """Return a masked deep copy of one execution failure record."""
    sanitized = deepcopy(failure)
    sanitized.query_masked = self.sanitize_text(sanitized.query_masked)
    sanitized.error_message_masked = self.sanitize_text(sanitized.error_message_masked)
    return sanitized

  def _detect_and_mask(self, text: str) -> dict[str, object]:
    """Best-effort wrapper that never returns raw text on detector failure."""
    if self.detector is None:
      return {
        "masked_text": "[MASKED_UNAVAILABLE]",
        "summary": {},
        "findings": [],
        "runtime_status": {
          "step3": {
            "enabled": False,
            "model_source": "unknown",
            "load_status": "masking_unavailable",
          },
          "step4": {
            "enabled": False,
            "mode": "unknown",
            "status": "masking_unavailable",
            "reason": "masking_unavailable",
          },
        },
      }
    try:
      return self.detector.detect_and_mask(text)
    except Exception:
      return {
        "masked_text": "[MASKED_UNAVAILABLE]",
        "summary": {},
        "findings": [],
        "runtime_status": {
          "step3": {
            "enabled": False,
            "model_source": "unknown",
            "load_status": "masking_unavailable",
          },
          "step4": {
            "enabled": False,
            "mode": "unknown",
            "status": "masking_unavailable",
            "reason": "masking_unavailable",
          },
        },
      }


def sanitize_results_for_storage(
  results: list[AttackResult],
  config: dict[str, object],
) -> list[AttackResult]:
  """Mask a batch of results before saving them to disk."""
  sanitizer = StorageSanitizer(config)
  return sanitizer.sanitize_results(results)
