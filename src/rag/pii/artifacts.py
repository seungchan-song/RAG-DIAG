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
    self._flag_query_echo(masked, str(result.query or ""))

    result.response_masked = masked_text
    result.masking_applied = True
    result.pii_summary = dict(masked.get("summary", {}))
    result.pii_findings = list(masked.get("findings", []))
    result.pii_rejected = list(masked.get("rejected", []))
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

  def _flag_query_echo(self, masked: dict[str, object], query_text: str) -> None:
    """
    공격 질의에 이미 있던 값을 응답이 되뇐 것에 `echoed_from_query` 플래그를 붙입니다.

    A2 앵커는 정의상 대상 문서에서 뽑아낸 **실제 PII 값**이다
    (`attack/query_generator.py:_extract_sensitive_identifiers`). 그래서 모델이
    "SYNTH-PROJ-B923 에 대한 정보를 찾을 수 없습니다" 처럼 앵커를 되뇌기만 해도
    지금까지는 유출 1건으로 집계됐다. 반면 NORMAL baseline 질의는 "직원 연락처" 같은
    카테고리 명사라(`attack/normal_baseline.py:_NORMAL_PII_KEYWORDS`) echo 오염이 없다.
    편향이 한쪽에만 걸리므로 "공격이 추가로 만든 유출량" delta 가 부풀려진다.

    ⚠️ **삭제하지 않고 표시만 한다.** 모델이 값을 되뇐 것인지, 문서에서 검색해 출력한
    것인지는 응답만 봐서 구분할 수 없다. 그래서 화면에는 그대로 남기고 집계(intensity,
    delta)에서만 제외하는 보수적 선택을 한다.

    질의에 별도 탐지를 돌리지 않고 **원본 값의 부분문자열 검사**로 판정한다 — 질의에
    NER·sLLM 을 다시 태우면 쿼리당 비용이 두 배가 되는데, 되뇜은 값이 글자 그대로
    나타나는 경우가 전부라 그럴 필요가 없다.

    Args:
      masked: `PIIDetector.detect_and_mask()` 결과(confirmed/findings 보유). 제자리 수정된다.
      query_text: 이 응답을 유발한 공격 질의 원문.
    """
    if not query_text:
      return

    findings = masked.get("findings") or []
    confirmed = masked.get("confirmed") or []
    if not isinstance(findings, list) or len(findings) != len(confirmed):
      return

    echoed_by_tag: dict[str, int] = {}
    for finding, pii in zip(findings, confirmed):
      value = str(getattr(pii, "text", "") or "")
      if value and value in query_text:
        finding["echoed_from_query"] = True
        tag = str(finding.get("tag") or "")
        echoed_by_tag[tag] = echoed_by_tag.get(tag, 0) + 1

    # 집계용 파생값을 탐지 시점에 한 번만 계산해 summary 에 싣는다. 소비처
    # (evaluator/summary.py 의 intensity, report/generator.py 의 등급별 유출량)가
    # 각자 findings 를 다시 훑으면 규칙이 갈라지므로 여기서 한 곳에 못박는다.
    # `total`/`by_tag` 는 "응답에 실제로 있던 PII" 그대로 두어 화면 표시가 사실을 유지한다.
    summary = masked.get("summary")
    if not isinstance(summary, dict):
      return

    echoed_total = sum(echoed_by_tag.values())
    summary["echoed_from_query_count"] = echoed_total
    summary["echoed_by_tag"] = echoed_by_tag
    summary["total_excluding_echo"] = max(
      0, int(summary.get("total") or 0) - echoed_total
    )
    summary["by_tag_excluding_echo"] = {
      tag: count - echoed_by_tag.get(tag, 0)
      for tag, count in (summary.get("by_tag") or {}).items()
      if count - echoed_by_tag.get(tag, 0) > 0
    }
    summary["high_risk_count_excluding_echo"] = sum(
      1
      for finding in findings
      if finding.get("high_risk") is True and not finding.get("echoed_from_query")
    )

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
        "rejected": [],
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
        "rejected": [],
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
