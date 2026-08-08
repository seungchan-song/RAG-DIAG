"""Unified PII detection and masking pipeline."""

from __future__ import annotations

from typing import Any

from loguru import logger

from rag.pii.classifier import PIIClassifier, is_high_risk_tag
from rag.pii.masker import PIIMasker
from rag.pii.step0_normalize import NormalizationResult, TextNormalizer
from rag.pii.step1_regex import RegexDetector
from rag.pii.step2_checksum import ChecksumValidator
from rag.pii.step3_ner import NERDetector
from rag.pii.step4_sllm import SLLMVerifier


class PIIDetector:
  """Run Step 0-4 PII detection and build storage-safe outputs."""

  def __init__(self, config: dict[str, Any]) -> None:
    self.normalizer = TextNormalizer(config)
    self.regex_detector = RegexDetector(config)
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

    # STEP 0: 변형(전각·호모글리프·자모분리·공백삽입) 정규화. 정규화된 텍스트에서
    # 탐지한 뒤 스팬을 '원문 좌표'로 되돌린다(마스킹·STEP 4 문맥 추출은 원문 기준).
    normalization = self.normalizer.normalize(text)
    detect_text = normalization.normalized_text

    regex_matches = self._remap_to_original(
      self.regex_detector.detect(detect_text), normalization
    )
    # 체크섬 탈락 항목을 버리지 않고 함께 받아 "구조 일치·검증 탈락"으로 노출한다.
    regex_validated, regex_rejected = self.checksum_validator.partition_valid(
      regex_matches
    )

    ner_matches = self._remap_to_original(
      self.ner_detector.detect(detect_text), normalization
    )
    # 정형 태그 후보 중 자릿수가 안 맞는 조각(모델이 스팬을 쪼갠 결과)을 걸러낸다.
    # 버리지 않고 rejection 채널로 보내 리포트에서 미탐과 구분되게 한다.
    ner_matches, ner_rejected = self.ner_detector.partition_structural(ner_matches)
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
    findings = self._build_public_findings(confirmed, text)
    rejected = self._build_public_rejected(regex_rejected + ner_rejected, text)

    return {
      "confirmed": confirmed,
      "summary": summary,
      "findings": findings,
      "rejected": rejected,
      "runtime_status": {
        "step0": {
          "enabled": self.normalizer.enabled,
          "changed": normalization.changed,
          "applied": normalization.applied,
        },
        "step1": {"detected_count": len(regex_matches)},
        "step2": {
          "validated_count": len(regex_validated),
          "rejected_count": len(regex_rejected),
        },
        "step3": self.ner_detector.get_runtime_status(
          match_count=len(ner_matches),
          route_b1_count=len(ner_b1),
          route_b2_count=len(ner_b2),
          structure_rejected_count=len(ner_rejected),
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

  def _remap_to_original(
    self,
    matches: list[Any],
    normalization: NormalizationResult,
  ) -> list[Any]:
    """
    정규화 텍스트에서 찾은 매치의 start/end 를 '원문 좌표'로 되돌린다.

    마스킹(masker)과 STEP 4 문맥 추출은 원문 인덱스를 사용하므로, 정규화된 텍스트에서
    탐지한 스팬을 원문 좌표로 옮겨야 원문의 올바른 구간이 마스킹된다. match.text 는
    정규화된(깨끗한) 문자열 그대로 두어 체크섬 검증과 마스킹 표현이 정확해진다.
    정규화로 바뀐 게 없으면(항등) 매치를 그대로 반환한다.

    Args:
      matches: 정규화 텍스트에서 탐지된 매치 목록(PIIMatch 또는 NERMatch)
      normalization: STEP 0 정규화 결과(원문 좌표 매핑 포함)

    Returns:
      list[Any]: start/end 가 원문 좌표로 갱신된 동일한 매치 목록
    """
    if not normalization.changed:
      return matches

    for match in matches:
      original_start, original_end = normalization.to_original_span(match.start, match.end)
      match.start = original_start
      match.end = original_end
    return matches

  def _is_recovered_by_step0(self, item: Any, original_text: str) -> bool:
    """
    이 항목이 STEP 0 정규화 덕분에 복원되어 탐지되었는지 판정한다.

    item.start/end 는 원문 좌표, item.text 는 정규화(깨끗한)된 값이다. 원문의 해당
    구간과 정규화된 값이 다르면 STEP 0 가 그 구간을 표준화(전각→반각, 자모결합 등)했다는
    뜻이므로 "변형 PII 복원"으로 본다. 정규화가 손대지 않은 구간은 둘이 같아 False.

    Args:
      item: ConfirmedPII 또는 RejectedPII (start/end/text 속성 보유)
      original_text: 원문 텍스트

    Returns:
      bool: STEP 0 정규화로 복원된 항목이면 True
    """
    original_span = original_text[item.start : item.end]
    return original_span != item.text

  def _build_public_findings(
    self,
    confirmed: list[Any],
    original_text: str,
  ) -> list[dict[str, Any]]:
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
          "recovered": self._is_recovered_by_step0(item, original_text),
        }
      )
    return findings

  def _build_public_rejected(
    self,
    rejected: list[Any],
    original_text: str,
  ) -> list[dict[str, Any]]:
    """
    체크섬 탈락 항목을 저장 안전한(마스킹된) 형태로 직렬화한다.

    탈락 항목도 원문이 주민번호 모양이면 그대로 저장하면 마스킹 정책 위반이므로,
    확정 PII 와 동일하게 masker 로 마스킹한 뒤 사유 메타데이터를 붙여 반환한다.
    status 는 "확실히 PII 아님"으로 단정하지 않고 "구조 일치·검증 미통과"라는
    중립 표현을 사용한다 — 체크섬 탈락값이 항상 비-PII 라고 보장할 수는 없기
    때문이다(예: 한 자리 깨진 실제 번호). 이 목록은 탐지 건수·위험도 집계에는
    포함하지 않으며 리포트 설명용으로만 쓰인다.
    """
    # 탈락 사유가 STEP 2 체크섬인지 STEP 3 구조 게이트인지 구분한다. 한 이름으로
    # 뭉뚱그리면 "체크섬이 틀린 값"과 "모델이 쪼갠 조각"이 리포트에서 같아 보인다.
    stages = {
      "regex": ("step2_checksum", "structurally_matched_unverified"),
      "ner": ("step3_structure", "ner_fragment_discarded"),
    }

    items: list[dict[str, Any]] = []
    for item in rejected:
      stage, status = stages[item.source]
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
          "source": item.source,
          "stage": stage,
          "status": status,
          "recovered": self._is_recovered_by_step0(item, original_text),
        }
      )
    return items
