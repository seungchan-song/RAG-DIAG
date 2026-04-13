"""
통합 PII 탐지 파이프라인 모듈

STEP 1 ~ STEP 4 + Classifier + Masker를 하나로 연결하여
텍스트에서 PII를 탐지하고 마스킹하는 전체 파이프라인을 제공합니다.

전체 흐름:
  텍스트 → STEP 1 (정규식) → STEP 2 (체크섬) → 경로 A 확정
       → STEP 3 (NER)   → 경로 B-1 확정
                          → STEP 4 (sLLM) → 경로 B-2 확정
       → Classifier (종합) → Masker (마스킹) → 결과

사용 예시:
  from rag.pii.detector import PIIDetector

  detector = PIIDetector(config)
  detector.warm_up()

  # 탐지만 수행
  result = detector.detect("홍길동의 전화번호는 010-1234-5678입니다.")

  # 탐지 + 마스킹
  masked = detector.detect_and_mask("홍길동의 전화번호는 010-1234-5678입니다.")
  # → "홍**의 전화번호는 010-****-5678입니다."
"""

from typing import Any

from loguru import logger

from rag.pii.classifier import PIIClassifier
from rag.pii.masker import PIIMasker
from rag.pii.step1_regex import RegexDetector
from rag.pii.step2_checksum import ChecksumValidator
from rag.pii.step3_ner import NERDetector
from rag.pii.step4_sllm import SLLMVerifier


class PIIDetector:
  """
  4단계 PII 탐지 파이프라인을 통합 실행하는 클래스입니다.

  하나의 detect() 호출로 STEP 1~4를 순차 실행하고
  최종 PII 확정 결과를 반환합니다.
  """

  def __init__(self, config: dict[str, Any]) -> None:
    """
    PIIDetector를 초기화합니다.

    각 단계의 탐지기/검증기를 생성합니다.

    Args:
      config: YAML에서 로드한 설정 딕셔너리
    """
    # 각 단계의 컴포넌트를 생성합니다
    self.regex_detector = RegexDetector()
    self.checksum_validator = ChecksumValidator()
    self.ner_detector = NERDetector(config)
    self.sllm_verifier = SLLMVerifier(config)
    self.classifier = PIIClassifier()
    self.masker = PIIMasker()

    logger.info("PIIDetector 초기화 완료 (4단계 파이프라인)")

  def warm_up(self) -> None:
    """
    NER 모델을 로드합니다.

    STEP 3 (KPF-BERT NER)는 모델 로드에 시간이 걸리므로
    별도의 warm_up 단계에서 수행합니다.
    모델이 없으면 STEP 3은 건너뛰고 STEP 1+2만 동작합니다.
    """
    self.ner_detector.warm_up()

  def detect(self, text: str) -> dict[str, Any]:
    """
    텍스트에서 4단계 PII 탐지를 수행합니다.

    전체 파이프라인:
      1. STEP 1: 정규식으로 구조화 PII 탐지
      2. STEP 2: 체크섬 검증으로 오탐 제거
      3. STEP 3: NER로 비구조화 PII 탐지
      4. 경로 B-1/B-2 분류
      5. STEP 4: B-2 항목 sLLM 교차검증
      6. Classifier: 모든 결과 종합하여 최종 확정

    Args:
      text: PII를 탐지할 원문 텍스트

    Returns:
      dict: 탐지 결과
        - "confirmed": 확정된 ConfirmedPII 목록
        - "summary": 태그별/경로별 요약 통계
        - "original_text": 원문 텍스트
    """
    logger.info(f"PII 탐지 시작 (텍스트 길이: {len(text)}자)")

    # === STEP 1: 정규식 탐지 ===
    regex_matches = self.regex_detector.detect(text)
    logger.debug(f"STEP 1 완료: {len(regex_matches)}개 패턴 매칭")

    # === STEP 2: 체크섬 검증 ===
    regex_validated = self.checksum_validator.filter_valid(regex_matches)
    logger.debug(f"STEP 2 완료: {len(regex_validated)}개 유효")

    # === STEP 3: NER 탐지 ===
    ner_matches = self.ner_detector.detect(text)
    logger.debug(f"STEP 3 완료: {len(ner_matches)}개 NER 탐지")

    # NER 결과를 경로 B-1, B-2로 분류
    ner_b1, ner_b2 = self.ner_detector.split_by_route(ner_matches)

    # === STEP 4: sLLM 교차검증 (B-2 항목만) ===
    sllm_verified = self.sllm_verifier.verify_batch(ner_b2, text)
    logger.debug(f"STEP 4 완료: {len(sllm_verified)}개 sLLM 확인")

    # === 최종 확정 ===
    confirmed = self.classifier.classify(
      regex_validated, ner_b1, sllm_verified
    )
    summary = self.classifier.to_summary(confirmed)

    return {
      "confirmed": confirmed,
      "summary": summary,
      "original_text": text,
    }

  def detect_and_mask(self, text: str) -> dict[str, Any]:
    """
    PII 탐지 후 마스킹까지 수행합니다.

    detect()를 호출한 뒤, 확정된 PII를 마스킹 처리합니다.

    Args:
      text: 원문 텍스트

    Returns:
      dict: 탐지 + 마스킹 결과
        - "confirmed": 확정된 PII 목록
        - "summary": 요약 통계
        - "original_text": 원문 텍스트
        - "masked_text": 마스킹된 텍스트
    """
    result = self.detect(text)
    confirmed = result["confirmed"]

    # 마스킹 수행
    masked_text = self.masker.mask_text(text, confirmed)
    result["masked_text"] = masked_text

    return result
