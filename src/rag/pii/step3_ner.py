"""
Step 3 NER 기반 PII 탐지.

NER 모델(KPF-BERT-KDPII)이 출력하는 KDPII 33개 엔티티 라벨을 코드 내부의
단축 PII 태그 체계(정규식·분류기·마스커 공통)로 정규화한 뒤,
신뢰 구간(HIGH_F1 / LOW_F1)에 따라 B-1(즉시 인정) / B-2(sLLM 검증) 경로로
라우팅한다.

이전 버전의 라벨 명세(`PER`, `LOC`, `QT_CARD`, `QT_RRN` 등)는 KDPII 모델의
실제 출력 라벨(`PS_NAME`, `LC_ADDRESS`, `QT_CARD_NUMBER`, `QT_RESIDENT_NUMBER`
등)과 일치하지 않아, 모델이 라벨을 찍어도 라우팅 대상에서 누락되는 버그가
있었다. 본 모듈은 KDPII 라벨 → 단축 태그 매핑(NER_LABEL_MAP)을 통해 이를
정합하며, 매핑 없는 라벨도 원본 그대로 보존해 후속 디버깅을 돕는다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger


# === KDPII NER 라벨 → 코드 내부 단축 PII 태그 정규화 매핑 ============
# 좌: 모델(KPF-BERT-KDPII)이 출력하는 KDPII 33개 엔티티 라벨.
# 우: 정규식/분류기/마스커가 공통으로 사용하는 단축 태그.
#
# 매핑 원칙:
#   1. 정규식 태그와 의미가 동일한 경우 단축 형태로 통일한다
#      (예: QT_CARD_NUMBER → QT_CARD, QT_RESIDENT_NUMBER → QT_RRN).
#   2. 단축 태그가 없는 신규 항목은 새 단축 태그를 부여한다
#      (예: QT_ACCOUNT_NUMBER → QT_ACCOUNT, TMI_SITE → TMI_SITE).
#   3. 큰 범주(LOC, ORG, DAT 등)는 정규식과 동일한 이름을 재사용한다.
NER_LABEL_MAP: dict[str, str] = {
  # --- 정형 식별자 (HIGH_F1) ---
  "QT_MOBILE": "QT_MOBILE",
  "QT_PHONE": "QT_PHONE",
  "QT_AGE": "QT_AGE",
  "QT_IP": "QT_IP",
  "TMI_EMAIL": "TMI_EMAIL",
  "TMI_SITE": "TMI_SITE",
  "QT_CARD_NUMBER": "QT_CARD",
  "QT_ACCOUNT_NUMBER": "QT_ACCOUNT",
  "QT_RESIDENT_NUMBER": "QT_RRN",
  "QT_ALIEN_NUMBER": "QT_ARN",
  "QT_PASSPORT_NUMBER": "QT_PASSPORT",
  "QT_DRIVER_NUMBER": "QT_DRIVER",
  "QT_PLATE_NUMBER": "QT_CAR",
  # --- 비정형 PII (LOW_F1) ---
  "PS_NAME": "PER",
  "PS_NICKNAME": "PER",
  "PS_ID": "PER",
  "LC_ADDRESS": "QT_ADDR",
  "LC_PLACE": "LOC",
  "LCP_COUNTRY": "LOC",
  "OG_DEPARTMENT": "ORG",
  "OG_WORKPLACE": "ORG",
  "OGG_CLUB": "ORG",
  "OGG_EDUCATION": "ORG",
  "OGG_RELIGION": "ORG",
  "CV_MILITARY_CAMP": "ORG",
  "DT_BIRTH": "DAT",
  "FD_MAJOR": "TMI_OCCUPATION",
  "CV_POSITION": "TMI_OCCUPATION",
  "CV_SEX": "TMI_HEALTH",
  "TM_BLOOD_TYPE": "TMI_HEALTH",
  # --- 부가정보 (보수적으로 LOW_F1 처리) ---
  "QT_GRADE": "QT_GRADE",
  "QT_LENGTH": "QT_LENGTH",
  "QT_WEIGHT": "QT_WEIGHT",
}

# 정형 패턴이라 NER만으로도 신뢰 가능한 단축 태그 집합 (B-1 경로).
HIGH_F1_TAGS = {
  "QT_ACCOUNT",
  "QT_AGE",
  "QT_ARN",
  "QT_CARD",
  "QT_CAR",
  "QT_DRIVER",
  "QT_IP",
  "QT_MOBILE",
  "QT_PASSPORT",
  "QT_PHONE",
  "QT_RRN",
  "TMI_EMAIL",
  "TMI_SITE",
}

# 문맥 의존적이라 sLLM 교차검증이 필요한 단축 태그 집합 (B-2 경로).
LOW_F1_TAGS = {
  "DAT",
  "LOC",
  "ORG",
  "PER",
  "QT_ADDR",
  "QT_GRADE",
  "QT_LENGTH",
  "QT_WEIGHT",
  "TMI_HEALTH",
  "TMI_OCCUPATION",
  "TMI_POLITICAL",
  "TMI_RELIGION",
  "TMI_SEXUAL",
}

# KPF-BERT 계열(BERT-base 구조)의 절대 입력 한계(positional embedding 크기).
# 토크나이저의 model_max_length 가 sentinel(매우 큰 수)로 설정된 경우에도
# 이 값을 강제로 적용해 자동 truncation 을 활성화한다.
_KPFBERT_MAX_INPUT_TOKENS = 512


@dataclass
class NERMatch:
  """One NER candidate entity."""

  tag: str
  text: str
  start: int
  end: int
  confidence: float
  source: str = "ner"
  is_high_f1: bool = False


class NERDetector:
  """Load and run the configured token classification model."""

  def __init__(self, config: dict[str, Any]) -> None:
    pii_config = config.get("pii", {})
    runtime_config = pii_config.get("runtime", {})
    ner_config = pii_config.get("ner", {})

    self.enabled = bool(runtime_config.get("enable_step3", True))
    self.model_path = ner_config.get("model_path", "townboy/kpfbert-kdpii")
    self.confidence_threshold = float(ner_config.get("confidence_threshold", 0.8))

    self.pipeline = None
    self.model_source = "hub"
    self.load_status = "not_loaded" if self.enabled else "skipped"
    self.error_message = ""
    self.resolved_model_identifier = self.model_path

  def warm_up(self) -> None:
    """Load the NER model once."""
    if not self.enabled:
      self.pipeline = None
      self.model_source = "disabled"
      self.load_status = "skipped"
      self.error_message = "step3_disabled"
      return

    local_path = Path(self.model_path)
    if local_path.exists():
      self.model_source = "local"
      self.resolved_model_identifier = str(local_path)
    else:
      self.model_source = "hub"
      self.resolved_model_identifier = self.model_path

    try:
      from transformers import AutoTokenizer
      from transformers import pipeline as hf_pipeline

      # KPF-BERT 토크나이저는 model_max_length 가 sentinel(~1e30) 로 설정돼 있어
      # 자동 truncation 이 활성화되지 않는다. 명시적으로 512 토큰으로 강제해
      # 긴 응답에서 발생하던 RuntimeError("tensor a (N) vs b (512)") 를 차단한다.
      tokenizer = AutoTokenizer.from_pretrained(self.resolved_model_identifier)
      tokenizer_max = int(getattr(tokenizer, "model_max_length", 0) or 0)
      if tokenizer_max <= 0 or tokenizer_max > _KPFBERT_MAX_INPUT_TOKENS:
        tokenizer.model_max_length = _KPFBERT_MAX_INPUT_TOKENS
      self.pipeline = hf_pipeline(
        "token-classification",
        model=self.resolved_model_identifier,
        tokenizer=tokenizer,
        aggregation_strategy="simple",
        device=-1,
      )
      self.load_status = "ready"
      self.error_message = ""
      logger.info(
        "Step 3 NER model ready from {}: {} (max_input_tokens={})",
        self.model_source,
        self.resolved_model_identifier,
        tokenizer.model_max_length,
      )
    except Exception as error:
      self.pipeline = None
      self.load_status = "failed"
      self.error_message = str(error)
      logger.warning("Step 3 NER warm-up failed: {}", error)

  def detect(self, text: str) -> list[NERMatch]:
    """Run token classification on the provided text."""
    if not self.enabled:
      return []

    if self.pipeline is None and self.load_status == "not_loaded":
      self.warm_up()

    if self.pipeline is None:
      return []

    try:
      raw_results = self.pipeline(text)
    except Exception as error:
      self.load_status = "failed"
      self.error_message = str(error)
      logger.warning("Step 3 inference failed: {}", error)
      return []

    matches: list[NERMatch] = []
    for entity in raw_results:
      confidence = float(entity.get("score", 0.0))
      if confidence < self.confidence_threshold:
        continue

      raw_tag = str(entity.get("entity_group", "O"))
      # KDPII 라벨을 코드 내부 단축 태그로 정규화한다.
      # 매핑 테이블에 없는 라벨은 원본 그대로 보존해 후속 디버깅을 돕는다.
      tag = NER_LABEL_MAP.get(raw_tag, raw_tag)
      matches.append(
        NERMatch(
          tag=tag,
          text=str(entity.get("word", "")),
          start=int(entity.get("start", 0)),
          end=int(entity.get("end", 0)),
          confidence=confidence,
          is_high_f1=tag in HIGH_F1_TAGS,
        )
      )

    return matches

  def split_by_route(
    self,
    matches: list[NERMatch],
  ) -> tuple[list[NERMatch], list[NERMatch]]:
    """Split NER findings into direct-confirm and sLLM-review buckets."""
    route_b1 = [match for match in matches if match.is_high_f1]
    route_b2 = [match for match in matches if not match.is_high_f1]
    return route_b1, route_b2

  def is_available(self) -> bool:
    """Return whether Step 3 is usable for the current process."""
    return self.enabled and self.pipeline is not None and self.load_status == "ready"

  def get_runtime_status(
    self,
    *,
    match_count: int = 0,
    route_b1_count: int = 0,
    route_b2_count: int = 0,
  ) -> dict[str, Any]:
    """Return a serializable Step 3 runtime status snapshot."""
    return {
      "enabled": self.enabled,
      "model_path": self.model_path,
      "resolved_model_identifier": self.resolved_model_identifier,
      "model_source": self.model_source,
      "load_status": self.load_status,
      "error": self.error_message,
      "match_count": match_count,
      "route_b1_count": route_b1_count,
      "route_b2_count": route_b2_count,
    }
