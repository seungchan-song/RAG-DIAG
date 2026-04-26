"""Step 3 NER-based PII detection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger

HIGH_F1_TAGS = {
  "QT_AGE",
  "QT_CARD",
  "QT_CAR",
  "QT_IP",
  "QT_MOBILE",
  "QT_PASSPORT",
  "QT_PHONE",
  "QT_RRN",
  "TMI_EMAIL",
}

LOW_F1_TAGS = {
  "DAT",
  "LOC",
  "ORG",
  "PER",
  "QT_ADDR",
  "TMI_HEALTH",
  "TMI_OCCUPATION",
  "TMI_POLITICAL",
  "TMI_RELIGION",
  "TMI_SEXUAL",
}


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
      from transformers import pipeline as hf_pipeline

      self.pipeline = hf_pipeline(
        "token-classification",
        model=self.resolved_model_identifier,
        tokenizer=self.resolved_model_identifier,
        aggregation_strategy="simple",
        device=-1,
      )
      self.load_status = "ready"
      self.error_message = ""
      logger.info(
        "Step 3 NER model ready from {}: {}",
        self.model_source,
        self.resolved_model_identifier,
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

      tag = str(entity.get("entity_group", "O"))
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
