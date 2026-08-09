"""KDPII-style benchmark evaluation for the layered PII pipeline."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rag.pii.classifier import ConfirmedPII
from rag.pii.detector import PIIDetector
from rag.pii.masker import PIIMasker
from rag.pii.step0_normalize import TextNormalizer
from rag.pii.step1_regex import PIIMatch, RegexDetector

LABEL_SCHEMA_VERSION = "kdpii-33-v1"
ARTIFACT_POLICY = "masked_only"
EVAL_MODES = ("step1", "step1_2", "step1_2_3", "full")

# canonical 값 계산용 정규화기(전각·호모글리프·자모분리 복원). eval 은 오프라인이라
# 단일 인스턴스를 재사용해도 안전하다.
_CANONICAL_NORMALIZER = TextNormalizer({})
# 값 단위 비교 시 무시할 구분자/공백(전화·주민번호의 하이픈, 이메일의 점 등).
_CANON_STRIP_RE = re.compile(r"[\s\-._]")


def canonical_value(surface: str) -> str:
  """
  엔티티 표면 문자열을 '값 단위 비교용' 정규형으로 변환한다.

  STEP 0(전각→반각·호모글리프·자모결합) 정규화 후 구분자/공백을 제거하고 casefold 한다.
  변형(evasion)된 PII 와 그 canonical 형태를 같은 값으로 인식시켜, 완전일치 채점이
  놓치던 변형 PII 를 canonical 매칭으로 채점할 수 있게 하는 것이 목적이다.

  예: "０１０－１２３４" · "010 1234" · "010-1234" → 모두 "0101234" 로 수렴.

  Args:
    surface: 엔티티의 원문 표면 텍스트(text[start:end])

  Returns:
    str: 정규화·구분자제거·casefold 를 거친 canonical 값(빈 입력이면 "")
  """
  if not surface:
    return ""
  normalized = _CANONICAL_NORMALIZER.normalize(surface).normalized_text
  return _CANON_STRIP_RE.sub("", normalized).casefold()


def _span_iou(a_start: int, a_end: int, b_start: int, b_end: int) -> float:
  """
  두 스팬 [a_start, a_end) 와 [b_start, b_end) 의 IoU(교집합/합집합)를 계산한다.

  경계가 조금 어긋난(조사 포함 등) 예측도 같은 개체로 인정하기 위한 부분일치 척도다.

  Returns:
    float: 0.0(겹침 없음) ~ 1.0(완전 일치)
  """
  intersection = max(0, min(a_end, b_end) - max(a_start, b_start))
  if intersection <= 0:
    return 0.0
  union = (a_end - a_start) + (b_end - b_start) - intersection
  return intersection / union if union > 0 else 0.0

# ⚠️ 여기 없는 태그를 NER_LABEL_MAP 이 만들어내면 normalize_label 이
# LabelNormalizationError 로 벤치마크 전체를 실패시킨다. step3_ner.py 의
# NER_LABEL_MAP 우변 · step1_regex.py 의 tag 와 항상 같이 움직여야 한다.
CANONICAL_LABELS = (
  "DAT",
  "EMPLOYEE_ID",
  "LOC",
  "MEMBER_ID",
  "ORG",
  "PARTICIPANT_ID",
  "PER",
  "QT_ACCOUNT",
  "QT_ADDR",
  "QT_AGE",
  "QT_ARN",
  "QT_CARD",
  "QT_CAR",
  "QT_DRIVER",
  "QT_GRADE",
  "QT_IP",
  "QT_LENGTH",
  # ⚠️ QT_MOBILE 은 canonical 이 아니다 — 아래 LABEL_ALIASES 에서 QT_PHONE 으로 접는다.
  #    개인정보 33종 표준이 휴대전화와 일반전화를 PHONE 하나로 통합했기 때문이다.
  #    정규식(step1_regex)은 둘을 계속 구분하지만, 벤치마크 gold 에는 MOBILE 라벨이
  #    아예 없어 그대로 채점하면 **맞게 탐지한 건이 오탐+미탐으로 이중 계산**된다
  #    (실측 2026-08-03: QT_MOBILE fp=210 / QT_PHONE fn=210, 같은 210건).
  "QT_PASSPORT",
  "QT_PHONE",
  "QT_RRN",
  "QT_WEIGHT",
  "USER_ID",
  "ZIPCODE",
  "TMI_BIRTH",
  "TMI_BLOOD_TYPE",
  "TMI_BODY",
  "TMI_DISABILITY",
  "TMI_EDUCATION",
  "TMI_EMAIL",
  "TMI_FAMILY",
  # 성별 전용 태그. 예전에는 TMI_HEALTH 로 접혀 있었는데 성별은 건강정보가 아니다
  # (step3_ner.py:NER_LABEL_MAP 의 GENDER 주석 참조). 둘을 함께 옮겼다.
  "TMI_GENDER",
  "TMI_HEALTH",
  "TMI_HOBBY",
  "TMI_IDEOLOGY",
  "TMI_MARRIAGE",
  "TMI_NATIONALITY",
  "TMI_OCCUPATION",
  "TMI_PET",
  "TMI_POLITICAL",
  "TMI_PROPERTY",
  "TMI_RELATION",
  "TMI_RELIGION",
  "TMI_SEXUAL",
  "TMI_SITE",
)

LABEL_ALIASES = {
  # --- 자체 데이터셋(개인정보 33종) 라벨 → 내부 canonical 태그 ---
  # NER_LABEL_MAP 과 같은 대응이어야 벤치마크 채점이 모델 출력과 맞물린다.
  "ACCOUNT_NUMBER": "QT_ACCOUNT",
  "ALIEN_NUMBER": "QT_ARN",
  "BIRTHDATE": "DAT",
  "CARD_NUMBER": "QT_CARD",
  "CITY": "LOC",
  "DEPARTMENT": "ORG",
  "DRIVER_LICENSE": "QT_DRIVER",
  "GENDER": "TMI_GENDER",
  "HEIGHT": "QT_LENGTH",
  "MAJOR": "TMI_OCCUPATION",
  "NICKNAME": "PER",
  "PASSPORTNUM": "QT_PASSPORT",
  "POSITION": "TMI_OCCUPATION",
  "SCHOOL": "ORG",
  "URL": "TMI_SITE",
  "VEHICLE_NUMBER": "QT_CAR",
  "WEIGHT": "QT_WEIGHT",
  "WORKPLACE": "ORG",
  # --- 기존 별칭 ---
  "ADDRESS": "QT_ADDR",
  "ADDR": "QT_ADDR",
  "AGE": "QT_AGE",
  "ARN": "QT_ARN",
  "BIRTH": "TMI_BIRTH",
  "BLOODTYPE": "TMI_BLOOD_TYPE",
  "BLOOD_TYPE": "TMI_BLOOD_TYPE",
  "BODY": "TMI_BODY",
  "CARD": "QT_CARD",
  "CAR": "QT_CAR",
  "CAR_NO": "QT_CAR",
  "DATE": "DAT",
  "DISABILITY": "TMI_DISABILITY",
  "EDUCATION": "TMI_EDUCATION",
  "EMAIL": "TMI_EMAIL",
  "E_MAIL": "TMI_EMAIL",
  "FAMILY": "TMI_FAMILY",
  "HEALTH": "TMI_HEALTH",
  "HOBBY": "TMI_HOBBY",
  "IDEOLOGY": "TMI_IDEOLOGY",
  "IP": "QT_IP",
  "IP_ADDRESS": "QT_IP",
  "LOCATION": "LOC",
  "MARRIAGE": "TMI_MARRIAGE",
  "MOBILE": "QT_PHONE",
  "MOBILE_PHONE": "QT_PHONE",
  "QT_MOBILE": "QT_PHONE",
  "NAME": "PER",
  "NATIONALITY": "TMI_NATIONALITY",
  "OCCUPATION": "TMI_OCCUPATION",
  "ORGANIZATION": "ORG",
  "ORG_NAME": "ORG",
  "PASSPORT": "QT_PASSPORT",
  "PASSPORT_NO": "QT_PASSPORT",
  "PERSON": "PER",
  "PET": "TMI_PET",
  "PHONE": "QT_PHONE",
  "PHONE_NUMBER": "QT_PHONE",
  "POLITICAL": "TMI_POLITICAL",
  "PROPERTY": "TMI_PROPERTY",
  "RELATION": "TMI_RELATION",
  "RELIGION": "TMI_RELIGION",
  "RESIDENT_REGISTRATION_NUMBER": "QT_RRN",
  "RRN": "QT_RRN",
  "SEXUAL": "TMI_SEXUAL",
}


class LabelNormalizationError(ValueError):
  """Raised when a gold or predicted label is outside the canonical namespace."""


@dataclass(frozen=True)
class EvalEntity:
  """One normalized span-level entity used for canonical span matching."""

  sample_id: str
  start: int
  end: int
  label: str
  text: str
  route: str
  source: str
  confidence: float = 1.0

  @property
  def key(self) -> tuple[int, int, str]:
    return (self.start, self.end, self.label)

  @property
  def span_key(self) -> tuple[int, int]:
    return (self.start, self.end)

  @property
  def canonical(self) -> str:
    """이 엔티티의 값 단위 정규형(변형 PII 를 같은 값으로 인식시키기 위함)."""
    return canonical_value(self.text)


@dataclass(frozen=True)
class EvalSample:
  """One benchmark sample from a KDPII-style JSONL file."""

  sample_id: str
  text: str
  entities: tuple[EvalEntity, ...]


def normalize_label(label: str) -> str:
  """Normalize one tag into the canonical KDPII namespace."""
  normalized = (
    str(label)
    .strip()
    .upper()
    .replace("-", "_")
    .replace(" ", "_")
  )

  if normalized in CANONICAL_LABELS:
    return normalized

  if normalized.startswith(("B_", "I_")):
    suffix = normalized[2:]
    if suffix in CANONICAL_LABELS:
      return suffix
    if suffix in LABEL_ALIASES:
      return LABEL_ALIASES[suffix]

  if normalized in LABEL_ALIASES:
    return LABEL_ALIASES[normalized]

  raise LabelNormalizationError(
    f"label_normalization_error: unsupported label '{label}'"
  )


def resolve_eval_modes(mode: str, all_modes: bool) -> list[str]:
  """Resolve the CLI flags into a deterministic mode list."""
  if mode not in EVAL_MODES:
    allowed = ", ".join(EVAL_MODES)
    raise ValueError(f"Unsupported evaluation mode: {mode}. Allowed: {allowed}")
  if all_modes:
    return list(EVAL_MODES)
  return [mode]


def load_eval_dataset(dataset_path: str | Path) -> tuple[Path, list[EvalSample]]:
  """Load a local KDPII-style JSONL dataset."""
  path = Path(dataset_path).expanduser().resolve()
  if not path.exists():
    raise FileNotFoundError(f"PII evaluation dataset not found: {path}")

  samples: list[EvalSample] = []
  with open(path, "r", encoding="utf-8") as file:
    for index, raw_line in enumerate(file, start=1):
      line = raw_line.strip()
      if not line:
        continue

      payload = json.loads(line)
      sample_id = str(payload.get("sample_id") or f"sample-{index:04d}")
      text = str(payload.get("text", ""))
      entities_payload = payload.get("entities", [])
      if not isinstance(entities_payload, list):
        raise ValueError(f"{path}:{index} has a non-list 'entities' field.")

      normalized_entities: list[EvalEntity] = []
      seen_keys: set[tuple[int, int, str]] = set()
      seen_spans: dict[tuple[int, int], str] = {}
      for entity_payload in entities_payload:
        start = int(entity_payload["start"])
        end = int(entity_payload["end"])
        if start < 0 or end <= start or end > len(text):
          raise ValueError(
            f"{path}:{index} has an invalid entity span "
            f"({start}, {end}) for sample '{sample_id}'."
          )

        label = normalize_label(str(entity_payload["label"]))
        key = (start, end, label)
        span_key = (start, end)
        if span_key in seen_spans and seen_spans[span_key] != label:
          raise ValueError(
            f"{path}:{index} contains conflicting labels for span "
            f"{span_key} in sample '{sample_id}'."
          )
        if key in seen_keys:
          continue

        normalized_entities.append(
          EvalEntity(
            sample_id=sample_id,
            start=start,
            end=end,
            label=label,
            text=text[start:end],
            route="gold",
            source="gold",
          )
        )
        seen_keys.add(key)
        seen_spans[span_key] = label

      samples.append(
        EvalSample(
          sample_id=sample_id,
          text=text,
          entities=tuple(sorted(normalized_entities, key=lambda item: item.key)),
        )
      )

  if not samples:
    raise ValueError(f"PII evaluation dataset is empty: {path}")

  return path, samples


def build_dataset_manifest(path: Path, samples: list[EvalSample]) -> dict[str, Any]:
  """Build a serializable dataset manifest for snapshots and summaries."""
  file_hash = hashlib.sha256(path.read_bytes()).hexdigest()
  tag_counts = {tag: 0 for tag in CANONICAL_LABELS}
  entity_count = 0
  for sample in samples:
    for entity in sample.entities:
      tag_counts[entity.label] += 1
      entity_count += 1

  return {
    "dataset_path": str(path),
    "dataset_name": path.name,
    "dataset_hash": file_hash,
    "sample_count": len(samples),
    "entity_count": entity_count,
    "tag_counts": {tag: count for tag, count in tag_counts.items() if count > 0},
  }


class PIIBenchmarkRunner:
  """Run one or more canonical-match PII benchmark modes and write safe artifacts."""

  def __init__(self, config: dict[str, Any]) -> None:
    self.config = copy.deepcopy(config)
    eval_config = self.config.get("pii", {}).get("eval", {})
    self.label_schema_version = str(
      eval_config.get("label_schema_version", LABEL_SCHEMA_VERSION)
    )
    self.error_context_chars = int(eval_config.get("error_context_chars", 20))
    # canonical 값이 다를 때 부분일치(경계 어긋남)를 TP 로 인정하는 IoU 임계값.
    # 채점 관례값(0.5)이며, 태그별 탐지 임계값이 아니라 모델과 무관한 매칭 규칙이다.
    self.match_iou_threshold = float(eval_config.get("match_iou_threshold", 0.5))
    self.regex_detector = RegexDetector(self.config)
    self.masker = PIIMasker()

  def evaluate(
    self,
    *,
    dataset_path: str | Path,
    modes: list[str],
    run_id: str,
    output_dir: Path,
    summary_metadata: dict[str, Any] | None = None,
  ) -> dict[str, Path]:
    """Evaluate the dataset and write JSON and CSV artifacts."""
    resolved_path, samples = load_eval_dataset(dataset_path)
    dataset_manifest = build_dataset_manifest(resolved_path, samples)

    mode_results: dict[str, dict[str, Any]] = {}
    by_tag_rows: list[dict[str, Any]] = []
    error_rows: list[dict[str, Any]] = []
    for mode in modes:
      result = self._evaluate_mode(samples, mode)
      mode_results[mode] = result
      by_tag_rows.extend(self._build_by_tag_rows(mode, result))
      error_rows.extend(self._build_error_rows(mode, result))

    summary = self._build_summary(
      run_id=run_id,
      dataset_manifest=dataset_manifest,
      modes=modes,
      mode_results=mode_results,
    )
    if summary_metadata:
      summary.update(copy.deepcopy(summary_metadata))

    output_dir.mkdir(parents=True, exist_ok=True)
    summary_path = output_dir / "pii_eval_summary.json"
    by_tag_path = output_dir / "pii_eval_by_tag.csv"
    errors_path = output_dir / "pii_eval_errors.csv"

    with open(summary_path, "w", encoding="utf-8") as file:
      json.dump(summary, file, ensure_ascii=False, indent=2)

    self._write_csv(
      by_tag_path,
      rows=by_tag_rows,
      fieldnames=[
        "mode",
        "tag",
        "support",
        "predicted",
        "tp",
        "fp",
        "fn",
        "precision",
        "recall",
        "f1",
      ],
    )
    self._write_csv(
      errors_path,
      rows=error_rows,
      fieldnames=[
        "mode",
        "sample_id",
        "error_type",
        "gold_label",
        "pred_label",
        "route",
        "masked_snippet",
      ],
    )

    return {
      "json": summary_path,
      "by_tag_csv": by_tag_path,
      "errors_csv": errors_path,
    }

  def _evaluate_mode(
    self,
    samples: list[EvalSample],
    mode: str,
  ) -> dict[str, Any]:
    detector = self._create_detector(mode)
    if detector is not None:
      detector.warm_up()

    tp_counts = {tag: 0 for tag in CANONICAL_LABELS}
    fp_counts = {tag: 0 for tag in CANONICAL_LABELS}
    fn_counts = {tag: 0 for tag in CANONICAL_LABELS}
    errors: list[dict[str, Any]] = []
    total_gold = 0
    total_predicted = 0
    exact_match_count = 0
    canonical_match_count = 0
    runtime_totals = self._build_runtime_totals(mode, detector)

    for sample in samples:
      predictions, runtime_status = self._predict_entities(sample, mode, detector)
      total_gold += len(sample.entities)
      total_predicted += len(predictions)
      exact_match_count += len(
        {entity.key for entity in sample.entities}
        & {entity.key for entity in predictions}
      )

      comparison = self._compare_entities(sample, predictions)
      canonical_match_count += sum(comparison["tp"].values())
      self._merge_counts(tp_counts, comparison["tp"])
      self._merge_counts(fp_counts, comparison["fp"])
      self._merge_counts(fn_counts, comparison["fn"])
      errors.extend(comparison["errors"])
      self._accumulate_runtime(runtime_totals, runtime_status)

    per_tag_metrics = self._build_per_tag_metrics(tp_counts, fp_counts, fn_counts)
    totals = {
      "tp": sum(tp_counts.values()),
      "fp": sum(fp_counts.values()),
      "fn": sum(fn_counts.values()),
    }
    micro_precision = _safe_div(totals["tp"], totals["tp"] + totals["fp"])
    micro_recall = _safe_div(totals["tp"], totals["tp"] + totals["fn"])
    micro_f1 = _f1(micro_precision, micro_recall)

    active_metrics = [
      metrics
      for metrics in per_tag_metrics.values()
      if metrics["support"] > 0 or metrics["predicted"] > 0
    ]
    macro_precision = _safe_div(
      sum(item["precision"] for item in active_metrics),
      len(active_metrics),
    )
    macro_recall = _safe_div(
      sum(item["recall"] for item in active_metrics),
      len(active_metrics),
    )
    macro_f1 = _safe_div(
      sum(item["f1"] for item in active_metrics),
      len(active_metrics),
    )

    return {
      "mode": mode,
      "label_schema_version": self.label_schema_version,
      "artifact_policy": ARTIFACT_POLICY,
      "sample_count": len(samples),
      "gold_entity_count": total_gold,
      "predicted_entity_count": total_predicted,
      "exact_match_count": exact_match_count,
      "canonical_match_count": canonical_match_count,
      "overall_micro_precision": round(micro_precision, 6),
      "overall_micro_recall": round(micro_recall, 6),
      "overall_micro_f1": round(micro_f1, 6),
      "overall_macro_precision": round(macro_precision, 6),
      "overall_macro_recall": round(macro_recall, 6),
      "overall_macro_f1": round(macro_f1, 6),
      "active_tag_count": len(active_metrics),
      "per_tag_metrics": per_tag_metrics,
      "runtime_status": runtime_totals,
      "errors": errors,
    }

  def _create_detector(self, mode: str) -> PIIDetector | None:
    if mode == "step1":
      return None

    mode_config = copy.deepcopy(self.config)
    runtime_config = mode_config.setdefault("pii", {}).setdefault("runtime", {})
    if mode == "step1_2":
      runtime_config["enable_step3"] = False
      runtime_config["enable_step4"] = False
    elif mode == "step1_2_3":
      runtime_config["enable_step4"] = False

    return PIIDetector(mode_config)

  def _predict_entities(
    self,
    sample: EvalSample,
    mode: str,
    detector: PIIDetector | None,
  ) -> tuple[list[EvalEntity], dict[str, Any]]:
    if mode == "step1":
      regex_matches = self.regex_detector.detect(sample.text)
      predictions = [
        self._entity_from_regex_match(sample, match)
        for match in regex_matches
      ]
      runtime_status = self._build_step1_runtime_status(len(regex_matches))
      return predictions, runtime_status

    if detector is None:
      raise ValueError(f"Detector unexpectedly missing for mode '{mode}'.")

    detected = detector.detect(sample.text)
    confirmed = detected.get("confirmed", [])
    predictions = [
      self._entity_from_confirmed(sample, item)
      for item in confirmed
    ]
    runtime_status = dict(detected.get("runtime_status", {}))
    return predictions, runtime_status

  def _entity_from_regex_match(self, sample: EvalSample, match: PIIMatch) -> EvalEntity:
    return EvalEntity(
      sample_id=sample.sample_id,
      start=match.start,
      end=match.end,
      label=normalize_label(match.tag),
      text=match.text,
      route="STEP1_RAW",
      source="regex",
      confidence=1.0,
    )

  def _entity_from_confirmed(
    self,
    sample: EvalSample,
    item: ConfirmedPII,
  ) -> EvalEntity:
    return EvalEntity(
      sample_id=sample.sample_id,
      start=item.start,
      end=item.end,
      label=normalize_label(item.tag),
      text=item.text,
      route=item.route,
      source=item.source,
      confidence=float(item.confidence),
    )

  def _match_entities(
    self,
    gold_entities: tuple[EvalEntity, ...],
    predictions: list[EvalEntity],
  ) -> list[tuple[int, int]]:
    """
    gold 와 예측 엔티티를 canonical 기준으로 1:1 그리디 매칭한다.

    두 엔티티는 (1) 라벨이 같고 (2) 스팬이 겹치며 (3) canonical 값이 같거나
    스팬 IoU 가 임계값 이상일 때 매칭 후보가 된다. 후보를 매칭 점수(canonical 일치
    가산 + IoU) 내림차순으로 배정해 각 엔티티가 최대 한 번만 매칭되게 한다. 이로써
    완전일치 채점이 놓치던 (a) 변형 PII(전각·자모 등, canonical 일치)와 (b) 경계
    어긋남(IoU 부분일치)을 모두 TP 로 인정한다.

    Args:
      gold_entities: 정답 엔티티들
      predictions: 예측 엔티티들

    Returns:
      list[tuple[int, int]]: 매칭된 (gold_index, pred_index) 쌍 목록
    """
    gold_canonical = [entity.canonical for entity in gold_entities]
    pred_canonical = [entity.canonical for entity in predictions]

    candidates: list[tuple[float, int, int]] = []
    for gold_index, gold_entity in enumerate(gold_entities):
      for pred_index, pred_entity in enumerate(predictions):
        if gold_entity.label != pred_entity.label:
          continue
        iou = _span_iou(
          gold_entity.start, gold_entity.end, pred_entity.start, pred_entity.end
        )
        if iou <= 0.0:
          continue
        same_canonical = (
          gold_canonical[gold_index] != ""
          and gold_canonical[gold_index] == pred_canonical[pred_index]
        )
        if same_canonical or iou >= self.match_iou_threshold:
          score = (1.0 if same_canonical else 0.0) + iou
          candidates.append((score, gold_index, pred_index))

    candidates.sort(key=lambda item: item[0], reverse=True)
    matched_gold: set[int] = set()
    matched_pred: set[int] = set()
    pairs: list[tuple[int, int]] = []
    for _score, gold_index, pred_index in candidates:
      if gold_index in matched_gold or pred_index in matched_pred:
        continue
      matched_gold.add(gold_index)
      matched_pred.add(pred_index)
      pairs.append((gold_index, pred_index))
    return pairs

  def _compare_entities(
    self,
    sample: EvalSample,
    predictions: list[EvalEntity],
  ) -> dict[str, Any]:
    tp_counts = {tag: 0 for tag in CANONICAL_LABELS}
    fp_counts = {tag: 0 for tag in CANONICAL_LABELS}
    fn_counts = {tag: 0 for tag in CANONICAL_LABELS}
    errors: list[dict[str, Any]] = []

    gold_entities = sample.entities
    pairs = self._match_entities(gold_entities, predictions)
    matched_gold = {gold_index for gold_index, _ in pairs}
    matched_pred = {pred_index for _, pred_index in pairs}
    for gold_index, _pred_index in pairs:
      tp_counts[gold_entities[gold_index].label] += 1

    # 라벨 불일치: 매칭되지 않은 gold·pred 중 스팬이 충분히 겹치지만(IoU≥임계) 라벨이
    # 다른 쌍을 label_mismatch 로 기록한다(FP+FN 동시 계상). 완전일치 시절의 진단 보존.
    mismatch_gold: set[int] = set()
    mismatch_pred: set[int] = set()
    for gold_index, gold_entity in enumerate(gold_entities):
      if gold_index in matched_gold:
        continue
      for pred_index, pred_entity in enumerate(predictions):
        if pred_index in matched_pred or pred_index in mismatch_pred:
          continue
        if gold_entity.label == pred_entity.label:
          continue
        iou = _span_iou(
          gold_entity.start, gold_entity.end, pred_entity.start, pred_entity.end
        )
        if iou < self.match_iou_threshold:
          continue
        mismatch_gold.add(gold_index)
        mismatch_pred.add(pred_index)
        fp_counts[pred_entity.label] += 1
        fn_counts[gold_entity.label] += 1
        errors.append(
          {
            "sample_id": sample.sample_id,
            "error_type": "label_mismatch",
            "gold_label": gold_entity.label,
            "pred_label": pred_entity.label,
            "route": pred_entity.route,
            "masked_snippet": self._masked_snippet(
              sample.text,
              start=gold_entity.start,
              end=gold_entity.end,
              label=gold_entity.label,
              route=pred_entity.route,
              source=pred_entity.source,
            ),
          }
        )
        break

    for pred_index, pred_entity in enumerate(predictions):
      if pred_index in matched_pred or pred_index in mismatch_pred:
        continue
      fp_counts[pred_entity.label] += 1
      errors.append(
        {
          "sample_id": sample.sample_id,
          "error_type": "fp",
          "gold_label": "",
          "pred_label": pred_entity.label,
          "route": pred_entity.route,
          "masked_snippet": self._masked_snippet(
            sample.text,
            start=pred_entity.start,
            end=pred_entity.end,
            label=pred_entity.label,
            route=pred_entity.route,
            source=pred_entity.source,
          ),
        }
      )

    for gold_index, gold_entity in enumerate(gold_entities):
      if gold_index in matched_gold or gold_index in mismatch_gold:
        continue
      fn_counts[gold_entity.label] += 1
      errors.append(
        {
          "sample_id": sample.sample_id,
          "error_type": "fn",
          "gold_label": gold_entity.label,
          "pred_label": "",
          "route": "gold_only",
          "masked_snippet": self._masked_snippet(
            sample.text,
            start=gold_entity.start,
            end=gold_entity.end,
            label=gold_entity.label,
            route=gold_entity.route,
            source=gold_entity.source,
          ),
        }
      )

    return {
      "tp": tp_counts,
      "fp": fp_counts,
      "fn": fn_counts,
      "errors": errors,
    }

  def _masked_snippet(
    self,
    text: str,
    *,
    start: int,
    end: int,
    label: str,
    route: str,
    source: str,
  ) -> str:
    snippet_start = max(0, start - self.error_context_chars)
    snippet_end = min(len(text), end + self.error_context_chars)
    snippet = text[snippet_start:snippet_end]
    local_start = start - snippet_start
    local_end = end - snippet_start
    pii = ConfirmedPII(
      tag=label,
      text=text[start:end],
      start=local_start,
      end=local_end,
      route=route,
      source=source,
      confidence=1.0,
    )
    return self.masker.mask_text(snippet, [pii])

  def _build_per_tag_metrics(
    self,
    tp_counts: dict[str, int],
    fp_counts: dict[str, int],
    fn_counts: dict[str, int],
  ) -> dict[str, dict[str, Any]]:
    metrics: dict[str, dict[str, Any]] = {}
    for tag in CANONICAL_LABELS:
      precision = _safe_div(tp_counts[tag], tp_counts[tag] + fp_counts[tag])
      recall = _safe_div(tp_counts[tag], tp_counts[tag] + fn_counts[tag])
      metrics[tag] = {
        "support": tp_counts[tag] + fn_counts[tag],
        "predicted": tp_counts[tag] + fp_counts[tag],
        "tp": tp_counts[tag],
        "fp": fp_counts[tag],
        "fn": fn_counts[tag],
        "precision": round(precision, 6),
        "recall": round(recall, 6),
        "f1": round(_f1(precision, recall), 6),
      }
    return metrics

  def _build_runtime_totals(
    self,
    mode: str,
    detector: PIIDetector | None,
  ) -> dict[str, Any]:
    if mode == "step1":
      return self._build_step1_runtime_status(0)

    if detector is None:
      raise ValueError(f"Detector unexpectedly missing for mode '{mode}'.")

    return {
      "step1": {"detected_count": 0},
      "step2": {"validated_count": 0},
      "step3": {
        **detector.ner_detector.get_runtime_status(),
        "match_count_total": 0,
        "route_b1_total": 0,
        "route_b2_total": 0,
      },
      "step4": {
        **detector.sllm_verifier.get_runtime_status(),
        "candidate_count_total": 0,
        "verified_count_total": 0,
        "reason_counts": {},
      },
    }

  def _build_step1_runtime_status(self, detected_count: int) -> dict[str, Any]:
    return {
      "step1": {"detected_count": detected_count},
      "step2": {
        "enabled": False,
        "validated_count": 0,
        "status": "skipped",
        "reason": "mode_step1",
      },
      "step3": {
        "enabled": False,
        "model_source": "disabled",
        "load_status": "skipped",
        "error": "mode_step1",
        "match_count_total": 0,
        "route_b1_total": 0,
        "route_b2_total": 0,
      },
      "step4": {
        "enabled": False,
        "mode": "disabled",
        "status": "skipped",
        "reason": "mode_step1",
        "candidate_count_total": 0,
        "verified_count_total": 0,
        "reason_counts": {"mode_step1": 1},
      },
    }

  def _accumulate_runtime(
    self,
    aggregate: dict[str, Any],
    runtime_status: dict[str, Any],
  ) -> None:
    step1 = runtime_status.get("step1", {})
    step2 = runtime_status.get("step2", {})
    step3 = runtime_status.get("step3", {})
    step4 = runtime_status.get("step4", {})

    aggregate["step1"]["detected_count"] += int(step1.get("detected_count", 0))
    aggregate["step2"]["validated_count"] = (
      int(aggregate["step2"].get("validated_count", 0))
      + int(step2.get("validated_count", 0))
    )

    aggregate_step3 = aggregate["step3"]
    for field in (
      "enabled",
      "model_path",
      "resolved_model_identifier",
      "resolved_revision",
      "model_source",
      "load_status",
      "error",
    ):
      if field in step3:
        aggregate_step3[field] = step3[field]
    aggregate_step3["match_count_total"] += int(step3.get("match_count", 0))
    aggregate_step3["route_b1_total"] += int(step3.get("route_b1_count", 0))
    aggregate_step3["route_b2_total"] += int(step3.get("route_b2_count", 0))

    aggregate_step4 = aggregate["step4"]
    for field in ("enabled", "mode", "status", "model", "error"):
      if field in step4:
        aggregate_step4[field] = step4[field]
    aggregate_step4["candidate_count_total"] += int(step4.get("candidate_count", 0))
    aggregate_step4["verified_count_total"] += int(step4.get("verified_count", 0))
    reason = str(step4.get("reason", "") or "unknown")
    reason_counts = aggregate_step4.setdefault("reason_counts", {})
    reason_counts[reason] = reason_counts.get(reason, 0) + 1

  def _merge_counts(self, target: dict[str, int], update: dict[str, int]) -> None:
    for tag, count in update.items():
      target[tag] = target.get(tag, 0) + int(count)

  def _build_summary(
    self,
    *,
    run_id: str,
    dataset_manifest: dict[str, Any],
    modes: list[str],
    mode_results: dict[str, dict[str, Any]],
  ) -> dict[str, Any]:
    summary: dict[str, Any] = {
      "eval_run_id": run_id,
      "dataset_manifest": dataset_manifest,
      "requested_modes": modes,
      "label_schema_version": self.label_schema_version,
      "artifact_policy": ARTIFACT_POLICY,
      "mode_results": mode_results,
    }

    if len(modes) == 1:
      single_mode = mode_results[modes[0]]
      summary.update(
        {
          "mode": single_mode["mode"],
          "overall_micro_precision": single_mode["overall_micro_precision"],
          "overall_micro_recall": single_mode["overall_micro_recall"],
          "overall_micro_f1": single_mode["overall_micro_f1"],
          "overall_macro_precision": single_mode["overall_macro_precision"],
          "overall_macro_recall": single_mode["overall_macro_recall"],
          "overall_macro_f1": single_mode["overall_macro_f1"],
          "per_tag_metrics": single_mode["per_tag_metrics"],
          "runtime_status": single_mode["runtime_status"],
        }
      )

    return summary

  def _build_by_tag_rows(
    self,
    mode: str,
    result: dict[str, Any],
  ) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for tag, metrics in result.get("per_tag_metrics", {}).items():
      rows.append(
        {
          "mode": mode,
          "tag": tag,
          "support": metrics["support"],
          "predicted": metrics["predicted"],
          "tp": metrics["tp"],
          "fp": metrics["fp"],
          "fn": metrics["fn"],
          "precision": metrics["precision"],
          "recall": metrics["recall"],
          "f1": metrics["f1"],
        }
      )
    return rows

  def _build_error_rows(
    self,
    mode: str,
    result: dict[str, Any],
  ) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in result.get("errors", []):
      row = dict(item)
      row["mode"] = mode
      rows.append(row)
    return rows

  def _write_csv(
    self,
    path: Path,
    *,
    rows: list[dict[str, Any]],
    fieldnames: list[str],
  ) -> None:
    with open(path, "w", encoding="utf-8", newline="") as file:
      writer = csv.DictWriter(file, fieldnames=fieldnames)
      writer.writeheader()
      for row in rows:
        writer.writerow(row)


def serialize_eval_snapshot(
  *,
  dataset_manifest: dict[str, Any],
  modes: list[str],
  label_schema_version: str,
) -> dict[str, Any]:
  """Build the extra snapshot metadata stored for one pii-eval run."""
  return {
    "pii_eval": {
      "dataset_manifest": dataset_manifest,
      "requested_modes": modes,
      "label_schema_version": label_schema_version,
      "artifact_policy": ARTIFACT_POLICY,
    }
  }


def _safe_div(numerator: float, denominator: float) -> float:
  if denominator == 0:
    return 0.0
  return numerator / denominator


def _f1(precision: float, recall: float) -> float:
  if precision == 0.0 and recall == 0.0:
    return 0.0
  return 2 * precision * recall / (precision + recall)
