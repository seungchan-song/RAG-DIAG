"""KDPII-style benchmark evaluation for the layered PII pipeline."""

from __future__ import annotations

import copy
import csv
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rag.pii.classifier import ConfirmedPII
from rag.pii.detector import PIIDetector
from rag.pii.masker import PIIMasker
from rag.pii.step1_regex import PIIMatch, RegexDetector

LABEL_SCHEMA_VERSION = "kdpii-33-v1"
ARTIFACT_POLICY = "masked_only"
EVAL_MODES = ("step1", "step1_2", "step1_2_3", "full")

CANONICAL_LABELS = (
  "DAT",
  "LOC",
  "ORG",
  "PER",
  "QT_ADDR",
  "QT_AGE",
  "QT_ARN",
  "QT_CARD",
  "QT_CAR",
  "QT_IP",
  "QT_MOBILE",
  "QT_PASSPORT",
  "QT_PHONE",
  "QT_RRN",
  "TMI_BIRTH",
  "TMI_BLOOD_TYPE",
  "TMI_BODY",
  "TMI_DISABILITY",
  "TMI_EDUCATION",
  "TMI_EMAIL",
  "TMI_FAMILY",
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
)

LABEL_ALIASES = {
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
  "MOBILE": "QT_MOBILE",
  "MOBILE_PHONE": "QT_MOBILE",
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
  """One normalized span-level entity used for exact-match evaluation."""

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
  """Run one or more exact-match PII benchmark modes and write safe artifacts."""

  def __init__(self, config: dict[str, Any]) -> None:
    self.config = copy.deepcopy(config)
    eval_config = self.config.get("pii", {}).get("eval", {})
    self.label_schema_version = str(
      eval_config.get("label_schema_version", LABEL_SCHEMA_VERSION)
    )
    self.error_context_chars = int(eval_config.get("error_context_chars", 20))
    self.regex_detector = RegexDetector()
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

  def _compare_entities(
    self,
    sample: EvalSample,
    predictions: list[EvalEntity],
  ) -> dict[str, Any]:
    gold_by_key = {entity.key: entity for entity in sample.entities}
    pred_by_key = {entity.key: entity for entity in predictions}
    gold_by_span = {entity.span_key: entity for entity in sample.entities}
    pred_by_span = {entity.span_key: entity for entity in predictions}

    tp_counts = {tag: 0 for tag in CANONICAL_LABELS}
    fp_counts = {tag: 0 for tag in CANONICAL_LABELS}
    fn_counts = {tag: 0 for tag in CANONICAL_LABELS}
    errors: list[dict[str, Any]] = []

    matched_keys = set(gold_by_key) & set(pred_by_key)
    for key in matched_keys:
      tp_counts[key[2]] += 1

    mismatch_pred_keys: set[tuple[int, int, str]] = set()
    mismatch_gold_keys: set[tuple[int, int, str]] = set()

    for span_key, pred_entity in pred_by_span.items():
      gold_entity = gold_by_span.get(span_key)
      if gold_entity is None or gold_entity.label == pred_entity.label:
        continue

      mismatch_pred_keys.add(pred_entity.key)
      mismatch_gold_keys.add(gold_entity.key)
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

    for pred_entity in predictions:
      if pred_entity.key in matched_keys or pred_entity.key in mismatch_pred_keys:
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

    for gold_entity in sample.entities:
      if gold_entity.key in matched_keys or gold_entity.key in mismatch_gold_keys:
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
