"""Run directory, snapshot, checkpoint, and partial-result helpers."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from loguru import logger

REQUIRED_PROVENANCE_FIELDS = (
  "code_version",
  "python_version",
  "platform",
  "random_seed",
  "embedding_model",
  "reranker_model",
  "pii_ner_model",
  "pii_sllm_model",
  "index_manifest_ref",
  "index_manifest_hash",
)
SECRET_FIELD_TOKENS = (
  "api_key",
  "authorization",
  "password",
  "secret",
  "token",
)


class ExperimentManager:
  """Manage run-scoped artifacts under one result directory."""

  def __init__(
    self,
    config: dict[str, Any],
    *,
    results_dir_override: str | Path | None = None,
  ) -> None:
    self.results_dir = Path(
      results_dir_override
      or os.getenv(
        "RAG_RESULTS_PATH",
        config.get("report", {}).get("output_dir", "data/results"),
      )
    )
    self.results_dir.mkdir(parents=True, exist_ok=True)

  def create_run(self, prefix: str = "RAG") -> str:
    """Create a new run directory and return its run id."""
    today = datetime.now().strftime("%Y-%m%d")
    existing_runs = list(self.results_dir.glob(f"{prefix}-{today}-*"))
    run_id = f"{prefix}-{today}-{len(existing_runs) + 1:03d}"
    self._ensure_run_dir(run_id)
    logger.info("Created run {} at {}", run_id, self._run_dir(run_id))
    return run_id

  def save_snapshot(
    self,
    run_id: str,
    config: dict[str, Any],
    metadata: dict[str, Any] | None = None,
  ) -> Path:
    """Save or overwrite the run snapshot."""
    self._ensure_run_dir(run_id)
    snapshot = {
      "run_id": run_id,
      "created_at": datetime.now().isoformat(),
      "config": deepcopy(config),
    }
    if metadata:
      snapshot.update(deepcopy(metadata))

    resolved_config = snapshot.get("config", {}) or {}
    snapshot["config_fingerprint"] = snapshot.get("config_fingerprint") or fingerprint_payload(
      resolved_config
    )
    existing_provenance = snapshot.get("provenance", {})
    computed_provenance = build_snapshot_provenance(resolved_config, snapshot)
    if isinstance(existing_provenance, dict):
      snapshot["provenance"] = _deep_merge_dicts(computed_provenance, existing_provenance)
    else:
      snapshot["provenance"] = computed_provenance

    snapshot_path = self._run_dir(run_id) / "snapshot.yaml"
    with open(snapshot_path, "w", encoding="utf-8") as file:
      yaml.safe_dump(snapshot, file, allow_unicode=True, sort_keys=False)

    logger.info("Saved snapshot to {}", snapshot_path)
    return snapshot_path

  def load_snapshot(self, run_id: str) -> dict[str, Any]:
    """Load a run snapshot."""
    snapshot_path = self._run_dir(run_id) / "snapshot.yaml"
    if not snapshot_path.exists():
      raise FileNotFoundError(f"Snapshot not found: {snapshot_path}")
    with open(snapshot_path, "r", encoding="utf-8") as file:
      return yaml.safe_load(file) or {}

  def save_result(
    self,
    run_id: str,
    result: dict[str, Any],
    filename: str = "result.json",
  ) -> Path:
    """Save a final result artifact."""
    self._ensure_run_dir(run_id)
    result_path = self._run_dir(run_id) / filename
    with open(result_path, "w", encoding="utf-8") as file:
      json.dump(result, file, ensure_ascii=False, indent=2)
    logger.info("Saved result to {}", result_path)
    return result_path

  def replay_audit_path(self, run_id: str) -> Path:
    """Return the replay_audit.json path for a replayed run."""
    return self._run_dir(run_id) / "replay_audit.json"

  def save_replay_audit(self, run_id: str, audit: dict[str, Any]) -> Path:
    """Persist replay audit details for a newly replayed run."""
    self._ensure_run_dir(run_id)
    payload = dict(audit)
    payload["generated_at"] = datetime.now().isoformat()
    audit_path = self.replay_audit_path(run_id)
    with open(audit_path, "w", encoding="utf-8") as file:
      json.dump(payload, file, ensure_ascii=False, indent=2)
    logger.info("Saved replay audit to {}", audit_path)
    return audit_path

  def save_checkpoint(self, run_id: str, checkpoint: dict[str, Any]) -> Path:
    """Save a checkpoint.json file for resuming long runs."""
    self._ensure_run_dir(run_id)
    checkpoint = dict(checkpoint)
    checkpoint["run_id"] = run_id
    checkpoint["updated_at"] = datetime.now().isoformat()
    checkpoint_path = self._run_dir(run_id) / "checkpoint.json"
    with open(checkpoint_path, "w", encoding="utf-8") as file:
      json.dump(checkpoint, file, ensure_ascii=False, indent=2)
    logger.info("Saved checkpoint to {}", checkpoint_path)
    return checkpoint_path

  def load_checkpoint(self, run_id: str) -> dict[str, Any]:
    """Load an existing checkpoint."""
    checkpoint_path = self._run_dir(run_id) / "checkpoint.json"
    if not checkpoint_path.exists():
      raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
    with open(checkpoint_path, "r", encoding="utf-8") as file:
      return json.load(file)

  def save_partial_results(
    self,
    run_id: str,
    scenario: str,
    results: list[dict[str, Any]],
  ) -> Path:
    """Persist scenario-scoped partial results for checkpoint/resume."""
    self._ensure_run_dir(run_id)
    partial_path = self._run_dir(run_id) / f"{scenario.upper()}_partial.json"
    payload = {
      "run_id": run_id,
      "scenario": scenario.upper(),
      "updated_at": datetime.now().isoformat(),
      "result_count": len(results),
      "results": results,
    }
    with open(partial_path, "w", encoding="utf-8") as file:
      json.dump(payload, file, ensure_ascii=False, indent=2)
    logger.info("Saved partial results to {}", partial_path)
    return partial_path

  def load_partial_results(self, run_id: str, scenario: str) -> list[dict[str, Any]]:
    """Load previously saved scenario-scoped partial results."""
    partial_path = self._run_dir(run_id) / f"{scenario.upper()}_partial.json"
    if not partial_path.exists():
      return []
    with open(partial_path, "r", encoding="utf-8") as file:
      payload = json.load(file)
    return list(payload.get("results", []))

  def partial_results_path(self, run_id: str, scenario: str) -> Path:
    """Return the path of the partial result artifact."""
    return self._run_dir(run_id) / f"{scenario.upper()}_partial.json"

  def save_partial_failures(
    self,
    run_id: str,
    scenario: str,
    failures: list[dict[str, Any]],
  ) -> Path:
    """Persist scenario-scoped failure history for checkpoint/resume/reporting."""
    self._ensure_run_dir(run_id)
    failure_path = self.partial_failures_path(run_id, scenario)
    payload = {
      "run_id": run_id,
      "scenario": scenario.upper(),
      "updated_at": datetime.now().isoformat(),
      "failure_count": len(failures),
      "failures": failures,
    }
    with open(failure_path, "w", encoding="utf-8") as file:
      json.dump(payload, file, ensure_ascii=False, indent=2)
    logger.info("Saved partial failures to {}", failure_path)
    return failure_path

  def load_partial_failures(self, run_id: str, scenario: str) -> list[dict[str, Any]]:
    """Load previously saved scenario-scoped failures."""
    failure_path = self.partial_failures_path(run_id, scenario)
    if not failure_path.exists():
      return []
    with open(failure_path, "r", encoding="utf-8") as file:
      payload = json.load(file)
    return list(payload.get("failures", []))

  def partial_failures_path(self, run_id: str, scenario: str) -> Path:
    """Return the path of the partial failure artifact."""
    return self._run_dir(run_id) / f"{scenario.upper()}_failures.json"

  def checkpoint_path(self, run_id: str) -> Path:
    """Return the checkpoint path for a run."""
    return self._run_dir(run_id) / "checkpoint.json"

  def suite_manifest_path(self, run_id: str) -> Path:
    """Return the suite manifest path for a suite run."""
    return self._run_dir(run_id) / "suite_manifest.json"

  def save_suite_manifest(self, run_id: str, manifest: dict[str, Any]) -> Path:
    """Save a suite manifest artifact."""
    self._ensure_run_dir(run_id)
    payload = dict(manifest)
    payload["run_id"] = run_id
    manifest_path = self.suite_manifest_path(run_id)
    with open(manifest_path, "w", encoding="utf-8") as file:
      json.dump(payload, file, ensure_ascii=False, indent=2)
    logger.info("Saved suite manifest to {}", manifest_path)
    return manifest_path

  def load_suite_manifest(self, run_id: str) -> dict[str, Any]:
    """Load a suite manifest."""
    manifest_path = self.suite_manifest_path(run_id)
    if not manifest_path.exists():
      raise FileNotFoundError(f"Suite manifest not found: {manifest_path}")
    with open(manifest_path, "r", encoding="utf-8") as file:
      return json.load(file)

  def suite_checkpoint_path(self, run_id: str) -> Path:
    """Return the suite checkpoint path for a suite run."""
    return self._run_dir(run_id) / "suite_checkpoint.json"

  def save_suite_checkpoint(self, run_id: str, checkpoint: dict[str, Any]) -> Path:
    """Save a suite checkpoint artifact."""
    self._ensure_run_dir(run_id)
    payload = dict(checkpoint)
    payload["run_id"] = run_id
    payload["updated_at"] = datetime.now().isoformat()
    checkpoint_path = self.suite_checkpoint_path(run_id)
    with open(checkpoint_path, "w", encoding="utf-8") as file:
      json.dump(payload, file, ensure_ascii=False, indent=2)
    logger.info("Saved suite checkpoint to {}", checkpoint_path)
    return checkpoint_path

  def load_suite_checkpoint(self, run_id: str) -> dict[str, Any]:
    """Load a suite checkpoint."""
    checkpoint_path = self.suite_checkpoint_path(run_id)
    if not checkpoint_path.exists():
      raise FileNotFoundError(f"Suite checkpoint not found: {checkpoint_path}")
    with open(checkpoint_path, "r", encoding="utf-8") as file:
      return json.load(file)

  def run_dir(self, run_id: str) -> Path:
    """Return the on-disk run directory path."""
    return self._run_dir(run_id)

  def _run_dir(self, run_id: str) -> Path:
    return self.results_dir / run_id

  def _ensure_run_dir(self, run_id: str) -> Path:
    run_dir = self._run_dir(run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir


def fingerprint_payload(payload: Any) -> str:
  """Return a stable SHA-256 fingerprint for a serializable payload."""
  normalized = json.dumps(
    _normalize_payload(payload),
    ensure_ascii=False,
    sort_keys=True,
    separators=(",", ":"),
  )
  return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def build_snapshot_provenance(
  config: dict[str, Any],
  snapshot_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
  """Build one normalized provenance record for snapshots."""
  context = snapshot_context or {}
  retrieval_config = config.get("retrieval_config", {})
  reranker_config = retrieval_config.get("reranker", {})
  index_manifest = context.get("index_manifest", {}) if isinstance(context, dict) else {}
  index_manifest_ref = ""
  if isinstance(context, dict):
    index_manifest_ref = str(context.get("index_manifest_ref") or "")

  index_manifest_hash = ""
  if isinstance(context, dict):
    index_manifest_hash = str(context.get("index_manifest_hash") or "")
  if not index_manifest_hash and isinstance(index_manifest, dict) and index_manifest:
    index_manifest_hash = fingerprint_payload(index_manifest)

  return {
    "code_version": _resolve_code_version(),
    "python_version": platform.python_version(),
    "platform": platform.platform(),
    "random_seed": config.get("experiment", {}).get("random_seed", ""),
    "embedding_model": config.get("embedding", {}).get("model_name", ""),
    "reranker_model": reranker_config.get(
      "model_name",
      config.get("reranker", {}).get("model_name", ""),
    ),
    "pii_ner_model": config.get("pii", {}).get("ner", {}).get("model_path", ""),
    "pii_sllm_model": config.get("pii", {}).get("sllm", {}).get("model", ""),
    "index_manifest_ref": index_manifest_ref,
    "index_manifest_hash": index_manifest_hash,
  }


def snapshot_uses_compatibility_mode(snapshot: dict[str, Any]) -> bool:
  """Return True when a snapshot predates the normalized provenance schema."""
  provenance = snapshot.get("provenance")
  if not snapshot.get("config_fingerprint"):
    return True
  if not isinstance(provenance, dict):
    return True
  return any(field not in provenance for field in REQUIRED_PROVENANCE_FIELDS)


def build_replay_audit(
  *,
  source_run_id: str,
  source_run_type: str,
  replayed_run_id: str,
  source_snapshot: dict[str, Any],
  replay_snapshot: dict[str, Any],
  compatibility_mode: bool,
  index_manifest_match: bool | None,
) -> dict[str, Any]:
  """Build the replay audit payload stored beside a replayed run."""
  return {
    "source_run_id": source_run_id,
    "source_run_type": source_run_type,
    "replayed_run_id": replayed_run_id,
    "compatibility_mode": compatibility_mode,
    "snapshot_diff": diff_payloads(
      _snapshot_diff_view(source_snapshot),
      _snapshot_diff_view(replay_snapshot),
    ),
    "provenance_diff": diff_payloads(
      source_snapshot.get("provenance", {}),
      replay_snapshot.get("provenance", {}),
    ),
    "index_manifest_match": index_manifest_match,
  }


def diff_payloads(source: Any, target: Any) -> list[dict[str, Any]]:
  """Return key-level additions, removals, and value changes between payloads."""
  differences: list[dict[str, Any]] = []
  _diff_payloads(source, target, differences, path="")
  return differences


def _diff_payloads(
  source: Any,
  target: Any,
  differences: list[dict[str, Any]],
  *,
  path: str,
) -> None:
  if isinstance(source, dict) and isinstance(target, dict):
    keys = sorted(set(source) | set(target))
    for key in keys:
      child_path = f"{path}.{key}" if path else str(key)
      if key not in source:
        differences.append(
          {
            "path": child_path,
            "change": "added",
            "new": _redact_diff_value(child_path, target[key]),
          }
        )
        continue
      if key not in target:
        differences.append(
          {
            "path": child_path,
            "change": "removed",
            "old": _redact_diff_value(child_path, source[key]),
          }
        )
        continue
      _diff_payloads(source[key], target[key], differences, path=child_path)
    return

  if source != target:
    differences.append(
      {
        "path": path or "$",
        "change": "changed",
        "old": _redact_diff_value(path, source),
        "new": _redact_diff_value(path, target),
      }
    )


def _snapshot_diff_view(snapshot: dict[str, Any]) -> dict[str, Any]:
  filtered = deepcopy(snapshot)
  for key in (
    "run_id",
    "created_at",
    "updated_at",
    "provenance",
    "replayed_from_run_id",
    "compatibility_mode",
  ):
    filtered.pop(key, None)
  return filtered


def _redact_diff_value(path: str, value: Any) -> Any:
  lowered_path = path.lower()
  if any(token in lowered_path for token in SECRET_FIELD_TOKENS):
    return "<redacted>"
  return _normalize_payload(value)


def _normalize_payload(value: Any) -> Any:
  if isinstance(value, dict):
    return {
      str(key): _normalize_payload(item)
      for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
    }
  if isinstance(value, (list, tuple)):
    return [_normalize_payload(item) for item in value]
  if isinstance(value, Path):
    return str(value)
  if isinstance(value, (str, int, float, bool)) or value is None:
    return value
  return str(value)


def _resolve_code_version() -> dict[str, Any]:
  """Collect a best-effort git-aware code version record."""
  project_root = Path(__file__).resolve().parents[3]
  git_head, head_error = _run_git_command(project_root, "rev-parse", "HEAD")
  git_status, status_error = _run_git_command(project_root, "status", "--porcelain")

  if git_head:
    return {
      "source": "git",
      "git_head": git_head,
      "working_tree": "dirty" if git_status else "clean",
      "error": status_error if status_error and not git_status else "",
    }

  return {
    "source": "unavailable",
    "git_head": "",
    "working_tree": "unknown",
    "error": head_error or status_error or "git metadata unavailable",
  }


def _run_git_command(project_root: Path, *args: str) -> tuple[str, str]:
  try:
    completed = subprocess.run(
      ["git", *args],
      cwd=project_root,
      capture_output=True,
      text=True,
      check=False,
      timeout=5,
    )
  except (OSError, subprocess.SubprocessError) as error:
    return "", str(error)

  stdout = completed.stdout.strip()
  stderr = completed.stderr.strip()
  if completed.returncode != 0:
    return "", stderr or stdout or f"git exited with {completed.returncode}"
  return stdout, ""


def _deep_merge_dicts(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
  merged = deepcopy(base)
  for key, value in override.items():
    if isinstance(value, dict) and isinstance(merged.get(key), dict):
      merged[key] = _deep_merge_dicts(merged[key], value)
    else:
      merged[key] = deepcopy(value)
  return merged
