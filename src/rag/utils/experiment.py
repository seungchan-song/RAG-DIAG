"""Run directory, snapshot, checkpoint, and partial-result helpers."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
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
SECRET_PLACEHOLDER = "<redacted>"


def redact_secrets(value: Any) -> Any:
  """설정 트리에서 비밀값 필드만 자리표시자로 바꾼 사본을 돌려준다.

  `_redact_diff_value` 가 config diff 렌더링에만 쓰던 정책(SECRET_FIELD_TOKENS)을
  **밖으로 나가는 산출물에도** 적용하기 위한 공용 헬퍼다. 실제 유출 경로는
  HTML 리포트였다 — `report/generator.py` 가 `snapshot.config.adapter` 를 통째로
  임베드해서, 외부 RAG 를 진단하면 대상의 Bearer 토큰이 심사위원에게 건네는
  `report_dashboard.html` 안에 평문으로 실렸다.

  키 이름만 보고 판단하므로 구조는 그대로 보존된다(대시보드가 읽는
  `adapter.type`·`capabilities`·`generator` 는 영향 없음).

  Args:
    value: 설정 딕셔너리/리스트/스칼라. 원본은 변경하지 않는다.

  Returns:
    Any: 비밀 필드가 `<redacted>` 로 치환된 새 객체.
  """
  if isinstance(value, dict):
    redacted: dict[str, Any] = {}
    for key, item in value.items():
      lowered = str(key).lower()
      if any(token in lowered for token in SECRET_FIELD_TOKENS):
        redacted[str(key)] = SECRET_PLACEHOLDER
      else:
        redacted[str(key)] = redact_secrets(item)
    return redacted
  if isinstance(value, list):
    return [redact_secrets(item) for item in value]
  return value


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
    # 일련번호는 **개수**가 아니라 기존 **최대 번호 + 1** 로 뽑는다. 개수로 세면 중간 런을
    # 하나라도 지웠을 때 살아 있는 런 ID 를 다시 발급해 그 디렉터리를 덮어쓴다
    # (2026-08-11 실제 사고: RAG-2026-0811-001 을 지운 상태에서 suite 가 데모 런
    #  RAG-2026-0811-002 위에 얹혀 전 셀이 "scenario_scope 불일치"로 실패했다).
    used = {
      int(match.group(1))
      for path in self.results_dir.glob(f"{prefix}-{today}-*")
      if (match := re.fullmatch(rf"{re.escape(prefix)}-{today}-(\d+)", path.name))
    }
    run_id = f"{prefix}-{today}-{max(used, default=0) + 1:03d}"
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

    logger.debug("Saved snapshot to {}", snapshot_path)
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
    logger.debug("Saved result to {}", result_path)
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
    logger.debug("Saved replay audit to {}", audit_path)
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
    logger.debug("Saved checkpoint to {}", checkpoint_path)
    return checkpoint_path

  def load_checkpoint(self, run_id: str) -> dict[str, Any]:
    """Load an existing checkpoint."""
    checkpoint_path = self._run_dir(run_id) / "checkpoint.json"
    if not checkpoint_path.exists():
      raise FileNotFoundError(f"Checkpoint not found: {checkpoint_path}")
    with open(checkpoint_path, "r", encoding="utf-8") as file:
      return json.load(file)

  def append_partial_result(
    self,
    run_id: str,
    scenario: str,
    result: dict[str, Any],
  ) -> Path:
    """완료된 결과 한 건을 체크포인트 파일에 **한 줄 덧붙인다**(JSONL).

    왜 append 인가 — 예전에는 질의가 하나 끝날 때마다 지금까지의 결과 **전체**를
    `json.dump(indent=2)` 로 다시 썼다. n 번째 질의에서 n 건을 쓰므로 총 쓰기량이
    O(n²) 로 늘어난다. 실측(2026-08-06): 전체 매트릭스 런 1회에 **9.14GB** 를 쓰는데
    최종 산출물은 124MB 였다(74배). 셀별로는 R4 3.3GB · NORMAL 2.7GB · R2 4셀 2.56GB.
    한 줄 append 로 바꾸면 총 쓰기량이 최종 파일 크기와 같아진다(O(n)).

    크래시 내성도 같이 좋아진다 — 예전 방식은 `open(mode="w")` 가 파일을 먼저 비우고
    쓰므로 그 순간 죽으면 **누적분 전체**를 잃었다. append 는 마지막 줄만 잘리고,
    `load_partial_results` 가 깨진 줄을 건너뛴다. 호출부(`cli/main.py`)가 결과를 먼저
    쓰고 체크포인트를 나중에 저장하므로, 잘린 줄에 해당하는 질의는 완료 목록에 없어
    다음 실행에서 그대로 재시도된다.

    Args:
      run_id: 실행 ID
      scenario: 시나리오명 (파일명 접두사로 대문자화된다)
      result: 직렬화가 끝난 결과 한 건

    Returns:
      Path: 결과가 덧붙여진 JSONL 파일 경로
    """
    self._ensure_run_dir(run_id)
    partial_path = self.partial_results_path(run_id, scenario)
    with open(partial_path, "a", encoding="utf-8") as file:
      file.write(json.dumps(result, ensure_ascii=False) + "\n")
    logger.debug("Appended partial result to {}", partial_path)
    return partial_path

  def load_partial_results(self, run_id: str, scenario: str) -> list[dict[str, Any]]:
    """이어하기용 부분 결과를 읽어온다(JSONL, 구형 `.json` 자동 호환).

    깨진 줄은 버리고 경고만 남긴다 — 크래시로 마지막 줄이 잘린 경우가 정상 경로라
    여기서 예외를 던지면 이어하기가 통째로 막힌다.
    """
    partial_path = self.partial_results_path(run_id, scenario)
    if partial_path.exists():
      results: list[dict[str, Any]] = []
      with open(partial_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
          line = line.strip()
          if not line:
            continue
          try:
            results.append(json.loads(line))
          except json.JSONDecodeError:
            logger.warning(
              "부분 결과의 손상된 줄을 건너뜁니다: {}:{} (해당 질의는 재시도됩니다)",
              partial_path,
              line_number,
            )
      return results

    # 구형 런(JSONL 이전)에서 이어하기/리플레이를 걸 수 있으므로 단일 JSON 도 읽는다.
    legacy_path = self._run_dir(run_id) / f"{scenario.upper()}_partial.json"
    if not legacy_path.exists():
      return []
    with open(legacy_path, "r", encoding="utf-8") as file:
      payload = json.load(file)
    return list(payload.get("results", []))

  def partial_results_path(self, run_id: str, scenario: str) -> Path:
    """Return the path of the partial result artifact."""
    return self._run_dir(run_id) / f"{scenario.upper()}_partial.jsonl"

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
    logger.debug("Saved partial failures to {}", failure_path)
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
    logger.debug("Saved suite manifest to {}", manifest_path)
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
    logger.debug("Saved suite checkpoint to {}", checkpoint_path)
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

  # 진단 대상 LLM. 설정에는 provider:auto 만 적혀 있을 수 있어서, 실행 시점에 실제로
  # 고른 provider/model 을 여기서 확정해 남긴다 — 이게 없으면 리포트가 "어떤 모델을
  # 진단했나"에 답하지 못하고 재현도 불가능해진다.
  from rag.generator.generator import describe_generator

  generator_identity = describe_generator(config)

  return {
    "code_version": _resolve_code_version(),
    "python_version": platform.python_version(),
    "platform": platform.platform(),
    "random_seed": config.get("experiment", {}).get("random_seed", ""),
    "embedding_model": config.get("embedding", {}).get("model_name", ""),
    "generator_provider": generator_identity["provider"],
    "generator_model": generator_identity["model"],
    "generator_configured": generator_identity["configured"],
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
