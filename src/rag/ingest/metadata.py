"""Document selection and ingest metadata helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from haystack import component
from haystack.dataclasses import Document

from rag.utils.text import extract_keywords, slugify_token

SUPPORTED_EXTENSIONS = {".pdf", ".txt", ".md"}
VALID_ENVIRONMENTS = {"clean", "poisoned"}
VALID_SCENARIOS = {"R2", "R4", "R9"}


@dataclass(frozen=True)
class DatasetSelection:
  """One resolved dataset selection for ingest and index creation."""

  file_paths: list[str]
  dataset_root: Path
  environment_scope: str
  scenario_scope: str
  dataset_scope: str
  dataset_selection_mode: str
  doc_selection_summary: dict[str, Any]


def normalize_environment(environment: str | None, default: str = "clean") -> str:
  """Normalize and validate an environment name."""
  normalized = str(environment or default).lower()
  if normalized not in VALID_ENVIRONMENTS:
    raise ValueError(
      f"Unsupported environment: {environment}. "
      f"Available: {sorted(VALID_ENVIRONMENTS)}"
    )
  return normalized


def resolve_scenario_scope(
  environment: str,
  scenario: str | None = None,
) -> str:
  """Resolve the dataset scenario scope for one environment."""
  environment_scope = normalize_environment(environment)
  if environment_scope == "clean":
    return "base"

  if not scenario:
    return "all"

  scenario_scope = str(scenario).upper()
  if scenario_scope == "ALL":
    return "all"
  if scenario_scope not in VALID_SCENARIOS:
    raise ValueError(
      f"Unsupported scenario: {scenario}. "
      f"Available: {sorted(VALID_SCENARIOS)}"
    )
  return scenario_scope


def build_dataset_scope(
  environment: str,
  scenario: str | None = None,
) -> str:
  """Build the environment/scenario scope label used in manifests and results."""
  environment_scope = normalize_environment(environment)
  return f"{environment_scope}/{resolve_scenario_scope(environment_scope, scenario)}"


def resolve_dataset_path(
  doc_dir: Path,
  environment: str | None = None,
) -> tuple[Path, bool]:
  """Resolve the canonical env directory when present, else fall back to legacy."""
  if environment is None:
    return doc_dir, False

  env_name = normalize_environment(environment)
  if doc_dir.name.lower() == env_name:
    return doc_dir, False

  env_dir = doc_dir / env_name
  if env_dir.exists():
    return env_dir, False

  return doc_dir, True


def collect_dataset_selection(
  doc_path: str,
  environment: str | None = None,
  scenario: str | None = None,
) -> DatasetSelection:
  """Resolve the exact file set for one environment/scenario scope."""
  doc_dir = Path(doc_path)
  if not doc_dir.exists():
    raise FileNotFoundError(f"Document directory was not found: {doc_dir}")

  environment_scope = normalize_environment(environment)
  scenario_scope = resolve_scenario_scope(environment_scope, scenario)
  dataset_scope = build_dataset_scope(environment_scope, scenario_scope)
  dataset_root, use_legacy_filter = resolve_dataset_path(doc_dir, environment_scope)
  dataset_selection_mode = "legacy" if use_legacy_filter else "canonical"

  file_paths: list[str] = []
  role_counts = {"normal": 0, "sensitive": 0, "attack": 0}
  attack_type_counts: dict[str, int] = {}

  for file_path in sorted(dataset_root.rglob("*")):
    if not file_path.is_file() or file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
      continue

    doc_role = infer_doc_role(file_path)
    attack_type = infer_attack_type(file_path)
    if not _should_include_document(
      environment_scope=environment_scope,
      scenario_scope=scenario_scope,
      doc_role=doc_role,
      attack_type=attack_type,
    ):
      continue

    file_paths.append(str(file_path.resolve()))
    role_counts[doc_role] = role_counts.get(doc_role, 0) + 1
    if attack_type:
      attack_type_counts[attack_type] = attack_type_counts.get(attack_type, 0) + 1

  return DatasetSelection(
    file_paths=file_paths,
    dataset_root=dataset_root.resolve(),
    environment_scope=environment_scope,
    scenario_scope=scenario_scope,
    dataset_scope=dataset_scope,
    dataset_selection_mode=dataset_selection_mode,
    doc_selection_summary={
      "selected_file_count": len(file_paths),
      "normal_count": role_counts.get("normal", 0),
      "sensitive_count": role_counts.get("sensitive", 0),
      "attack_count": role_counts.get("attack", 0),
      "by_doc_role": role_counts,
      "by_attack_type": attack_type_counts,
    },
  )


def collect_document_paths(
  doc_path: str,
  environment: str | None = None,
  scenario: str | None = None,
) -> tuple[list[str], Path]:
  """Compatibility wrapper that returns only file paths and dataset root."""
  selection = collect_dataset_selection(
    doc_path,
    environment=environment,
    scenario=scenario,
  )
  return selection.file_paths, selection.dataset_root


def infer_doc_role(file_path: Path) -> str:
  """Infer a document role from the path shape."""
  path_parts = {part.lower() for part in file_path.parts}
  stem = file_path.stem.lower()

  if "attack" in path_parts or stem.startswith("attack_"):
    return "attack"
  if "sensitive" in path_parts or stem.startswith("sensitive_"):
    return "sensitive"
  if "normal" in path_parts or "general" in path_parts or stem.startswith("general_"):
    return "normal"
  return "normal"


def infer_dataset_group(file_path: Path, environment: str | None = None) -> str:
  """Infer clean vs poisoned grouping for one file."""
  if environment:
    return normalize_environment(environment)

  lowered_parts = {part.lower() for part in file_path.parts}
  if "poisoned" in lowered_parts:
    return "poisoned"
  if "clean" in lowered_parts:
    return "clean"
  if infer_doc_role(file_path) == "attack":
    return "poisoned"
  return "clean"


def infer_attack_type(file_path: Path) -> str | None:
  """Infer the attack scenario code from a file path."""
  lowered = str(file_path).lower()
  match = re.search(r"(r[249])", lowered)
  if match:
    return match.group(1).upper()
  return None


def _should_include_document(
  *,
  environment_scope: str,
  scenario_scope: str,
  doc_role: str,
  attack_type: str | None,
) -> bool:
  """Return whether one document belongs to the requested dataset scope."""
  if environment_scope == "clean":
    return doc_role != "attack"

  if doc_role != "attack":
    return True

  if scenario_scope == "all":
    return True

  return attack_type == scenario_scope


def build_file_metadata_map(
  file_paths: list[str],
  dataset_root: Path,
  environment: str | None = None,
  scenario: str | None = None,
  dataset_selection_mode: str | None = None,
) -> dict[str, dict[str, Any]]:
  """Build the required ingest metadata for each selected file."""
  metadata_map: dict[str, dict[str, Any]] = {}
  environment_scope = normalize_environment(environment)
  scenario_scope = resolve_scenario_scope(environment_scope, scenario)
  dataset_scope = build_dataset_scope(environment_scope, scenario_scope)
  selection_mode = dataset_selection_mode or _infer_selection_mode(
    dataset_root,
    environment_scope=environment_scope,
  )

  for raw_path in file_paths:
    file_path = Path(raw_path).resolve()
    relative_source = file_path.relative_to(dataset_root).as_posix()
    file_hash = hashlib.sha256(file_path.read_bytes()).hexdigest()
    doc_role = infer_doc_role(file_path)
    attack_type = infer_attack_type(file_path)

    metadata_map[str(file_path)] = {
      "doc_id": build_doc_id_from_source(relative_source),
      "source": relative_source,
      "version": "v1.0",
      "file_hash": f"sha256:{file_hash}",
      "dataset_group": infer_dataset_group(file_path, environment_scope),
      "environment_scope": environment_scope,
      "scenario_scope": scenario_scope,
      "dataset_scope": dataset_scope,
      "dataset_selection_mode": selection_mode,
      "doc_role": doc_role,
      "attack_type": attack_type,
      "file_path": str(file_path),
    }

  return metadata_map


def build_doc_id_from_source(relative_source: str) -> str:
  """Build the stable file-level doc_id from one dataset-relative source path."""
  source_slug = slugify_token(relative_source.replace("/", "-"))
  source_hash = hashlib.sha1(relative_source.encode("utf-8")).hexdigest()[:10]
  return f"doc-{source_slug}-{source_hash}"


def _infer_selection_mode(dataset_root: Path, environment_scope: str) -> str:
  """Infer canonical vs legacy mode from the resolved dataset root."""
  return "canonical" if dataset_root.name.lower() == environment_scope else "legacy"


def get_primary_keyword(text: str, fallback: str = "문서") -> str:
  """Return the highest-priority keyword for query generation."""
  keywords = extract_keywords(text, max_keywords=3)
  return keywords[0] if keywords else fallback


def _resolve_file_key(meta: dict[str, Any]) -> str | None:
  for key in ("file_path", "source_id", "source", "path"):
    value = meta.get(key)
    if value:
      return str(Path(value).resolve())
  return None


@component
class DocumentMetadataEnricher:
  """Inject file-level metadata into converted documents."""

  def __init__(self, metadata_map: dict[str, dict[str, Any]]) -> None:
    self.metadata_map = metadata_map
    # Haystack 컨버터(TextFileToDocument 등)가 meta["file_path"]에 파일명(basename)만
    # 저장하는 경우가 있으므로, 보조 인덱스로 basename → metadata를 추가로 유지합니다.
    self._basename_map: dict[str, dict[str, Any]] = {
      Path(k).name: v for k, v in metadata_map.items()
    }

  @component.output_types(documents=list[Document])
  def run(self, documents: list[Document]) -> dict[str, list[Document]]:
    for document in documents:
      document.meta = document.meta or {}
      file_key = _resolve_file_key(document.meta)
      base_meta = self.metadata_map.get(file_key or "", {})

      # 전체 경로로 찾지 못한 경우 basename으로 재시도합니다.
      # (Haystack 컨버터가 절대 경로 대신 파일명만 meta에 저장할 때 발생)
      if not base_meta and file_key:
        base_meta = self._basename_map.get(Path(file_key).name, {})

      document.meta.update(base_meta)

      keywords = extract_keywords(document.content or "", max_keywords=3)
      if keywords:
        document.meta["keywords"] = keywords
        document.meta["keyword"] = keywords[0]
      else:
        document.meta.setdefault("keywords", [])
        document.meta.setdefault("keyword", get_primary_keyword("", fallback="문서"))

    return {"documents": documents}


@component
class ChunkMetadataEnricher:
  """Enforce chunk-level metadata after splitting."""

  @component.output_types(documents=list[Document])
  def run(self, documents: list[Document]) -> dict[str, list[Document]]:
    chunk_indices: dict[str, int] = {}

    for document in documents:
      document.meta = document.meta or {}
      doc_id = document.meta.get("doc_id", "doc-unknown")
      chunk_index = chunk_indices.get(doc_id, 0)
      chunk_indices[doc_id] = chunk_index + 1

      document.meta.setdefault("keyword", get_primary_keyword(document.content or ""))
      document.meta.setdefault(
        "keywords",
        extract_keywords(document.content or "", max_keywords=3),
      )
      document.meta["chunk_index"] = chunk_index
      document.meta["chunk_id"] = f"{doc_id}::chunk-{chunk_index:04d}"
      document.meta.setdefault("source", "unknown")
      document.meta.setdefault("version", "v1.0")
      document.meta.setdefault("doc_role", "normal")
      document.meta.setdefault("dataset_group", "clean")
      document.meta.setdefault("environment_scope", "clean")
      document.meta.setdefault("scenario_scope", "base")
      document.meta.setdefault("dataset_scope", "clean/base")
      document.meta.setdefault("dataset_selection_mode", "legacy")
      document.meta.setdefault("file_hash", "sha256:unknown")

    return {"documents": documents}
