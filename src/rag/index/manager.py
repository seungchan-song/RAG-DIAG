"""Persistent index creation, loading, validation, and incremental sync."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any

from loguru import logger

from rag.index.store import MANIFEST_FILENAME, PersistentFaissDocumentStore
from rag.ingest.metadata import (
  build_doc_id_from_source,
  build_file_metadata_map,
  collect_dataset_selection,
  resolve_scenario_scope,
)
from rag.ingest.pipeline import run_ingest_files

INDEX_VERSION = "faiss-v2"
REUSE_VALIDATION_FIELDS = (
  "backend",
  "index_version",
  "environment_type",
  "scenario_scope",
  "dataset_scope",
  "dataset_selection_mode",
  "embedding_model",
  "profile_name",
)
INCREMENTAL_VALIDATION_FIELDS = (
  "backend",
  "index_version",
  "environment_type",
  "scenario_scope",
  "dataset_scope",
  "embedding_model",
  "profile_name",
)


class PersistentIndexManager:
  """Build, load, validate, and incrementally update one scoped FAISS index."""

  def __init__(
    self,
    config: dict[str, Any],
    *,
    doc_path: str,
    environment: str,
    scenario: str | None = None,
  ) -> None:
    if not environment:
      raise ValueError("An environment is required to resolve a persisted index")

    self.config = config
    self.doc_path = doc_path
    self.environment = str(environment).lower()
    self.scenario = scenario
    self.scenario_scope = resolve_scenario_scope(self.environment, scenario)
    if self.environment == "poisoned" and self.scenario_scope == "all":
      raise ValueError(
        "A scenario is required for poisoned indexes. "
        "Use one of: R2, R4, R9."
      )

    self.dataset_scope = f"{self.environment}/{self.scenario_scope}"
    self.profile_name = str(config.get("profile_name", "default"))
    self.index_config = config.get("index", {})
    self.index_root = Path(self.index_config.get("root_dir", "data/indexes"))
    if not self.index_root.is_absolute():
      project_root = Path(__file__).resolve().parents[3]
      self.index_root = project_root / self.index_root

    self.index_dir = self.index_root / self.environment / self.scenario_scope / self.profile_name
    self.manifest_path = self.index_dir / MANIFEST_FILENAME

  def ensure_index(
    self,
    *,
    rebuild: bool = False,
    auto_build_if_missing: bool | None = None,
    incremental: bool = False,
    sync_delete: bool = False,
  ) -> tuple[PersistentFaissDocumentStore, dict[str, Any], str]:
    """Load, build, rebuild, or incrementally update the scoped index."""
    if rebuild and incremental:
      raise ValueError("`--rebuild` and `--incremental` cannot be used together.")

    allow_auto_build = (
      self.index_config.get("auto_build_if_missing", True)
      if auto_build_if_missing is None
      else auto_build_if_missing
    )
    expected_state = self._collect_expected_state()
    expected_manifest = expected_state["manifest"]

    if rebuild:
      store, manifest = self.build_index(
        expected_state=expected_state,
        ingest_mode="rebuild",
      )
      return store, manifest, "rebuilt"

    if incremental:
      if self.manifest_path.exists():
        store, manifest, status = self.incremental_update(
          expected_state=expected_state,
          sync_delete=sync_delete,
        )
        return store, manifest, status

      if not allow_auto_build:
        raise FileNotFoundError(
          "No persisted index was found for "
          f"dataset_scope='{self.dataset_scope}' at {self.index_dir}"
        )

      store, manifest = self.build_index(
        expected_state=expected_state,
        ingest_mode="build",
      )
      return store, manifest, "built"

    if self.manifest_path.exists():
      existing_manifest = self.load_manifest()
      self._validate_manifest(existing_manifest, expected_manifest)
      store = PersistentFaissDocumentStore.load(self.index_dir)
      logger.info("Reusing persisted index from {}", self.index_dir)
      return store, existing_manifest, "reused"

    if not allow_auto_build:
      raise FileNotFoundError(
        "No persisted index was found for "
        f"dataset_scope='{self.dataset_scope}' at {self.index_dir}"
      )

    store, manifest = self.build_index(
      expected_state=expected_state,
      ingest_mode="build",
    )
    return store, manifest, "built"

  def build_index(
    self,
    *,
    expected_state: dict[str, Any] | None = None,
    ingest_mode: str = "build",
  ) -> tuple[PersistentFaissDocumentStore, dict[str, Any]]:
    """Build a new persisted index from the configured document path."""
    state = expected_state or self._collect_expected_state()
    if not state["selection"].file_paths:
      dataset_root = state["selection"].dataset_root
      raise ValueError(
        f"No supported document files (.pdf, .txt, .md) were found: {dataset_root}"
      )

    manifest = deepcopy(state["manifest"])
    manifest["created_at"] = datetime.now().isoformat()
    delta = self._build_delta_payload(
      added=sorted(state["file_hashes"]),
      updated=[],
      deleted=[],
      unchanged=[],
      retained_deleted=[],
    )

    store = PersistentFaissDocumentStore(self.index_dir, manifest=manifest, persist=True)
    store, _ = run_ingest_files(
      state["selection"].file_paths,
      self.config,
      metadata_map=state["metadata_map"],
      document_store=store,
    )
    final_manifest = self._finalize_manifest(
      store,
      manifest=manifest,
      previous_source_state={},
      touched_sources=set(state["file_hashes"]),
      actual_file_hashes=state["file_hashes"],
      delta=delta,
      ingest_mode=ingest_mode,
    )
    logger.info("Built persisted index at {}", self.index_dir)
    return store, final_manifest

  def incremental_update(
    self,
    *,
    expected_state: dict[str, Any],
    sync_delete: bool = False,
  ) -> tuple[PersistentFaissDocumentStore, dict[str, Any], str]:
    """Apply add/update delta to the existing index and optionally sync deletions."""
    existing_manifest = self.load_manifest()
    expected_manifest = expected_state["manifest"]
    self._validate_incremental_request(existing_manifest, expected_manifest)

    store = PersistentFaissDocumentStore.load(self.index_dir)
    delta = self._compute_delta(existing_manifest, expected_manifest)
    added_sources = list(delta["added"])
    updated_sources = list(delta["updated"])
    deleted_sources = list(delta["deleted"])

    updated_doc_ids = [
      expected_state["source_to_doc_id"][source]
      for source in updated_sources
      if source in expected_state["source_to_doc_id"]
    ]
    if updated_doc_ids:
      deleted_chunks = store.delete_documents_by_doc_ids(updated_doc_ids)
      logger.info(
        "Incremental ingest removed {} old chunks for updated sources",
        deleted_chunks,
      )

    if sync_delete and deleted_sources:
      deleted_doc_ids = [
        self._resolve_doc_id_for_source(source, existing_manifest)
        for source in deleted_sources
      ]
      deleted_doc_ids = [doc_id for doc_id in deleted_doc_ids if doc_id]
      if deleted_doc_ids:
        deleted_chunks = store.delete_documents_by_doc_ids(deleted_doc_ids)
        logger.info(
          "Incremental ingest removed {} chunks for deleted sources",
          deleted_chunks,
        )

    ingest_sources = sorted(set(added_sources + updated_sources))
    if ingest_sources:
      subset_paths = [
        expected_state["source_to_path"][source]
        for source in ingest_sources
      ]
      subset_metadata = {
        path: expected_state["metadata_map"][path]
        for path in subset_paths
      }
      store, _ = run_ingest_files(
        subset_paths,
        self.config,
        metadata_map=subset_metadata,
        document_store=store,
      )

    actual_file_hashes = self._resolve_actual_file_hashes(
      existing_manifest,
      expected_manifest,
      sync_delete=sync_delete,
    )
    retained_deleted = [] if sync_delete else deleted_sources
    delta_payload = self._build_delta_payload(
      added=added_sources,
      updated=updated_sources,
      deleted=deleted_sources,
      unchanged=list(delta["unchanged"]),
      retained_deleted=retained_deleted,
    )
    ingest_mode = "incremental_sync_delete" if sync_delete else "incremental_add_update"
    status = self._resolve_incremental_status(delta, sync_delete=sync_delete)

    final_manifest = self._finalize_manifest(
      store,
      manifest={
        **deepcopy(expected_manifest),
        "created_at": existing_manifest.get("created_at", datetime.now().isoformat()),
      },
      previous_source_state=existing_manifest.get("source_state", {}),
      touched_sources=set(ingest_sources),
      actual_file_hashes=actual_file_hashes,
      delta=delta_payload,
      ingest_mode=ingest_mode,
    )
    logger.info("Incremental ingest completed at {} ({})", self.index_dir, status)
    return store, final_manifest, status

  def load_manifest(self) -> dict[str, Any]:
    """Load the existing manifest from disk."""
    if not self.manifest_path.exists():
      raise FileNotFoundError(f"Index manifest not found: {self.manifest_path}")
    with open(self.manifest_path, "r", encoding="utf-8") as file:
      return json.load(file)

  def _collect_expected_state(self) -> dict[str, Any]:
    selection = collect_dataset_selection(
      self.doc_path,
      environment=self.environment,
      scenario=self.scenario_scope,
    )
    metadata_map = build_file_metadata_map(
      selection.file_paths,
      selection.dataset_root,
      environment=selection.environment_scope,
      scenario=selection.scenario_scope,
      dataset_selection_mode=selection.dataset_selection_mode,
    )
    file_hashes = {
      metadata["source"]: metadata["file_hash"]
      for metadata in metadata_map.values()
    }
    dataset_manifest_hash = hashlib.sha256(
      json.dumps(file_hashes, sort_keys=True).encode("utf-8")
    ).hexdigest()

    manifest = {
      "backend": self.index_config.get("backend", "faiss"),
      "index_version": INDEX_VERSION,
      "environment_type": self.environment,
      "scenario_scope": self.scenario_scope,
      "dataset_scope": self.dataset_scope,
      "dataset_group": self.environment,
      "dataset_root": str(selection.dataset_root),
      "dataset_selection_mode": selection.dataset_selection_mode,
      "doc_selection_summary": selection.doc_selection_summary,
      "embedding_model": self.config.get("embedding", {}).get("model_name", ""),
      "file_hashes": file_hashes,
      "dataset_manifest_hash": dataset_manifest_hash,
      "profile_name": self.profile_name,
    }

    source_to_doc_id = {
      metadata["source"]: metadata["doc_id"]
      for metadata in metadata_map.values()
    }
    source_to_path = {
      metadata["source"]: path
      for path, metadata in metadata_map.items()
    }
    return {
      "selection": selection,
      "metadata_map": metadata_map,
      "file_hashes": file_hashes,
      "source_to_doc_id": source_to_doc_id,
      "source_to_path": source_to_path,
      "manifest": manifest,
    }

  def _finalize_manifest(
    self,
    store: PersistentFaissDocumentStore,
    *,
    manifest: dict[str, Any],
    previous_source_state: dict[str, Any],
    touched_sources: set[str],
    actual_file_hashes: dict[str, str],
    delta: dict[str, Any],
    ingest_mode: str,
  ) -> dict[str, Any]:
    ingest_timestamp = datetime.now().isoformat()
    manifest_payload = deepcopy(manifest)
    manifest_payload["file_hashes"] = {
      source: actual_file_hashes[source]
      for source in sorted(actual_file_hashes)
    }
    manifest_payload["dataset_manifest_hash"] = hashlib.sha256(
      json.dumps(manifest_payload["file_hashes"], sort_keys=True).encode("utf-8")
    ).hexdigest()
    manifest_payload["source_state"] = self._build_source_state(
      store,
      previous_source_state=previous_source_state,
      touched_sources=touched_sources,
      ingest_timestamp=ingest_timestamp,
    )
    manifest_payload["last_ingest_delta"] = delta
    manifest_payload["last_ingest_mode"] = ingest_mode

    store.manifest.update(manifest_payload)
    store.save()
    return store.get_manifest()

  def _build_source_state(
    self,
    store: PersistentFaissDocumentStore,
    *,
    previous_source_state: dict[str, Any],
    touched_sources: set[str],
    ingest_timestamp: str,
  ) -> dict[str, dict[str, Any]]:
    source_state: dict[str, dict[str, Any]] = {}

    for document in store.filter_documents():
      source = str(document.meta.get("source") or "")
      if not source:
        continue

      entry = source_state.setdefault(
        source,
        {
          "doc_id": str(document.meta.get("doc_id") or document.id),
          "file_hash": str(document.meta.get("file_hash") or ""),
          "chunk_count": 0,
          "last_ingested_at": ingest_timestamp,
        },
      )
      entry["doc_id"] = str(document.meta.get("doc_id") or entry["doc_id"])
      entry["file_hash"] = str(document.meta.get("file_hash") or entry["file_hash"])
      entry["chunk_count"] += 1

    for source, entry in source_state.items():
      if source in touched_sources or source not in previous_source_state:
        entry["last_ingested_at"] = ingest_timestamp
      else:
        entry["last_ingested_at"] = str(
          previous_source_state.get(source, {}).get("last_ingested_at")
          or ingest_timestamp
        )

    return {
      source: source_state[source]
      for source in sorted(source_state)
    }

  def _validate_manifest(
    self,
    existing_manifest: dict[str, Any],
    expected_manifest: dict[str, Any],
  ) -> None:
    """Raise when the on-disk manifest does not match the current inputs."""
    if not self.index_config.get("require_manifest_match", True):
      return

    mismatches = self._collect_manifest_mismatches(
      existing_manifest,
      expected_manifest,
      fields=REUSE_VALIDATION_FIELDS,
      compare_file_hashes=True,
    )
    if mismatches:
      mismatch_list = ", ".join(mismatches)
      raise ValueError(
        "Persisted index manifest does not match the current configuration "
        f"for dataset_scope='{self.dataset_scope}': {mismatch_list}. "
        "Run `rag ingest --env ... --scenario ... --incremental` to apply changes "
        "or `rag ingest --env ... --scenario ... --rebuild` to rebuild the index."
      )

  def _validate_incremental_request(
    self,
    existing_manifest: dict[str, Any],
    expected_manifest: dict[str, Any],
  ) -> None:
    """Reject incremental sync when the index scope/config itself changed."""
    mismatches = self._collect_manifest_mismatches(
      existing_manifest,
      expected_manifest,
      fields=INCREMENTAL_VALIDATION_FIELDS,
      compare_file_hashes=False,
    )
    if mismatches:
      mismatch_list = ", ".join(mismatches)
      raise ValueError(
        "Incremental ingest cannot be applied because the persisted index scope "
        f"changed for dataset_scope='{self.dataset_scope}': {mismatch_list}. "
        "Run `rag ingest --env ... --scenario ... --rebuild` instead."
      )

  def _collect_manifest_mismatches(
    self,
    existing_manifest: dict[str, Any],
    expected_manifest: dict[str, Any],
    *,
    fields: tuple[str, ...],
    compare_file_hashes: bool,
  ) -> list[str]:
    mismatches: list[str] = []
    for field in fields:
      if existing_manifest.get(field) != expected_manifest.get(field):
        mismatches.append(field)
    if compare_file_hashes and (
      existing_manifest.get("file_hashes", {}) != expected_manifest.get("file_hashes", {})
    ):
      mismatches.append("file_hashes")
    return mismatches

  def _compute_delta(
    self,
    existing_manifest: dict[str, Any],
    expected_manifest: dict[str, Any],
  ) -> dict[str, list[str]]:
    existing_file_hashes = dict(existing_manifest.get("file_hashes", {}))
    expected_file_hashes = dict(expected_manifest.get("file_hashes", {}))

    existing_sources = set(existing_file_hashes)
    expected_sources = set(expected_file_hashes)
    shared_sources = existing_sources & expected_sources

    return {
      "added": sorted(expected_sources - existing_sources),
      "updated": sorted(
        source
        for source in shared_sources
        if existing_file_hashes.get(source) != expected_file_hashes.get(source)
      ),
      "deleted": sorted(existing_sources - expected_sources),
      "unchanged": sorted(
        source
        for source in shared_sources
        if existing_file_hashes.get(source) == expected_file_hashes.get(source)
      ),
    }

  def _build_delta_payload(
    self,
    *,
    added: list[str],
    updated: list[str],
    deleted: list[str],
    unchanged: list[str],
    retained_deleted: list[str],
  ) -> dict[str, Any]:
    return {
      "added": {"count": len(added), "sources": added},
      "updated": {"count": len(updated), "sources": updated},
      "deleted": {"count": len(deleted), "sources": deleted},
      "unchanged": {"count": len(unchanged), "sources": unchanged},
      "retained_deleted": {
        "count": len(retained_deleted),
        "sources": retained_deleted,
      },
    }

  def _resolve_actual_file_hashes(
    self,
    existing_manifest: dict[str, Any],
    expected_manifest: dict[str, Any],
    *,
    sync_delete: bool,
  ) -> dict[str, str]:
    if sync_delete:
      return dict(expected_manifest.get("file_hashes", {}))

    actual_file_hashes = dict(existing_manifest.get("file_hashes", {}))
    actual_file_hashes.update(expected_manifest.get("file_hashes", {}))
    return actual_file_hashes

  def _resolve_doc_id_for_source(
    self,
    source: str,
    manifest: dict[str, Any],
  ) -> str:
    source_state = manifest.get("source_state", {})
    if isinstance(source_state, dict):
      source_payload = source_state.get(source, {})
      if isinstance(source_payload, dict) and source_payload.get("doc_id"):
        return str(source_payload["doc_id"])
    return build_doc_id_from_source(source)

  def _resolve_incremental_status(
    self,
    delta: dict[str, list[str]],
    *,
    sync_delete: bool,
  ) -> str:
    has_add_update = bool(delta["added"] or delta["updated"])
    has_delete = bool(delta["deleted"])
    if not has_add_update and not has_delete:
      return "incremental_noop"
    if sync_delete and has_delete:
      return "incremental_synced"
    if has_add_update:
      return "incremental_updated"
    return "incremental_pending_delete"
