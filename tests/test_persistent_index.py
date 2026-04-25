"""Tests for persistent FAISS indexing and checkpoint helpers."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from haystack import Document

from rag.index.manager import PersistentIndexManager
from rag.index.store import PersistentFaissDocumentStore


def _base_config(tmp_path: Path) -> dict:
  return {
    "embedding": {"model_name": "test-embedding-model", "device": "cpu"},
    "index": {
      "backend": "faiss",
      "root_dir": str(tmp_path / "indexes"),
      "auto_build_if_missing": True,
      "require_manifest_match": True,
    },
    "retriever": {"top_k": 5, "similarity_threshold": 0.0},
    "report": {"output_dir": str(tmp_path / "results")},
  }


def test_persistent_faiss_store_saves_and_loads_documents(tmp_path: Path):
  store = PersistentFaissDocumentStore(
    tmp_path / "indexes" / "clean",
    manifest={
      "backend": "faiss",
      "index_version": "faiss-v1",
      "environment_type": "clean",
    },
  )
  documents = [
    Document(
      id="doc-1",
      content="alpha",
      embedding=[1.0, 0.0],
      meta={"doc_id": "doc-1", "chunk_id": "doc-1::chunk-0000"},
    ),
    Document(
      id="doc-2",
      content="beta",
      embedding=[0.0, 1.0],
      meta={"doc_id": "doc-2", "chunk_id": "doc-2::chunk-0000"},
    ),
  ]

  written = store.write_documents(documents)
  loaded = PersistentFaissDocumentStore.load(tmp_path / "indexes" / "clean")
  results = loaded.query_by_embedding([1.0, 0.0], top_k=1)

  assert written == 2
  assert loaded.count_documents() == 2
  assert results[0].id == "doc-1"
  assert (tmp_path / "indexes" / "clean" / "manifest.json").exists()


def test_persistent_faiss_store_deletes_documents_by_doc_id(tmp_path: Path):
  store = PersistentFaissDocumentStore(
    tmp_path / "indexes" / "clean",
    manifest={"backend": "faiss", "index_version": "faiss-v2"},
  )
  store.write_documents(
    [
      Document(
        id="doc-1::chunk-0000",
        content="alpha",
        embedding=[1.0, 0.0],
        meta={"doc_id": "doc-1", "chunk_id": "doc-1::chunk-0000"},
      ),
      Document(
        id="doc-1::chunk-0001",
        content="alpha-2",
        embedding=[0.9, 0.1],
        meta={"doc_id": "doc-1", "chunk_id": "doc-1::chunk-0001"},
      ),
      Document(
        id="doc-2::chunk-0000",
        content="beta",
        embedding=[0.0, 1.0],
        meta={"doc_id": "doc-2", "chunk_id": "doc-2::chunk-0000"},
      ),
    ]
  )

  deleted = store.delete_documents_by_doc_ids(["doc-1"])
  loaded = PersistentFaissDocumentStore.load(tmp_path / "indexes" / "clean")

  assert deleted == 2
  assert loaded.count_documents() == 1
  assert loaded.filter_documents()[0].meta["doc_id"] == "doc-2"


def test_index_manager_builds_and_reuses_matching_index(tmp_path: Path, monkeypatch):
  docs_root = tmp_path / "documents"
  clean_dir = docs_root / "clean" / "normal"
  clean_dir.mkdir(parents=True)
  (clean_dir / "doc1.txt").write_text("alpha document", encoding="utf-8")

  def fake_run_ingest_files(file_paths, config, *, metadata_map, document_store=None):
    document_store.write_documents(
      [
        Document(
          id="doc-1",
          content="alpha document",
          embedding=[1.0, 0.0],
          meta={
            "doc_id": "doc-1",
            "chunk_id": "doc-1::chunk-0000",
            "keyword": "alpha",
            "doc_role": "normal",
          },
        )
      ]
    )
    return document_store, 1

  monkeypatch.setattr("rag.index.manager.run_ingest_files", fake_run_ingest_files)

  manager = PersistentIndexManager(
    _base_config(tmp_path),
    doc_path=str(docs_root),
    environment="clean",
  )

  _, built_manifest, built_status = manager.ensure_index()
  _, reused_manifest, reused_status = manager.ensure_index()

  assert built_status == "built"
  assert reused_status == "reused"
  assert built_manifest["embedding_model"] == "test-embedding-model"
  assert built_manifest["dataset_scope"] == "clean/base"
  assert reused_manifest["doc_count"] == 1


def test_index_manager_raises_on_manifest_mismatch(tmp_path: Path, monkeypatch):
  docs_root = tmp_path / "documents"
  clean_dir = docs_root / "clean" / "normal"
  clean_dir.mkdir(parents=True)
  source_file = clean_dir / "doc1.txt"
  source_file.write_text("alpha document", encoding="utf-8")

  def fake_run_ingest_files(file_paths, config, *, metadata_map, document_store=None):
    document_store.write_documents(
      [
        Document(
          id="doc-1",
          content="alpha document",
          embedding=[1.0, 0.0],
          meta={
            "doc_id": "doc-1",
            "chunk_id": "doc-1::chunk-0000",
            "keyword": "alpha",
            "doc_role": "normal",
          },
        )
      ]
    )
    return document_store, 1

  monkeypatch.setattr("rag.index.manager.run_ingest_files", fake_run_ingest_files)

  manager = PersistentIndexManager(
    _base_config(tmp_path),
    doc_path=str(docs_root),
    environment="clean",
  )
  manager.ensure_index()

  source_file.write_text("alpha document updated", encoding="utf-8")

  try:
    manager.ensure_index()
  except ValueError as error:
    assert "file_hashes" in str(error)
  else:
    raise AssertionError("Expected a manifest mismatch error")


def test_index_manager_uses_scenario_scoped_paths_for_clean_and_poisoned(tmp_path: Path):
  config = _base_config(tmp_path)

  clean_manager = PersistentIndexManager(
    config,
    doc_path=str(tmp_path / "documents"),
    environment="clean",
  )
  poisoned_manager = PersistentIndexManager(
    config,
    doc_path=str(tmp_path / "documents"),
    environment="poisoned",
    scenario="R9",
  )

  assert clean_manager.index_dir == tmp_path / "indexes" / "clean" / "base" / "default"
  assert poisoned_manager.index_dir == (
    tmp_path / "indexes" / "poisoned" / "R9" / "default"
  )


def test_index_manager_detects_scenario_scope_mismatch(tmp_path: Path, monkeypatch):
  docs_root = tmp_path / "documents"
  poisoned_normal = docs_root / "poisoned" / "normal"
  poisoned_attack_r9 = docs_root / "poisoned" / "attack" / "r9"
  poisoned_normal.mkdir(parents=True)
  poisoned_attack_r9.mkdir(parents=True)
  (poisoned_normal / "normal_01.txt").write_text("alpha document", encoding="utf-8")
  (poisoned_attack_r9 / "attack_r9_01.txt").write_text("marker", encoding="utf-8")

  def fake_run_ingest_files(file_paths, config, *, metadata_map, document_store=None):
    file_path = Path(file_paths[0]).resolve()
    meta = dict(metadata_map[str(file_path)])
    document_store.write_documents(
      [
        Document(
          id=f"{meta['doc_id']}::chunk-0000",
          content=file_path.read_text(encoding="utf-8"),
          embedding=[1.0, 0.0],
          meta={
            **meta,
            "chunk_id": f"{meta['doc_id']}::chunk-0000",
            "keyword": "alpha",
          },
        )
      ]
    )
    return document_store, 1

  monkeypatch.setattr("rag.index.manager.run_ingest_files", fake_run_ingest_files)

  r9_manager = PersistentIndexManager(
    _base_config(tmp_path),
    doc_path=str(docs_root),
    environment="poisoned",
    scenario="R9",
  )
  r9_manager.ensure_index()

  r4_manager = PersistentIndexManager(
    _base_config(tmp_path),
    doc_path=str(docs_root),
    environment="poisoned",
    scenario="R4",
  )

  try:
    r4_manager._validate_manifest(
      r9_manager.load_manifest(),
      r4_manager._collect_expected_state()["manifest"],
    )
  except ValueError as error:
    assert "scenario_scope" in str(error)
  else:
    raise AssertionError("Expected a scenario_scope mismatch error")


def test_index_manager_incremental_adds_and_replaces_changed_sources(tmp_path: Path, monkeypatch):
  docs_root = tmp_path / "documents"
  clean_dir = docs_root / "clean" / "normal"
  clean_dir.mkdir(parents=True)
  first_file = clean_dir / "doc1.txt"
  second_file = clean_dir / "doc2.txt"
  first_file.write_text("alpha document", encoding="utf-8")

  def fake_run_ingest_files(file_paths, config, *, metadata_map, document_store=None):
    documents: list[Document] = []
    for index, file_path in enumerate(sorted(file_paths), start=1):
      path = Path(file_path)
      meta = dict(metadata_map[str(path.resolve())])
      doc_id = meta["doc_id"]
      documents.append(
        Document(
          id=f"{doc_id}::chunk-0000",
          content=path.read_text(encoding="utf-8"),
          embedding=[float(index), 0.0],
          meta={
            **meta,
            "chunk_id": f"{doc_id}::chunk-0000",
            "keyword": path.stem,
          },
        )
      )
    document_store.write_documents(documents)
    return document_store, len(documents)

  monkeypatch.setattr("rag.index.manager.run_ingest_files", fake_run_ingest_files)

  manager = PersistentIndexManager(
    _base_config(tmp_path),
    doc_path=str(docs_root),
    environment="clean",
  )
  manager.ensure_index()

  first_file.write_text("alpha document updated", encoding="utf-8")
  second_file.write_text("beta document", encoding="utf-8")

  store, manifest, status = manager.ensure_index(incremental=True)
  documents = sorted(store.filter_documents(), key=lambda item: item.meta["source"])
  source_state = manifest["source_state"]

  assert status == "incremental_updated"
  assert manifest["last_ingest_mode"] == "incremental_add_update"
  assert manifest["last_ingest_delta"]["added"]["count"] == 1
  assert manifest["last_ingest_delta"]["updated"]["count"] == 1
  assert manifest["last_ingest_delta"]["deleted"]["count"] == 0
  assert [doc.meta["source"] for doc in documents] == ["normal/doc1.txt", "normal/doc2.txt"]
  assert documents[0].content == "alpha document updated"
  assert source_state["normal/doc1.txt"]["chunk_count"] == 1
  assert source_state["normal/doc2.txt"]["chunk_count"] == 1
  datetime.fromisoformat(source_state["normal/doc1.txt"]["last_ingested_at"])


def test_index_manager_incremental_sync_delete_removes_missing_sources(tmp_path: Path, monkeypatch):
  docs_root = tmp_path / "documents"
  clean_dir = docs_root / "clean" / "normal"
  clean_dir.mkdir(parents=True)
  first_file = clean_dir / "doc1.txt"
  second_file = clean_dir / "doc2.txt"
  first_file.write_text("alpha document", encoding="utf-8")
  second_file.write_text("beta document", encoding="utf-8")

  def fake_run_ingest_files(file_paths, config, *, metadata_map, document_store=None):
    documents: list[Document] = []
    for index, file_path in enumerate(sorted(file_paths), start=1):
      path = Path(file_path)
      meta = dict(metadata_map[str(path.resolve())])
      doc_id = meta["doc_id"]
      documents.append(
        Document(
          id=f"{doc_id}::chunk-0000",
          content=path.read_text(encoding="utf-8"),
          embedding=[float(index), 0.0],
          meta={
            **meta,
            "chunk_id": f"{doc_id}::chunk-0000",
            "keyword": path.stem,
          },
        )
      )
    document_store.write_documents(documents)
    return document_store, len(documents)

  monkeypatch.setattr("rag.index.manager.run_ingest_files", fake_run_ingest_files)

  manager = PersistentIndexManager(
    _base_config(tmp_path),
    doc_path=str(docs_root),
    environment="clean",
  )
  manager.ensure_index()

  second_file.unlink()

  retained_store, retained_manifest, retained_status = manager.ensure_index(incremental=True)
  assert retained_status == "incremental_pending_delete"
  assert retained_store.count_documents() == 2
  assert retained_manifest["last_ingest_delta"]["deleted"]["count"] == 1
  assert retained_manifest["last_ingest_delta"]["retained_deleted"]["count"] == 1
  assert "normal/doc2.txt" in retained_manifest["file_hashes"]

  synced_store, synced_manifest, synced_status = manager.ensure_index(
    incremental=True,
    sync_delete=True,
  )
  synced_sources = [doc.meta["source"] for doc in synced_store.filter_documents()]

  assert synced_status == "incremental_synced"
  assert synced_manifest["last_ingest_mode"] == "incremental_sync_delete"
  assert synced_manifest["last_ingest_delta"]["deleted"]["count"] == 1
  assert synced_manifest["last_ingest_delta"]["retained_deleted"]["count"] == 0
  assert "normal/doc2.txt" not in synced_manifest["file_hashes"]
  assert synced_sources == ["normal/doc1.txt"]
