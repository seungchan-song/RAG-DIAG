"""
ingest 메타데이터 유틸리티 테스트
"""

from pathlib import Path

from rag.ingest.metadata import (
  build_file_metadata_map,
  collect_dataset_selection,
  collect_document_paths,
  infer_attack_type,
  infer_doc_role,
)


def test_collect_document_paths_legacy_clean_excludes_attack(tmp_path: Path):
  docs_dir = tmp_path / "documents"
  general_dir = docs_dir / "general"
  attack_dir = docs_dir / "attack"
  general_dir.mkdir(parents=True)
  attack_dir.mkdir(parents=True)

  (general_dir / "general_01.txt").write_text("일반 문서", encoding="utf-8")
  (attack_dir / "attack_r9_01.txt").write_text("공격 문서", encoding="utf-8")

  file_paths, dataset_root = collect_document_paths(str(docs_dir), environment="clean")

  assert dataset_root == docs_dir.resolve()
  assert len(file_paths) == 1
  assert "general_01.txt" in file_paths[0]


def test_collect_document_paths_prefers_env_directory(tmp_path: Path):
  docs_dir = tmp_path / "documents"
  clean_dir = docs_dir / "clean" / "normal"
  poisoned_dir = docs_dir / "poisoned" / "attack"
  clean_dir.mkdir(parents=True)
  poisoned_dir.mkdir(parents=True)

  (clean_dir / "normal_01.txt").write_text("정상 문서", encoding="utf-8")
  (poisoned_dir / "attack_r9_01.txt").write_text("오염 문서", encoding="utf-8")

  file_paths, dataset_root = collect_document_paths(str(docs_dir), environment="poisoned")

  assert dataset_root == (docs_dir / "poisoned").resolve()
  assert len(file_paths) == 1
  assert "attack_r9_01.txt" in file_paths[0]


def test_build_file_metadata_map_populates_required_fields(tmp_path: Path):
  docs_dir = tmp_path / "documents" / "clean" / "sensitive"
  docs_dir.mkdir(parents=True)
  file_path = docs_dir / "sensitive_01_customer.txt"
  file_path.write_text("홍길동 010-1234-5678", encoding="utf-8")

  metadata_map = build_file_metadata_map(
    [str(file_path.resolve())],
    (tmp_path / "documents" / "clean").resolve(),
    environment="clean",
  )
  metadata = metadata_map[str(file_path.resolve())]

  assert metadata["doc_id"].startswith("doc-")
  assert metadata["source"] == "sensitive/sensitive_01_customer.txt"
  assert metadata["dataset_group"] == "clean"
  assert metadata["environment_scope"] == "clean"
  assert metadata["scenario_scope"] == "base"
  assert metadata["dataset_scope"] == "clean/base"
  assert metadata["dataset_selection_mode"] == "canonical"
  assert metadata["doc_role"] == "sensitive"
  assert metadata["file_hash"].startswith("sha256:")


def test_doc_role_and_attack_type_inference(tmp_path: Path):
  file_path = tmp_path / "poisoned" / "attack" / "attack_r9_01.txt"
  file_path.parent.mkdir(parents=True)
  file_path.write_text("marker", encoding="utf-8")

  assert infer_doc_role(file_path) == "attack"
  assert infer_attack_type(file_path) == "R9"


def test_collect_dataset_selection_filters_canonical_poisoned_by_scenario(tmp_path: Path):
  docs_dir = tmp_path / "documents"
  normal_dir = docs_dir / "poisoned" / "normal"
  attack_r4_dir = docs_dir / "poisoned" / "attack" / "r4"
  attack_r9_dir = docs_dir / "poisoned" / "attack" / "r9"
  normal_dir.mkdir(parents=True)
  attack_r4_dir.mkdir(parents=True)
  attack_r9_dir.mkdir(parents=True)

  (normal_dir / "normal_01.txt").write_text("normal", encoding="utf-8")
  (attack_r4_dir / "attack_r4_01.txt").write_text("r4", encoding="utf-8")
  (attack_r9_dir / "attack_r9_01.txt").write_text("r9", encoding="utf-8")

  selection = collect_dataset_selection(
    str(docs_dir),
    environment="poisoned",
    scenario="R9",
  )

  assert selection.dataset_selection_mode == "canonical"
  assert selection.dataset_scope == "poisoned/R9"
  assert selection.doc_selection_summary["selected_file_count"] == 2
  assert any(path.endswith("normal_01.txt") for path in selection.file_paths)
  assert any(path.endswith("attack_r9_01.txt") for path in selection.file_paths)
  assert all("attack_r4_01.txt" not in path for path in selection.file_paths)


def test_collect_dataset_selection_filters_legacy_poisoned_by_scenario(tmp_path: Path):
  docs_dir = tmp_path / "documents"
  general_dir = docs_dir / "general"
  attack_dir = docs_dir / "attack"
  general_dir.mkdir(parents=True)
  attack_dir.mkdir(parents=True)

  (general_dir / "general_01.txt").write_text("normal", encoding="utf-8")
  (attack_dir / "attack_r4_01.txt").write_text("r4", encoding="utf-8")
  (attack_dir / "attack_r9_01.txt").write_text("r9", encoding="utf-8")

  selection = collect_dataset_selection(
    str(docs_dir),
    environment="poisoned",
    scenario="R9",
  )

  assert selection.dataset_selection_mode == "legacy"
  assert selection.dataset_scope == "poisoned/R9"
  assert selection.doc_selection_summary["selected_file_count"] == 2
  assert any(path.endswith("general_01.txt") for path in selection.file_paths)
  assert any(path.endswith("attack_r9_01.txt") for path in selection.file_paths)
  assert all("attack_r4_01.txt" not in path for path in selection.file_paths)
