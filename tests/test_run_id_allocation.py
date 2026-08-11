"""run_id 발급 회귀 테스트.

`create_run` 이 일련번호를 "기존 런 개수"로 세면, 중간 런을 하나 지운 뒤 살아 있는 런 ID 를
다시 발급해 그 디렉터리를 덮어쓴다. 2026-08-11 에 실제로 이 사고가 났다(데모 런
RAG-2026-0811-002 위에 suite 가 얹혀 전 셀이 실패). 여기서 고정한다.
"""

from __future__ import annotations

from rag.utils.experiment import ExperimentManager


def test_create_run_never_reuses_existing_id(tmp_path) -> None:
  """중간 번호가 비어 있어도 기존 런 ID 를 재발급하지 않는다."""
  manager = ExperimentManager({}, results_dir_override=tmp_path)

  first = manager.create_run()
  second = manager.create_run()
  assert first != second

  # 중간 런을 삭제한다(개수 기반 카운터라면 second 를 다시 발급한다).
  for path in tmp_path.iterdir():
    if path.name == first:
      for child in path.iterdir():
        child.unlink()
      path.rmdir()

  third = manager.create_run()
  assert third not in {first, second}


def test_create_run_counts_only_its_own_prefix(tmp_path) -> None:
  """prefix 가 다른 런(PII-EVAL)은 RAG 일련번호에 영향을 주지 않는다."""
  manager = ExperimentManager({}, results_dir_override=tmp_path)

  manager.create_run(prefix="PII-EVAL")
  manager.create_run(prefix="PII-EVAL")

  assert manager.create_run().endswith("-001")
