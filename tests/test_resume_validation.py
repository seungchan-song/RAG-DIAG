"""`rag run --resume` 컨텍스트 검증 회귀 테스트.

체크포인트의 scenario_scope 는 인덱스 매니페스트에서 복사되고, PersistentIndexManager 는
그 값을 항상 "all" 로 적는다(index/manager.py:57). 검증기가 "base"/시나리오명만 기대하면
정상적인 재개가 전부 거부된다 — 2026-08-11 에 실제로 suite resume 이 전 셀에서 죽었다.
"""

from __future__ import annotations

import pytest

from rag.cli.main import _validate_resume_request


def _checkpoint(**overrides: object) -> dict[str, object]:
  """clean 환경 NORMAL 셀의 정상 체크포인트를 만든다."""
  base = {
    "scenario": "NORMAL",
    "attacker": "A1",
    "environment_type": "clean",
    "profile_name": "reranker_on",
    "scenario_scope": "all",
  }
  base.update(overrides)
  return base


def _validate(checkpoint: dict[str, object], **overrides: str) -> None:
  """체크포인트와 같은 컨텍스트로 재개를 검증한다."""
  request = {
    "scenario": "NORMAL",
    "attacker": "A1",
    "env": "clean",
    "profile_name": "reranker_on",
  }
  request.update(overrides)
  _validate_resume_request(checkpoint=checkpoint, snapshot={}, **request)


def test_resume_accepts_all_scope_index() -> None:
  """매니페스트가 적는 'all' 스코프로 재개가 통과한다."""
  _validate(_checkpoint())


def test_resume_accepts_poisoned_all_scope() -> None:
  """poisoned/R9 도 'all' 인덱스로 재개할 수 있다."""
  checkpoint = _checkpoint(
    scenario="R9", attacker="A3", environment_type="poisoned", scenario_scope="all"
  )
  _validate(checkpoint, scenario="R9", attacker="A3", env="poisoned")


def test_resume_rejects_narrower_scope_mismatch() -> None:
  """좁게 빌드된 인덱스(R2)로 R9 를 재개하려 하면 거부한다."""
  checkpoint = _checkpoint(
    scenario="R9", attacker="A3", environment_type="poisoned", scenario_scope="R2"
  )
  with pytest.raises(ValueError, match="scenario_scope"):
    _validate(checkpoint, scenario="R9", attacker="A3", env="poisoned")


def test_resume_still_rejects_profile_mismatch() -> None:
  """기존에 잡던 불일치(profile)는 그대로 잡아야 한다."""
  with pytest.raises(ValueError, match="profile_name"):
    _validate(_checkpoint(), profile_name="reranker_off")
