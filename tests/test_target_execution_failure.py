"""대상 RAG 호출 실패가 '공격 실패' 로 위장되지 않는지 검증합니다.

배경(2026-08-06 감사 U14-7):
  `BaseAttack._run_rag_query` 가 모든 예외를 삼키고 빈 트레이스를 돌려줬다.
  그 결과 대상 서버가 죽었거나 API 키가 틀렸을 때도 빈 응답 → `success=False`
  → 리포트에는 "공격 실패"로 찍혔다. 화면에서 방어가 막은 것과 구별되지 않는다.

  같은 구멍이 한 층 아래에도 있었다 — `generator/generator.py` 의 ClovaX·Local
  생성기는 HTTP 4xx/5xx 를 만나도 예외 대신 `replies=[""]` + `meta=[{"error": ...}]`
  를 돌려준다. 그래서 base.py 의 try/except 만 걷어내면 로컬 모델(대회 제출 경로)
  에서는 아무것도 달라지지 않는다. 두 경로를 함께 고정한다.

  이 프로젝트가 "방어 효과를 정량화한다"고 주장하는 이상, `is_blocked`(방어가 막음)와
  `TargetExecutionError`(부르지도 못함)는 절대 같은 칸에 들어가면 안 된다.
"""

from __future__ import annotations

from typing import Any

import pytest

from rag.adapters.base import Capability, RagTrace
from rag.attack.normal_baseline import NormalBaselineAttack

# `TargetExecutionError` 는 각 테스트 본문에서 import 한다 — 모듈 최상단에서 부르면
# 패치 이전 코드에서 파일 전체가 수집 에러로 끝나 정작 빨개져야 할 테스트가
# 실행되지 않는다(D10 에서 같은 함정을 밟았다).


class _DeadTarget:
  """대상 RAG 가 죽어 있는 상황(네트워크·인증 오류)."""

  capabilities = {Capability.QUERY}

  def query(self, query: str) -> RagTrace:
    raise ConnectionError("target unreachable")


class _GeneratorErrorTarget:
  """호출은 됐지만 생성기가 오류 메타를 실어 보낸 상황(HTTP 500 등)."""

  capabilities = {Capability.QUERY}

  def __init__(self, meta: list[dict[str, Any]]) -> None:
    self._meta = meta

  def query(self, query: str) -> RagTrace:
    return RagTrace(
      answer="",
      raw={"generator": {"replies": [""], "meta": self._meta}},
    )


def _attack(target: Any) -> NormalBaselineAttack:
  attack = NormalBaselineAttack({})
  attack.target = target
  return attack


def test_target_exception_propagates_instead_of_empty_trace() -> None:
  """대상 호출 예외를 삼키면 안 된다 — 삼키면 '공격 실패' 로 오집계된다."""
  with pytest.raises(ConnectionError):
    _attack(_DeadTarget())._run_rag_query(None, "질문")


def test_generator_error_meta_becomes_execution_failure() -> None:
  """생성기 오류 메타는 실행 실패로 승격된다(빈 응답으로 채점되지 않는다)."""
  from rag.attack.base import TargetExecutionError

  target = _GeneratorErrorTarget(
    [{"provider": "local", "model": "qwen2.5", "error": "HTTP 500"}]
  )

  with pytest.raises(TargetExecutionError) as excinfo:
    _attack(target)._run_rag_query(None, "질문")

  # 어느 대상이 왜 죽었는지 실패 기록만 보고 알 수 있어야 한다.
  message = str(excinfo.value)
  assert "local" in message and "qwen2.5" in message and "HTTP 500" in message


def test_empty_answer_without_error_meta_is_still_scored() -> None:
  """오류가 아닌 빈 응답은 그대로 채점된다 — 오탐으로 런을 죽이면 안 된다.

  모델이 정말로 거절해서 빈 문자열을 준 경우까지 실행 실패로 올리면
  '방어가 막았다' 를 통째로 잃는다.
  """
  target = _GeneratorErrorTarget([{"provider": "local", "model": "qwen2.5"}])

  trace = _attack(target)._run_rag_query(None, "질문")

  assert trace["generator"]["replies"] == [""]


def test_external_adapter_trace_without_meta_is_not_flagged() -> None:
  """외부 어댑터 트레이스(meta 비어 있음)는 이 검사에 걸리지 않는다."""

  class _ExternalTarget:
    capabilities = {Capability.QUERY}

    def query(self, query: str) -> RagTrace:
      return RagTrace(answer="정상 응답", metadata={"is_blocked": True})

  trace = _attack(_ExternalTarget())._run_rag_query(None, "질문")

  # 가드레일 차단은 예외가 아니라 target_metadata 로 전달돼야 한다(D2 원칙).
  assert trace["generator"]["replies"] == ["정상 응답"]
  assert trace["target_metadata"]["is_blocked"] is True


def test_scenario_execute_does_not_reswallow(monkeypatch) -> None:
  """시나리오 `execute()` 가 예외를 다시 삼키지 않아야 CLI 가 실패로 적재한다."""
  attack = _attack(_DeadTarget())

  with pytest.raises(ConnectionError):
    attack.execute({"query": "질문", "query_id": "q1"}, None)
