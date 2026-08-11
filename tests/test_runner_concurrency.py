"""질의 실행 동시성 기본값 회귀 테스트.

로컬 생성기(Ollama)는 메모리가 빠듯하면 `-np 1` 로 떠 요청을 직렬화한다. 워커를 늘리면
처리량은 그대로인 채 큐 대기만 길어져 타임아웃이 나고, 그 타임아웃은 응답이 긴 질의를
골라 죽여 R2 성공률을 과소 측정한다(2026-08-11 RAG-2026-0811-003 실측 6.6%).
"""

from __future__ import annotations

import pytest


def resolve_max_workers(config: dict) -> int:
  """cli/main.py 의 max_workers 결정 규칙과 동일한 계산."""
  default_workers = 2 if config.get("generator", {}).get("provider") == "local" else 5
  return config.get("runner", {}).get("max_workers") or default_workers


@pytest.mark.parametrize(
  ("config", "expected"),
  [
    ({"generator": {"provider": "local"}}, 2),
    ({"generator": {"provider": "openai"}}, 5),
    ({}, 5),
    # null 로 비워 둬도 provider 기본값으로 떨어져야 한다(.get 의 default 는 안 먹는다).
    ({"generator": {"provider": "local"}, "runner": {"max_workers": None}}, 2),
    # 명시값은 언제나 이긴다(vLLM 등 슬롯이 넉넉한 서버).
    ({"generator": {"provider": "local"}, "runner": {"max_workers": 8}}, 8),
  ],
)
def test_max_workers_default(config: dict, expected: int) -> None:
  """provider 별 기본값과 override 우선순위를 고정한다."""
  assert resolve_max_workers(config) == expected
