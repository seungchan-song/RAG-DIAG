"""R4 비회원 반사실 어댑터 캐시의 스레드 안전성 회귀 테스트.

왜 이 파일이 있나 — CLI 는 `R4MembershipAttack` 인스턴스 **하나**를
`ThreadPoolExecutor(max_workers=5)` 위에서 공유한다(`cli/main.py:_process_query_task`).
그런데 `generate_queries` 는 문서당 b=1 쿼리를 전부 쌓고 이어서 b=0 쿼리를 쌓으므로,
같은 `target_doc_id` 의 b=0 쿼리들이 큐에서 나란히 워커로 들어간다.

락이 없던 시절 `_resolve_non_member_adapter` 는 조회와 저장 사이가 열려 있어서
동시 진입한 워커가 **전부 빈 캐시를 보고** `build_variant` 를 중복 실행했다
(2026-08-06 실측: 동시 5건 → 5회 전부 재구성, 캐시 적중 0). `build_variant` 는
문서 1,200개 재색인 + 파이프라인 재빌드라 비용이 크고, 그 순간 같은 크기의
DocumentStore 가 워커 수만큼 동시에 메모리에 뜬다.

여기서는 실제 `_resolve_non_member_adapter` 를 그대로 호출하고 `build_variant` 만
스텁으로 바꿔 호출 횟수를 센다. 지연(sleep)은 락이 없을 때의 경쟁 창을 재현하기
위한 것으로, 락이 있으면 지연과 무관하게 항상 1회여야 한다.
"""

from __future__ import annotations

import concurrent.futures
import threading
import time
from typing import Any

from rag.attack.r4_membership import R4MembershipAttack

# NER(KPF-BERT) 로드를 피해 테스트를 가볍게 유지한다. 이 테스트는 어댑터 캐시만 본다.
_NO_NER_CONFIG: dict[str, Any] = {
  "attack": {"r4": {"sensitive_use_ner": False}},
  "pii": {"runtime": {"enable_step3": False, "enable_step4": False}},
}


class _CountingTarget:
  """build_variant 호출 횟수를 세는 최소 스텁 어댑터."""

  def __init__(self, build_delay: float = 0.0) -> None:
    self.build_calls: list[frozenset[str]] = []
    self._lock = threading.Lock()
    self._build_delay = build_delay

  def build_variant(self, *, exclude_doc_ids: set[str]) -> "_CountingTarget":
    with self._lock:
      self.build_calls.append(frozenset(exclude_doc_ids))
    # 락이 없던 구현에서 경쟁 창을 벌리던 실제 비용(재색인)을 대신한다.
    time.sleep(self._build_delay)
    return _CountingTarget()


def _make_attack(target: _CountingTarget) -> R4MembershipAttack:
  return R4MembershipAttack(
    _NO_NER_CONFIG,
    attacker="A2",
    env="clean",
    probe_mode="sensitive",
    target=target,
  )


def test_same_doc_builds_variant_once_under_concurrency():
  """같은 target_doc_id 의 b=0 쿼리가 동시에 들어와도 재구성은 정확히 1회다."""
  target = _CountingTarget(build_delay=0.05)
  attack = _make_attack(target)
  queries = [{"target_doc_id": "doc-A"} for _ in range(5)]

  with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    adapters = list(
      executor.map(lambda q: attack._resolve_non_member_adapter(q, None), queries)
    )

  assert len(target.build_calls) == 1, (
    f"같은 문서에 build_variant 가 {len(target.build_calls)}회 실행됐다. "
    "_non_member_lock 이 빠졌거나 조회-저장 구간 밖으로 밀렸는지 확인할 것."
  )
  # 모든 호출자가 캐시된 동일 인스턴스를 받아야 한다 — 서로 다른 반사실 세계를
  # 쓰면 같은 문서의 b=0 응답들이 비교 불가능해진다.
  assert len({id(adapter) for adapter in adapters}) == 1
  assert set(attack._non_member_adapters) == {"doc-A"}


def test_distinct_docs_each_build_once():
  """문서가 다르면 각각 한 번씩 재구성된다(락이 캐시를 과도하게 막지 않는다)."""
  target = _CountingTarget(build_delay=0.02)
  attack = _make_attack(target)
  # 문서 4개 × 각 3건씩 동시 요청
  queries = [{"target_doc_id": f"doc-{i}"} for i in range(4) for _ in range(3)]

  with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    list(executor.map(lambda q: attack._resolve_non_member_adapter(q, None), queries))

  assert len(target.build_calls) == 4
  assert set(attack._non_member_adapters) == {"doc-0", "doc-1", "doc-2", "doc-3"}
  # 제외 대상이 요청한 문서와 정확히 일치해야 한다.
  assert {next(iter(call)) for call in target.build_calls} == {
    "doc-0",
    "doc-1",
    "doc-2",
    "doc-3",
  }


def test_cached_adapter_is_reused_across_sequential_calls():
  """순차 호출에서도 캐시가 그대로 동작한다(락 도입으로 기존 동작이 깨지지 않음)."""
  target = _CountingTarget()
  attack = _make_attack(target)

  first = attack._resolve_non_member_adapter({"target_doc_id": "doc-A"}, None)
  second = attack._resolve_non_member_adapter({"target_doc_id": "doc-A"}, None)

  assert first is second
  assert len(target.build_calls) == 1
