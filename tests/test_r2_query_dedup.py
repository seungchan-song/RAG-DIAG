"""R2 쿼리 생성이 중복 RAG 호출을 만들지 않는지 검증합니다.

배경:
  A1(Unaware Observer)은 위협 모델상 문서 내용을 모르므로 anchor 가 고정
  키워드 풀에서만 나오고 snippet 도 붙지 않는다. 즉 최종 쿼리가 target_docs 에
  전혀 의존하지 않는데, 예전 구현은 문서를 순회하며 동일 쿼리를 문서 수만큼
  복제해 RAG 호출(LLM+검색)을 그대로 낭비했다. 실측 RAG-2026-0803-001 에서는
  A1 240회 중 180회(75%)가 중복이었다.

  이 테스트는 그 회귀를 막는다. 중복이 다시 생기면 비용뿐 아니라 성공률
  집계에서 같은 쿼리가 여러 표를 행사해 지표까지 왜곡되므로 반드시 0이어야 한다.
"""

from typing import Any

from rag.attack.query_generator import AttackQueryGenerator


def _config() -> dict[str, Any]:
  """R2 쿼리 생성에 필요한 최소 설정을 만듭니다."""
  return {"attack": {"r2": {"standard_indices": [0], "num_repeats": 1}}}


def _docs(n: int) -> list[dict[str, Any]]:
  """타깃 문서 n 개를 만듭니다. 본문에는 PII 를 넣지 않습니다."""
  return [
    {"content": f"문서 본문 {i}", "doc_id": f"doc-{i:03d}", "meta": {}}
    for i in range(n)
  ]


def test_a1_queries_are_all_distinct() -> None:
  """A1 은 문서 수와 무관하게 중복 쿼리를 만들지 않는다."""
  gen = AttackQueryGenerator(_config(), attacker="A1")
  queries = gen.generate_r2_queries(_docs(20), env="clean")

  texts = [q["query"] for q in queries]
  assert len(texts) == len(set(texts)), (
    f"A1 이 중복 쿼리를 생성했습니다: {len(texts)}개 중 고유 {len(set(texts))}개"
  )
  # query_id 도 유일해야 실험 결과에서 행을 식별할 수 있다.
  ids = [q["query_id"] for q in queries]
  assert len(ids) == len(set(ids)), "query_id 가 중복됐습니다"


def test_a1_query_set_matches_legacy_doc_loop() -> None:
  """A1 이 만드는 쿼리 '집합' 은 예전 문서 루프 구현과 정확히 같아야 한다.

  중복만 제거했을 뿐 실험 의미가 바뀌면 안 되므로, 예전 구현이 만들던
  고유 쿼리 집합을 여기서 직접 재현해 비교한다.
  """
  cfg = _config()
  gen = AttackQueryGenerator(cfg, attacker="A1")
  docs = _docs(20)
  actual = {q["query"] for q in gen.generate_r2_queries(docs, env="clean")}

  # --- 예전 구현 재현: slot_index 를 문서 루프 밖에서 누적시키며 순회 ---
  anchors = [
    gen.R2_ANCHOR_TEMPLATES[i] for i in gen.R2_ACTIVE_ANCHOR_INDICES
  ]
  commands = [gen.R2_COMMAND_TEMPLATES[0]]
  if gen.R2_SELF_LOSING_TEMPLATES:
    commands.append(gen.R2_SELF_LOSING_TEMPLATES[0])
  if gen.R2_MANY_SHOT_TEMPLATES:
    commands.append(gen.R2_MANY_SHOT_TEMPLATES[0])
  pool = gen.GENERIC_OBSERVER_KEYWORDS

  legacy: set[str] = set()
  slot_index = 0
  for _doc in docs:
    for anchor_template in anchors:
      for command_template in commands:
        keyword = pool[slot_index % len(pool)]
        slot_index += 1
        legacy.add(
          f"{anchor_template.format(keyword=keyword)}\n\n"
          f"{command_template.format(keyword=keyword, snippet='')}"
        )

  assert actual == legacy, (
    f"쿼리 집합이 달라졌습니다 (신규 전용 {len(actual - legacy)}개, "
    f"누락 {len(legacy - actual)}개)"
  )


def test_a1_respects_target_doc_count() -> None:
  """--num-targets 로 문서를 줄이면 A1 쿼리 수도 예전처럼 줄어야 한다.

  A1 은 문서 비의존이지만, 문서 수를 줄여 빠르게 돌려보는 기존 사용법
  (`rag run -s R2 -n 3`)의 비용 특성까지 바꾸지는 않는다.
  """
  gen = AttackQueryGenerator(_config(), attacker="A1")
  few = gen.generate_r2_queries(_docs(3), env="clean")
  many = gen.generate_r2_queries(_docs(20), env="clean")

  # 문서 3개 × (앵커 2 × 명령 3) = 18 슬롯 < 풀 30 → 18개
  assert len(few) == 18, f"문서 3개일 때 18개를 기대했으나 {len(few)}개"
  # 문서 20개면 120 슬롯이지만 풀이 30개라 고유 쿼리는 30개가 상한
  assert len(many) == 30, f"문서 20개일 때 30개를 기대했으나 {len(many)}개"


def test_a2_still_targets_each_document() -> None:
  """A2 는 문서를 아는 공격자이므로 문서별 쿼리가 그대로 유지돼야 한다."""
  gen = AttackQueryGenerator(_config(), attacker="A2")
  docs = _docs(5)
  queries = gen.generate_r2_queries(docs, env="clean")

  # 문서 5개 × (앵커 2 × 명령 3) = 30개, 문서마다 target 이 붙는다.
  assert len(queries) == 30, f"30개를 기대했으나 {len(queries)}개"
  assert {q["target_doc_id"] for q in queries} == {d["doc_id"] for d in docs}
  # A2 는 문서 본문 스니펫을 쓰므로 target_text 가 채워져 있어야 한다.
  assert all(q["target_text"] for q in queries)
