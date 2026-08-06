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


def _command_pool(gen: AttackQueryGenerator) -> list[str]:
  """standard_indices=[0] 설정에서 production 이 쓰는 명령 슬롯 목록.

  슬롯 구성이 바뀌면(예: 변형 출력 유도 5종 추가) 기대 쿼리 수도 함께 변하므로,
  개수를 상수로 박지 않고 클래스 상수에서 매번 유도한다. 이 테스트가 지키려는
  것은 슬롯 개수가 아니라 **A1 이 문서를 순회하지 않는다**는 성질이다.
  """
  commands = [gen.R2_COMMAND_TEMPLATES[0]]
  if gen.R2_SELF_LOSING_TEMPLATES:
    commands.append(gen.R2_SELF_LOSING_TEMPLATES[0])
  if gen.R2_MANY_SHOT_TEMPLATES:
    commands.append(gen.R2_MANY_SHOT_TEMPLATES[0])
  commands.extend(template for _kind, template in gen.R2_EVASION_TEMPLATES)
  return commands


def _stride(gen: AttackQueryGenerator) -> int:
  """문서 한 개가 소비하는 슬롯 수 (활성 앵커 수 × 명령 슬롯 수)."""
  return len(gen.R2_ACTIVE_ANCHOR_INDICES) * len(_command_pool(gen))


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


def test_a1_queries_are_subset_of_doc_loop_and_cover_all_commands() -> None:
  """A1 쿼리는 예전 문서 루프가 만들던 조합의 부분집합이고, 명령 슬롯을 다 덮는다.

  D6(중복 제거) 시점에는 두 집합이 **바이트 단위로 같았다**. 그때는 보폭(6)과
  키워드 풀(30)의 배수 관계 덕분에 문서 루프가 만들 수 있는 고유 조합이 정확히
  30개였기 때문이다. 이후 명령 슬롯이 늘어(변형 출력 유도 5종) 문서 루프가
  만들 수 있는 조합은 훨씬 많아졌지만, A1 은 여전히 **키워드 풀 크기만큼만**
  돌린다 — 문서 비의존 공격자에게 그 이상은 낭비다.

  그래서 지키는 성질을 두 개로 바꾼다.
    1. 새로 생긴 쿼리가 없다(부분집합) — 없던 공격을 몰래 만들지 않는다.
    2. 모든 명령 슬롯이 최소 한 번은 실행된다 — 특정 페이로드가 통째로
       누락되면 그 기법의 위험도가 0으로 찍힌다.
  """
  cfg = _config()
  gen = AttackQueryGenerator(cfg, attacker="A1")
  docs = _docs(20)
  produced = gen.generate_r2_queries(docs, env="clean")
  actual = {q["query"] for q in produced}

  # --- 예전 구현 재현: slot_index 를 문서 루프 밖에서 누적시키며 순회 ---
  anchors = [
    gen.R2_ANCHOR_TEMPLATES[i] for i in gen.R2_ACTIVE_ANCHOR_INDICES
  ]
  commands = _command_pool(gen)
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

  assert actual <= legacy, (
    f"문서 루프가 만들지 않던 쿼리가 새로 생겼습니다: {len(actual - legacy)}개"
  )
  # 페이로드 종류가 전부 최소 1회는 실행돼야 한다. (self_losing·many_shot 은
  # 템플릿에 {keyword}/{snippet} 이 들어가 원문과 문자열이 달라지므로 템플릿을
  # 직접 비교하지 않고 종류로 본다.)
  assert {q["payload_type"] for q in produced} == {
    "standard", "self_losing", "many_shot", "evasion",
  }
  # 변형 출력 유도는 5종이 전부 나가야 STEP 0 를 종류별로 측정할 수 있다.
  kinds = {q["evasion_kind"] for q in produced if q["payload_type"] == "evasion"}
  assert len(kinds) == len(gen.R2_EVASION_TEMPLATES), (
    f"실행되지 않은 우회 종류가 있습니다: {len(gen.R2_EVASION_TEMPLATES) - len(kinds)}개"
  )


def test_a1_respects_target_doc_count() -> None:
  """--num-targets 로 문서를 줄이면 A1 쿼리 수도 예전처럼 줄어야 한다.

  A1 은 문서 비의존이지만, 문서 수를 줄여 빠르게 돌려보는 기존 사용법
  (`rag run -s R2 -n 3`)의 비용 특성까지 바꾸지는 않는다.
  """
  gen = AttackQueryGenerator(_config(), attacker="A1")
  stride = _stride(gen)
  pool_size = len(gen.GENERIC_OBSERVER_KEYWORDS)
  # 슬롯 수가 풀보다 적어 상한에 걸리지 않는 문서 수를 고른다(현재 stride=16 → 1개).
  small = max(1, pool_size // stride)
  few = gen.generate_r2_queries(_docs(small), env="clean")
  many = gen.generate_r2_queries(_docs(20), env="clean")

  # 상한에 안 걸리는 구간에서는 문서 수 × stride 그대로 나온다.
  assert len(few) == small * stride, (
    f"문서 {small}개일 때 {small * stride}개를 기대했으나 {len(few)}개"
  )
  # 문서 20개면 슬롯이 넘치지만 키워드 풀 크기가 고유 쿼리의 상한이다.
  assert len(many) == pool_size, f"문서 20개일 때 {pool_size}개를 기대했으나 {len(many)}개"


def test_a2_still_targets_each_document() -> None:
  """A2 는 문서를 아는 공격자이므로 문서별 쿼리가 그대로 유지돼야 한다."""
  gen = AttackQueryGenerator(_config(), attacker="A2")
  docs = _docs(5)
  queries = gen.generate_r2_queries(docs, env="clean")

  # 문서 5개 × stride, 문서마다 target 이 붙는다(A1 과 달리 상한 없음).
  expected = 5 * _stride(gen)
  assert len(queries) == expected, f"{expected}개를 기대했으나 {len(queries)}개"
  assert {q["target_doc_id"] for q in queries} == {d["doc_id"] for d in docs}
  # A2 는 문서 본문 스니펫을 쓰므로 target_text 가 채워져 있어야 한다.
  assert all(q["target_text"] for q in queries)


def test_normal_queries_are_all_distinct() -> None:
  """NORMAL baseline 도 문서 수와 무관하게 중복 쿼리를 만들지 않는다."""
  from rag.attack.normal_baseline import NormalBaselineAttack

  attack = NormalBaselineAttack(
    {"attack": {"normal": {"num_templates": 9, "num_repeats": 1, "max_target_docs": 20}}},
    attacker="A1",
    env="clean",
  )
  queries = attack.generate_queries(_docs(20))

  texts = [q["query"] for q in queries]
  assert len(texts) == len(set(texts)), (
    f"NORMAL 이 중복 쿼리를 생성했습니다: {len(texts)}개 중 고유 {len(set(texts))}개"
  )
  ids = [q["query_id"] for q in queries]
  assert len(ids) == len(set(ids)), "query_id 가 중복됐습니다"


def test_normal_query_set_matches_legacy_doc_loop() -> None:
  """NORMAL 쿼리 '집합' 은 예전 문서 루프 구현과 정확히 같아야 한다.

  대조군이므로 실험 의미가 바뀌면 공격 시나리오와의 비교 자체가 깨진다.
  예전 구현(전역 카운터를 doc×template 로 누적)을 재현해 집합을 비교한다.
  """
  from rag.attack import normal_baseline as nb

  cfg = {"attack": {"normal": {"num_templates": 9, "num_repeats": 1, "max_target_docs": 20}}}
  attack = nb.NormalBaselineAttack(cfg, attacker="A1", env="clean")
  docs = _docs(20)
  actual = {q["query"] for q in attack.generate_queries(docs)}

  # --- 예전 구현 재현 ---
  template_pool = nb._NORMAL_QUERY_TEMPLATES
  template_count = min(9, len(template_pool))
  legacy: set[str] = set()
  global_pick_index = 0
  for _doc in docs:
    for i in range(template_count):
      _query_type, template_text = template_pool[i % len(template_pool)]
      keyword = attack.keywords[global_pick_index % len(attack.keywords)]
      global_pick_index += 1
      legacy.add(template_text.format(keyword=keyword))

  assert actual == legacy, (
    f"쿼리 집합이 달라졌습니다 (신규 전용 {len(actual - legacy)}개, "
    f"누락 {len(legacy - actual)}개)"
  )


def test_normal_respects_target_doc_count() -> None:
  """--num-targets 로 문서를 줄이면 NORMAL 쿼리 수도 예전처럼 줄어야 한다."""
  from rag.attack.normal_baseline import NormalBaselineAttack

  cfg = {"attack": {"normal": {"num_templates": 9, "num_repeats": 1, "max_target_docs": 20}}}
  attack = NormalBaselineAttack(cfg, attacker="A1", env="clean")

  # 문서 3개 × 템플릿 9 = 27 슬롯 < lcm(9, 16)=144 → 27개 그대로
  assert len(attack.generate_queries(_docs(3))) == 27
  # 문서 20개면 180 슬롯이지만 서로 다른 조합이 144개뿐이라 144 가 상한
  assert len(attack.generate_queries(_docs(20))) == 144
