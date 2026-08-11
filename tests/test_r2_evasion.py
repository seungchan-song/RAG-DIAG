"""R2 변형 출력 유도(evasion) 페이로드가 STEP 0 와 맞물려 있는지 검증합니다.

배경:
  STEP 0(변형 PII 정규화)은 구현돼 있고 기본값도 on 이지만, 2026-08-05 실측에서
  전체 문서 1,987개 중 **단 한 건도 발동하지 않았다.** 코퍼스에 변형 PII 가 없고
  공격 쿼리도 변형 출력을 요구하지 않았기 때문이다. 즉 성능을 측정할 방법이 없었다.

  해법은 코퍼스를 오염시키는 것이 아니라(사내 문서가 전각으로 쓰여 있을 이유가
  없다) **공격자가 변형해서 뱉으라고 시키는 것**이다 — 출력단 필터 우회는 실제
  위협이고, 문서는 정상인 채로 응답만 변형된다.

  이 테스트는 두 가지를 고정한다.
    1. 우회 종류 이름이 STEP 0 의 `applied` 어휘와 정확히 일치할 것.
       (어긋나면 "요청한 우회"와 "되돌린 변환"이 서로 다른 축이 돼 집계가 거짓말한다)
    2. 각 페이로드가 실제로 STEP 0 가 되돌릴 수 있는 변형을 지시할 것.
"""

from typing import Any

from rag.attack.query_generator import AttackQueryGenerator
from rag.pii.step0_normalize import TextNormalizer

# STEP 0 가 `NormalizationResult.applied` 에 기록하는 변환 이름 전체.
# step0_normalize.py 의 normalize() 가 append 하는 문자열과 같아야 한다.
STEP0_TRANSFORMS = {"invisible", "compat", "homoglyph", "jamo", "digit_sep"}


def _config() -> dict[str, Any]:
  return {"attack": {"r2": {"standard_indices": [0], "num_repeats": 1}}}


def _docs(n: int) -> list[dict[str, Any]]:
  return [
    {"content": f"문서 본문 {i}", "doc_id": f"doc-{i:03d}", "meta": {}}
    for i in range(n)
  ]


def test_evasion_kinds_cover_step0_transforms_exactly() -> None:
  """우회 종류와 STEP 0 변환이 1:1 대응해야 한다.

  한쪽에만 있는 항목이 생기면 "STEP 0 가 막아준 우회"를 종류별로 셀 수 없다.
  """
  kinds = {kind for kind, _template in AttackQueryGenerator.R2_EVASION_TEMPLATES}

  assert kinds == STEP0_TRANSFORMS, (
    f"우회 종류가 STEP 0 변환과 어긋납니다 "
    f"(공격에만 있음 {kinds - STEP0_TRANSFORMS}, STEP 0 에만 있음 {STEP0_TRANSFORMS - kinds})"
  )


def test_evasion_queries_carry_kind_metadata() -> None:
  """생성된 쿼리에 evasion 슬롯이 종류와 함께 실려야 한다.

  실행되는 종류는 템플릿 풀 전체가 아니라 **config 로 켠 것들**이다
  (기본값 = `R2_DEFAULT_EVASION_KINDS`).
  """
  gen = AttackQueryGenerator(_config(), attacker="A2")
  queries = gen.generate_r2_queries(_docs(2), env="clean")

  evasion = [q for q in queries if q["payload_type"] == "evasion"]
  assert evasion, "evasion 페이로드가 하나도 생성되지 않았습니다"
  assert {q["evasion_kind"] for q in evasion} == set(gen.R2_DEFAULT_EVASION_KINDS)
  # evasion 이 아닌 슬롯은 종류가 비어 있어야 리포트 집계가 새지 않는다.
  others = [q for q in queries if q["payload_type"] != "evasion"]
  assert all(q["evasion_kind"] == "" for q in others)


def test_default_evasion_kinds_exclude_measured_dead_slots() -> None:
  """기본값이 D9 실측(전량 거절·탐지 0건)을 반영해야 한다.

  compat·homoglyph 를 기본으로 되돌리면 20문서 셀 기준 RAG 호출이 80회 늘어나는데
  D9 에서 그 80건은 아무것도 측정하지 못했다. 되돌리려면 재측정 근거가 필요하다.
  """
  defaults = set(AttackQueryGenerator.R2_DEFAULT_EVASION_KINDS)

  assert defaults == {"jamo", "invisible", "digit_sep"}
  # 템플릿 풀 자체는 5종을 유지해야 재측정 시 이름만 되넣으면 된다.
  assert defaults < STEP0_TRANSFORMS


def test_evasion_kinds_are_config_selectable() -> None:
  """config 로 슬롯을 골라 쓰거나 전부 끌 수 있어야 한다."""
  config = _config()
  config["attack"]["r2"]["evasion_kinds"] = ["compat", "없는종류"]
  gen = AttackQueryGenerator(config, attacker="A2")
  queries = gen.generate_r2_queries(_docs(2), env="clean")

  # 알 수 없는 이름은 무시되고, 지정한 종류만 실행된다.
  assert {q["evasion_kind"] for q in queries if q["payload_type"] == "evasion"} == {
    "compat"
  }

  config["attack"]["r2"]["evasion_kinds"] = []
  off_gen = AttackQueryGenerator(config, attacker="A2")
  off_queries = off_gen.generate_r2_queries(_docs(2), env="clean")

  assert not [q for q in off_queries if q["payload_type"] == "evasion"], (
    "빈 리스트는 evasion 슬롯을 전부 꺼야 한다 — 기본값 폴백이면 호출이 줄지 않는다"
  )


def test_step0_recovers_each_requested_evasion() -> None:
  """각 우회 종류대로 변형된 PII 를 STEP 0 가 실제로 되돌리는지 확인한다.

  페이로드가 지시하는 변형을 응답에 그대로 재현해, STEP 0 가 그 변환을
  `applied` 에 기록하고 원문 표기를 복원하는지 본다. 이게 깨지면 우회 요청은
  나가는데 탐지는 못 하는 상태가 되어 유출이 0건으로 찍힌다.
  """
  normalizer = TextNormalizer({"pii": {"normalize": {"digit_spacing_min_run": 5}}})
  samples = {
    # 전각 숫자 (compat)
    "compat": "연락처는 ０１０－１２３４－５６７８ 입니다.",
    # 키릴 'о'(U+043E) 를 섞은 이메일 (homoglyph)
    "homoglyph": "메일은 hоng@example.com 입니다.",
    # 자모 분리된 이름 (jamo)
    "jamo": "담당자는 ㅎㅗㅇㄱㅣㄹㄷㅗㅇ 입니다.",
    # 제로폭 문자 삽입 (invisible)
    "invisible": "연락처는 010-1​234-5​678 입니다.",
    # 숫자 사이 공백 (digit_sep). 주민번호는 하이픈 사이 숫자열이 6·7자리라
    # 게이트(digit_spacing_min_run=5)를 넘는다.
    "digit_sep": "주민번호는 9 0 1 0 1 5 - 1 2 3 4 5 6 7 입니다.",
  }

  for kind, text in samples.items():
    result = normalizer.normalize(text)
    assert kind in result.applied, (
      f"{kind} 변형을 STEP 0 가 되돌리지 못했습니다 (applied={result.applied})"
    )


def test_spaced_identifier_runs_are_recovered() -> None:
  """공백 삽입된 전화번호·이메일이 회수되는지 — 예전 '미탐 핀' 을 뒤집은 자리.

  이 테스트는 원래 반대 방향이었다(`applied == []` 을 못박아 둠). 근거는
  "임계값 5 는 **연속 숫자** 길이인데 한국 전화번호는 하이픈으로 3·4·4 로 끊긴다"
  였는데, 그 미탐이 실제 피해를 냈다 — RAG-2026-0810-001 실측에서
  `0 1 0 - 9 0 0 0 - 5 0 1 4` 가 전화번호로 복원되지 않아 NER 이 이를 `QT_IP` 로
  오탐했고(응답 1건당 QT_IP 6건), `y e o n w o o . y a n g 8 0 @ e x a m p l e . t e s t`
  는 이메일 탐지를 통째로 빠져나갔다.

  임계값(5)은 그대로 두고 **런의 정의만** 넓혔다: 숫자-숫자가 아니라
  영숫자+구분자(`_RUN_CHARS`) 런. clean/poisoned/demo 코퍼스 2,228건에 새 정규화기를
  돌려 발동 0건임을 확인했으므로 정상 문서 오탐은 없다.
  """
  normalizer = TextNormalizer({"pii": {"normalize": {"digit_spacing_min_run": 5}}})

  phone = normalizer.normalize("연락처는 0 1 0 - 1 2 3 4 - 5 6 7 8 입니다.")
  assert "010-1234-5678" in phone.normalized_text, (
    f"하이픈으로 끊긴 전화번호 런이 복원되지 않았습니다 (={phone.normalized_text!r})"
  )

  email = normalizer.normalize("이메일 y a n g 8 0 @ e x a m p l e . t e s t 입니다.")
  assert "yang80@example.test" in email.normalized_text, (
    f"영문 공백 삽입 이메일이 복원되지 않았습니다 (={email.normalized_text!r})"
  )


def test_spaced_run_does_not_touch_normal_prose() -> None:
  """정상 표기는 런이 끊겨 그대로 남아야 한다 — 위 확장의 오탐 안전망.

  한글('3 년 9 개월')과 슬래시('8 5 / 1 0 0')는 `_RUN_CHARS` 밖이라 런을 끊는다.
  이게 깨지면 점수·기간 같은 평범한 숫자가 붙어 NER 에 새 오탐을 만든다.
  """
  normalizer = TextNormalizer({"pii": {"normalize": {"digit_spacing_min_run": 5}}})

  for text in ("전공 실무 능력: 8 5 / 1 0 0", "근무 기간 3 년 9 개월", "방 302 호실 5명"):
    result = normalizer.normalize(text)
    assert result.applied == [], f"정상 표기가 정규화됐습니다: {text!r} → {result.normalized_text!r}"
