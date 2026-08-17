"""PII 태그 네임스페이스 정합성 회귀 테스트.

태그 이름은 네 곳에 흩어져 있고 서로 맞물려야만 리포트와 벤치마크가 옳다.

  step3_ner.NER_LABEL_MAP   모델이 뱉는 33종 라벨 → 내부 단축 태그
  eval.CANONICAL_LABELS     벤치마크 채점 네임스페이스
  classifier.PII_TAG_LABELS 사용자에게 보여줄 한국어 이름
  step4_sllm.ADAPTER_TAG_MAP 내부 태그 → sLLM 어댑터가 학습한 라벨

한쪽만 바뀌면 조용히 세 가지가 망가진다.
  · 한국어 이름이 없으면 마스킹 자리표시자가 `[TMI_BLOOD_TYPE]` 처럼 내부
    코드명 그대로 리포트에 실린다(2026-08-06 실측: 5종 누락).
  · canonical 에 없으면 벤치마크가 맞게 탐지한 항목을 오탐+미탐으로 이중 계산
    한다(`QT_MOBILE`/`QT_PHONE` 때 실제로 210건이 그렇게 샜다).
  · 어댑터가 못 본 라벨을 보내면 STEP 4 가 OOD 입력을 받는다. 예외가 아니라
    판정 품질만 조용히 떨어지므로 눈에 띄지 않는다.

셋 다 예외가 아니라 '숫자가 조용히 틀리는' 방식으로 나타나므로 테스트로 막는다.
"""

from __future__ import annotations

from rag.pii.classifier import PII_TAG_LABELS, tag_label
from rag.pii.eval import CANONICAL_LABELS, LABEL_ALIASES
from rag.pii.masker import PIIMasker
from rag.pii.step3_ner import HIGH_F1_TAGS, NER_LABEL_MAP
from rag.pii.step4_sllm import ADAPTER_TAG_MAP

# STEP 4 sLLM 어댑터가 실제로 학습한 후보 태그 23종.
# 출처: bbanany/korean-pii-candidate-classification 의 `dataset_report.json`
# (clean split 태그 분포, 2026-08-17 확인). 추정이 아니라 학습 데이터 원문 값이다.
#
# 33종이 아니라 23종인 이유: 어댑터는 우리 NER 라벨 체계 전부가 아니라 후보 span
# 분류에 필요한 부분집합만 학습했다. 그래서 이 집합이 곧 STEP 4 의 입력 계약이다.
SLLM_TRAINED_TAGS = frozenset({
  "ACCOUNT_NUMBER",
  "ADDRESS",
  "AGE",
  "BIRTHDATE",
  "BLOOD_TYPE",
  "CARD_NUMBER",
  "CITY",
  "DEPARTMENT",
  "EMAIL",
  "EMPLOYEE_ID",
  "GENDER",
  "HEIGHT",
  "IP_ADDRESS",
  "MAJOR",
  "NAME",
  "NATIONALITY",
  "NICKNAME",
  "PHONE_NUMBER",
  "POSITION",
  "RELIGION",
  "SCHOOL",
  "WEIGHT",
  "WORKPLACE",
})


def test_every_ner_tag_has_a_korean_label():
  """NER 이 낼 수 있는 모든 내부 태그에 한국어 이름이 있어야 한다."""
  missing = sorted(set(NER_LABEL_MAP.values()) - set(PII_TAG_LABELS))
  assert not missing, (
    f"한국어 이름이 없는 태그: {missing}. "
    "classifier.PII_TAG_LABELS 에 추가할 것 — 없으면 마스킹 자리표시자가 "
    "내부 코드명 그대로 리포트에 노출된다."
  )


def test_every_ner_tag_is_in_benchmark_namespace():
  """NER 내부 태그가 벤치마크 canonical 집합 안에 있어야 채점이 맞물린다."""
  missing = sorted(set(NER_LABEL_MAP.values()) - set(CANONICAL_LABELS))
  assert not missing, (
    f"eval.CANONICAL_LABELS 에 없는 태그: {missing}. "
    "라벨을 옮길 때는 step3_ner·eval·classifier 를 같은 커밋에서 함께 고칠 것."
  )


def test_ner_and_eval_agree_on_source_label_mapping():
  """같은 원본 라벨은 step3 와 eval 이 같은 내부 태그로 접어야 한다.

  둘이 갈라지면 모델이 맞게 탐지해도 벤치마크는 다른 태그로 채점해 틀렸다고 센다.
  """
  disagreements = {
    label: (internal, LABEL_ALIASES[label])
    for label, internal in NER_LABEL_MAP.items()
    if label in LABEL_ALIASES and LABEL_ALIASES[label] != internal
  }
  assert not disagreements, f"step3 ↔ eval 매핑 불일치: {disagreements}"


def test_step4_candidates_use_labels_the_adapter_was_trained_on():
  """STEP 4 로 가는 태그는 전부 어댑터 학습 어휘 안에 있어야 한다.

  STEP 4 는 B-2 경로(= HIGH_F1_TAGS 밖)만 받는다. 그 13개가 ADAPTER_TAG_MAP 을
  거쳐 어떤 라벨로 나가는지가 어댑터와의 실제 계약이고, 2026-08-17 학습셋 대조
  시점에는 OOD 0건이었다. 매핑이나 HIGH_F1_TAGS 를 건드리면 여기가 먼저 깨진다.

  B-1 경로는 일부러 단언하지 않는다. QT_PHONE→PHONE 등 11개가 학습 어휘 밖이지만
  (학습셋은 PHONE_NUMBER 로 학습했다) B-1 은 sLLM 을 안 타므로 지금은 무해하다.
  다만 태그별 이중임계(U4)로 confidence 하드컷을 낮추면 그 순간 살아난다.
  """
  reachable = sorted(set(NER_LABEL_MAP.values()) - HIGH_F1_TAGS)
  out_of_vocabulary = {
    tag: ADAPTER_TAG_MAP.get(tag, tag)
    for tag in reachable
    if ADAPTER_TAG_MAP.get(tag, tag) not in SLLM_TRAINED_TAGS
  }
  assert not out_of_vocabulary, (
    f"어댑터가 학습하지 않은 라벨로 나가는 태그: {out_of_vocabulary}. "
    "step4_sllm.ADAPTER_TAG_MAP 을 학습 어휘로 맞추거나, 어휘가 실제로 늘었으면 "
    "SLLM_TRAINED_TAGS 를 dataset_report.json 기준으로 갱신할 것."
  )


def test_gender_is_not_classified_as_health_information():
  """성별은 건강정보가 아니다 (개인정보보호법 제23조 민감정보에 들지 않는다).

  예전에는 GENDER 가 TMI_HEALTH 로 접혀 리포트가 성별 탐지를 "건강정보"로
  표기했다. 위험 등급은 둘 다 context 라 점수는 안 바뀌었지만 표기가 틀렸다.
  """
  assert NER_LABEL_MAP["GENDER"] == "TMI_GENDER"
  assert LABEL_ALIASES["GENDER"] == "TMI_GENDER"
  assert tag_label("TMI_GENDER") == "성별"


def test_mask_mobile_preserves_carrier_prefix():
  """마스킹이 통신사 식별번호를 위조하지 않는다.

  예전 구현은 앞 3자리를 "010" 으로 하드코딩해 011·016·017·018·019 번호를
  전부 010 으로 바꿔 저장했다. 마스킹은 가리는 작업이지 없는 사실을 만드는
  작업이 아니다 — 이 산출물은 리포트에 그대로 실린다.
  """
  masker = PIIMasker()

  class _Item:
    def __init__(self, text: str) -> None:
      self.text = text
      self.tag = "QT_MOBILE"

  assert masker.mask_single(_Item("010-1234-5678")) == "010-****-5678"
  assert masker.mask_single(_Item("011-123-4567")) == "011-****-4567"
  assert masker.mask_single(_Item("019-9876-5432")) == "019-****-5432"
  # 자릿수가 모자라면 값을 지어내지 말고 자리표시자로 떨어뜨린다.
  assert masker.mask_single(_Item("1234")) == "[휴대전화]"
