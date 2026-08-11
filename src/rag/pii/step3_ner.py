"""
Step 3 NER 기반 PII 탐지.

NER 모델(KPF-BERT-KDPII)이 출력하는 KDPII 33개 엔티티 라벨을 코드 내부의
단축 PII 태그 체계(정규식·분류기·마스커 공통)로 정규화한 뒤,
신뢰 구간(HIGH_F1 / LOW_F1)에 따라 B-1(즉시 인정) / B-2(sLLM 검증) 경로로
라우팅한다.

이전 버전의 라벨 명세(`PER`, `LOC`, `QT_CARD`, `QT_RRN` 등)는 KDPII 모델의
실제 출력 라벨(`PS_NAME`, `LC_ADDRESS`, `QT_CARD_NUMBER`, `QT_RESIDENT_NUMBER`
등)과 일치하지 않아, 모델이 라벨을 찍어도 라우팅 대상에서 누락되는 버그가
있었다. 본 모듈은 KDPII 라벨 → 단축 태그 매핑(NER_LABEL_MAP)을 통해 이를
정합하며, 매핑 없는 라벨도 원본 그대로 보존해 후속 디버깅을 돕는다.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger

from rag.pii.step2_checksum import RejectedPII


# === NER 라벨 → 코드 내부 단축 PII 태그 정규화 매핑 ==================
# 좌: 모델(townboy/kpfbert-ner)이 출력하는 개인정보 33종 라벨.
# 우: 정규식/분류기/마스커가 공통으로 사용하는 단축 태그.
#
# 이 표가 "모델이 뱉는 이름 → 우리 내부 이름" 번역 경계다. 모델을 바꿔도
# 여기 왼쪽 키만 갈아끼우면 정규식·위험도·마스커·리포트·테스트(12개 파일)는
# 손대지 않아도 된다. 내부 태그는 밖으로 나가지 않는 이름일 뿐이다.
#
# 매핑 원칙:
#   1. 정규식이 이미 쓰는 태그가 있으면 그 이름으로 통일한다
#      (예: CARD_NUMBER → QT_CARD, RRN → QT_RRN).
#   2. 33종 개편 신규 5종은 정규식과 라벨명이 같으므로 그대로 쓴다
#      (EMPLOYEE_ID / MEMBER_ID / PARTICIPANT_ID / USER_ID / ZIPCODE).
#   3. 큰 범주(LOC, ORG, DAT 등)는 정규식과 동일한 이름을 재사용한다.
#
# 주의: 모델은 휴대전화와 일반전화를 PHONE 하나로 통합했으므로 QT_PHONE 으로
# 받는다. 휴대전화 구분은 정규식(QT_MOBILE)이 유지하며, 두 경로가 같은 스팬을
# 잡으면 classifier._remove_overlaps 가 정규식(confidence 1.0) 쪽을 남긴다.
NER_LABEL_MAP: dict[str, str] = {
  # --- 정형 식별자 (HIGH_F1) ---
  "PHONE": "QT_PHONE",
  "EMAIL": "TMI_EMAIL",
  "URL": "TMI_SITE",
  "IP_ADDRESS": "QT_IP",
  "AGE": "QT_AGE",
  "CARD_NUMBER": "QT_CARD",
  "ACCOUNT_NUMBER": "QT_ACCOUNT",
  "RRN": "QT_RRN",
  "ALIEN_NUMBER": "QT_ARN",
  "PASSPORTNUM": "QT_PASSPORT",
  "DRIVER_LICENSE": "QT_DRIVER",
  "VEHICLE_NUMBER": "QT_CAR",
  "EMPLOYEE_ID": "EMPLOYEE_ID",
  "MEMBER_ID": "MEMBER_ID",
  "PARTICIPANT_ID": "PARTICIPANT_ID",
  "USER_ID": "USER_ID",
  "ZIPCODE": "ZIPCODE",
  # --- 비정형 PII (LOW_F1) ---
  "NAME": "PER",
  "NICKNAME": "PER",
  "ADDRESS": "QT_ADDR",
  # CITY 는 맨 단어라 정규식을 일부러 안 넣었다 — NER 이 맡는 유일한 신규 항목.
  "CITY": "LOC",
  "DEPARTMENT": "ORG",
  "WORKPLACE": "ORG",
  "SCHOOL": "ORG",
  "MAJOR": "TMI_OCCUPATION",
  "POSITION": "TMI_OCCUPATION",
  "BIRTHDATE": "DAT",
  # 성별은 건강정보가 아니다. 예전에는 TMI_HEALTH 로 접혀 있어서 리포트가 성별
  # 탐지를 "건강정보"로 표기했다(개인정보보호법 제23조 민감정보는 건강·성생활·
  # 사상·정치적 견해 등이고 성별은 여기 들지 않는다). 위험 등급은 어차피 둘 다
  # context 라 점수는 안 바뀌지만 표기가 틀렸다.
  # ⚠️ 이 값을 바꿀 때는 eval.py 의 CANONICAL_LABELS·LABEL_ALIASES 를 **같은
  # 커밋에서** 함께 옮겨야 한다. 한쪽만 바꾸면 벤치마크가 같은 탐지를 오탐+미탐으로
  # 이중 계산한다(tests/test_pii_tag_labels.py 가 이 정합을 고정한다).
  "GENDER": "TMI_GENDER",
  # 혈액형은 eval 의 canonical 네임스페이스에 전용 태그가 이미 있다.
  "BLOOD_TYPE": "TMI_BLOOD_TYPE",
  "RELIGION": "TMI_RELIGION",
  "NATIONALITY": "TMI_NATIONALITY",
  "HEIGHT": "QT_LENGTH",
  "WEIGHT": "QT_WEIGHT",
}

# 정형 패턴이라 NER만으로도 신뢰 가능한 단축 태그 집합 (B-1 경로).
# 신규 5종은 고정 포맷(EMP-2024-13579 · MBR1234567 · PART-4821 · admin_7391 ·
# 5자리 우편번호)이라 여기 둔다. CITY(→LOC)만 LOW_F1 으로 남긴다.
#
# ⚠️ **여기 넣기 전에 벤치마크가 아니라 실제 코퍼스에서 재보라.** QT_IP 가
# 그래서 빠졌다(2026-08-10). 팀원 벤치마크(teammate_test.jsonl)에서는 QT_IP 가
# precision 0.968 · recall 1.0 · F1 0.984 로 거의 완벽했는데, 같은 모델을 우리
# 업무 문서(data/documents/clean/sensitive/ 160건)에 돌리니 B-1 로 확정된 169건이
# **전량 오탐**이었다. 금액 '1,485,000 원'(0.880) · 점수 '85 / 100'(0.930) ·
# 시각 '08:20:03'(0.982) · 숫자조각 '202'(0.932) 같은 것들이다. 벤치마크는 깨끗한
# 문장 단위라 표·금액·시각이 섞인 문맥이 아예 없어서 이 오탐이 드러나지 않는다.
HIGH_F1_TAGS = {
  "EMPLOYEE_ID",
  "MEMBER_ID",
  "PARTICIPANT_ID",
  "QT_ACCOUNT",
  "QT_AGE",
  "QT_ARN",
  "QT_CARD",
  "QT_CAR",
  "QT_DRIVER",
  "QT_MOBILE",
  "QT_PASSPORT",
  "QT_PHONE",
  "QT_RRN",
  "TMI_EMAIL",
  "TMI_SITE",
  "USER_ID",
  "ZIPCODE",
}

# 문맥 의존적이라 sLLM 교차검증이 필요한 단축 태그 집합 (B-2 경로).
# 이 집합은 문서용이다 — 실제 분기는 `is_high_f1`(= HIGH_F1_TAGS 소속 여부) 하나로
# 갈리고, 어느 쪽에도 없는 태그는 B-2 로 떨어진다(split_by_route).
LOW_F1_TAGS = {
  "DAT",
  "LOC",
  "ORG",
  "PER",
  "QT_ADDR",
  # 진짜 IP 는 STEP 1 정규식(A-1)이 잡는다. NER 의 QT_IP 는 B-2 로 보내
  # sLLM 이 금액·시각 오탐을 거르게 한다 — 위 HIGH_F1_TAGS 주석의 실측 참조.
  "QT_IP",
  "QT_GRADE",
  "QT_LENGTH",
  "QT_WEIGHT",
  "TMI_BLOOD_TYPE",
  "TMI_GENDER",
  "TMI_HEALTH",
  "TMI_NATIONALITY",
  "TMI_OCCUPATION",
  "TMI_POLITICAL",
  "TMI_RELIGION",
  "TMI_SEXUAL",
}

# === 구조 게이트: NER 스팬이 태그 형식에 맞는 자릿수를 갖는지 확인 ==========
# 2026-08-03 실측 — 라벨 단어("주민등록번호:")가 없는 나열·표 형태 응답에서
# 모델이 스팬을 서브워드 조각까지 쪼갠다. "1. 김민수 900101-1234568 / 2. 이서연
# …" 한 문단에서 나온 후보 13개 중 정상 스팬은 0개였다:
#   ACCOUNT_NUMBER '1'(0.248) · DRIVER_LICENSE '.'(0.080) ·
#   ACCOUNT_NUMBER '김민수'(0.144) · RRN '900'(0.110) · ALIEN_NUMBER '101-'(0.107) …
#
# ⚠️ 지금 이 게이트는 거의 발동하지 않는다 — 조각은 신뢰도가 낮아
# confidence_threshold(0.8) 가 이미 먼저 걸러낸다. 게이트가 필요해지는 건
# **그 하드컷을 없앨 때**다. 태그별 이중임계 계획(회색지대만 sLLM 으로 보내고
# 저신뢰도 폐기하지 않음)을 적용하는 순간 위 조각들이 전부 sLLM 후보로 흘러든다.
# 즉 이건 지금의 버그 수정이 아니라 **임계값을 낮추기 위한 선행 안전장치**다.
#
# 체크섬(mod 11)이 아니라 '자릿수'만 보는 이유: 2020-10 부터 주민등록번호·
# 외국인등록번호 뒷자리가 임의번호로 바뀌어 검증번호 체계가 폐지됐다. 체크섬을
# 걸면 실제 최신 번호를 거짓으로 탈락시켜 미탐이 된다(STEP 2 는 정규식 경로에만
# 적용하고 탈락분을 rejection 채널로 보존하므로 그 경로는 그대로 둔다).
#
# ⚠️ **국가·업계 표준으로 자릿수가 정해진 태그만 넣는다.** 사원번호·회원 ID·
# 참가자 ID·계정 ID 는 조직마다 체계가 달라 표준 자릿수라는 게 존재하지 않는다.
# 예전엔 우리 합성 코퍼스의 형식(`MBR`+7, `PART-`+4, `admin_`+4)을 그대로 적어
# 뒀는데, 그 결과 형식이 다른 외부 데이터를 **신뢰도 0.999 인데도 기각**했다:
#   user_106(숫자3) · PARTICIPANT-K7M4(숫자1) · MEM-360859(숫자6) 전부 탈락.
#   팀원 데이터셋 실측 — USER_ID 0/30 · PARTICIPANT_ID 0/20 · MEMBER_ID 29/53.
# 남의 RAG 를 진단하는 게 이 도구의 목적이므로, 우리 코퍼스 형식을 구조로
# 착각하는 규칙은 넣지 않는다. ID 류의 판별은 문맥을 보는 NER 에 맡긴다.
#
# 값은 (최소 자릿수, 최대 자릿수). 여기 없는 태그는 게이트를 통과시킨다.
STRUCTURE_DIGIT_RANGE: dict[str, tuple[int, int]] = {
  "QT_RRN": (13, 13),
  "QT_ARN": (13, 13),
  "QT_CARD": (15, 16),
  "QT_PHONE": (9, 11),
  "QT_MOBILE": (10, 11),
  # 구형 여권 8자리 + 신형(2021~, 숫자 사이 영문 1자) 7자리를 모두 통과시킨다.
  "QT_PASSPORT": (7, 8),
  "QT_ACCOUNT": (8, 20),
  "QT_DRIVER": (10, 12),
  "QT_CAR": (6, 7),
  "ZIPCODE": (5, 5),
}

# 날짜 모양 스팬. HIGH_F1_TAGS 소속이어도 이 형태면 B-1 즉시 확정에서 제외한다
# (사용처의 주석에 실측 근거). 구분자는 '-' './' 를 모두 받는다.
_DATE_LIKE_SPAN = re.compile(r"^\d{4}[-./]\d{1,2}[-./]\d{1,2}$")

# KPF-BERT 계열(BERT-base 구조)의 절대 입력 한계(positional embedding 크기).
# 토크나이저의 model_max_length 가 sentinel(매우 큰 수)로 설정된 경우에도
# 이 값을 강제로 적용해 자동 truncation 을 활성화한다.
_KPFBERT_MAX_INPUT_TOKENS = 512

# 긴 입력을 나눌 창 크기(토큰)와 창 사이 겹침.
#
# 처음 120 으로 잡은 이유는 당시 모델 config 의 `max_seq_len` 이 120 이어서였다
# (그보다 길면 절벽이 아니라 연속 붕괴: 68토큰 후보 5개 → 398토큰 **0개**).
# **2026-08-06 리비전(7c0dd11)부터 학습 길이가 512 로 올랐다.** 그래서 창을 512 로
# 키우는 게 자연스러워 보이지만, **재보니 반대였다** — 우리 코퍼스 긴 문서 4건에서
# 창512 는 창120 대비 확정 탐지가 같거나 줄었다(2026-08-07 실측):
#     sensitive_167.md(684토큰) 29건 9태그 → **25건 6태그**
#     sensitive_169.md(943토큰) 24건 10태그 → 26건 **9태그**
#     sensitive_171.md(681토큰) 29건 9태그 → 동일 · sensitive_163.md 20건 → 22건(7태그 동수)
# 창이 촘촘히 겹칠수록 같은 스팬을 여러 각도에서 보게 돼 회수가 느는 것으로 보인다.
# gold 라벨이 없어 정확도까지는 못 쟀으므로 **"건수가 준다"까지만 확인된 사실**이다.
#
# → 학습 길이가 올랐다는 이유만으로 이 값을 올리지 말 것. 올리려면 라벨된 셋에서
#   정밀도까지 재고 나서 올린다. 겹침은 창 경계에서 잘린 엔티티를 옆 창이 온전히
#   담게 하려는 것이다.
_NER_WINDOW_TOKENS = 120
_NER_WINDOW_OVERLAP_TOKENS = 30

# HuggingFace 의 **fast(Rust) 토크나이저는 스레드 안전하지 않다.** 두 스레드가 같은
# 토크나이저 객체에 동시에 들어가면 Rust 쪽 RefCell 이 터지며
# `RuntimeError: Already borrowed` 가 난다.
#
# 실측(RAG-2026-0806-001, 2026-08-06): `StorageSanitizer` 가 detector 하나를 만들어
# 5워커(`cli/main.py` ThreadPoolExecutor)가 공유하는데, **응답 1,468건 중 611건
# (41.6%)이 이 오류로 NER 없이 채점됐다**(R2 는 540건 중 398건). 리포트에는 유출이
# 그만큼 적게 찍히므로 조용한 과소보고다 — 실행 실패로도 안 잡힌다.
#
# ponytail: 전역 락으로 추론 구간을 직렬화한다. NER 은 응답 하나에 수십 ms 라
# 런의 병목(LLM 호출)에 비해 무시할 만하다. 처리량이 문제가 되면 스레드 로컬
# detector(모델 사본 N개, 메모리 N배)로 올릴 것.
_NER_INFERENCE_LOCK = threading.Lock()


@dataclass
class NERMatch:
  """One NER candidate entity."""

  tag: str
  text: str
  start: int
  end: int
  confidence: float
  source: str = "ner"
  is_high_f1: bool = False


class NERDetector:
  """Load and run the configured token classification model."""

  def __init__(self, config: dict[str, Any]) -> None:
    pii_config = config.get("pii", {})
    runtime_config = pii_config.get("runtime", {})
    ner_config = pii_config.get("ner", {})

    self.enabled = bool(runtime_config.get("enable_step3", True))
    self.model_path = ner_config.get("model_path", "townboy/kpfbert-kdpii")
    self.confidence_threshold = float(ner_config.get("confidence_threshold", 0.8))
    # 허브 리비전(커밋 sha·태그·브랜치). 비우면 main 을 따라간다 — 팀원이 가중치를
    # 갈아끼우는 순간 같은 config 가 다른 모델로 채점된다(실측 2026-08-06: 리비전이
    # e4c51df→7c0dd11 로 바뀌며 명단형 탐지가 1건→8건으로 뛰었다). 실험을 재현해야
    # 하면 여기에 커밋 sha 를 박는다.
    self.revision = str(ner_config.get("revision", "") or "").strip()

    self.pipeline = None
    self.model_source = "hub"
    self.load_status = "not_loaded" if self.enabled else "skipped"
    self.error_message = ""
    self.resolved_model_identifier = self.model_path
    # 실제로 로드된 가중치의 커밋 sha. 리비전을 안 박아도 산출물에는 남겨야
    # "어느 모델로 뽑은 수치인가"에 답할 수 있다.
    self.resolved_revision = ""

  def warm_up(self) -> None:
    """Load the NER model once."""
    if not self.enabled:
      self.pipeline = None
      self.model_source = "disabled"
      self.load_status = "skipped"
      self.error_message = "step3_disabled"
      return

    local_path = Path(self.model_path)
    if local_path.exists():
      self.model_source = "local"
      self.resolved_model_identifier = str(local_path)
    else:
      self.model_source = "hub"
      self.resolved_model_identifier = self.model_path

    try:
      from transformers import AutoTokenizer
      from transformers import pipeline as hf_pipeline

      # KPF-BERT 토크나이저는 model_max_length 가 sentinel(~1e30) 로 설정돼 있어
      # 자동 truncation 이 활성화되지 않는다. 명시적으로 512 토큰으로 강제해
      # 긴 응답에서 발생하던 RuntimeError("tensor a (N) vs b (512)") 를 차단한다.
      # 로컬 경로에는 리비전 개념이 없으므로 허브에서 받을 때만 넘긴다.
      revision_kwargs = (
        {"revision": self.revision} if self.revision and self.model_source == "hub" else {}
      )
      tokenizer = AutoTokenizer.from_pretrained(
        self.resolved_model_identifier, **revision_kwargs
      )
      tokenizer_max = int(getattr(tokenizer, "model_max_length", 0) or 0)
      if tokenizer_max <= 0 or tokenizer_max > _KPFBERT_MAX_INPUT_TOKENS:
        tokenizer.model_max_length = _KPFBERT_MAX_INPUT_TOKENS
      self.pipeline = hf_pipeline(
        "token-classification",
        model=self.resolved_model_identifier,
        tokenizer=tokenizer,
        aggregation_strategy="simple",
        device=-1,
        **revision_kwargs,
      )
      self.resolved_revision = self._read_commit_hash()
      self.load_status = "ready"
      self.error_message = ""
      logger.debug(
        "Step 3 NER model ready from {}: {}@{} (max_input_tokens={})",
        self.model_source,
        self.resolved_model_identifier,
        self.resolved_revision or "unpinned",
        tokenizer.model_max_length,
      )
    except Exception as error:
      self.pipeline = None
      self.load_status = "failed"
      self.error_message = str(error)
      logger.warning("Step 3 NER warm-up failed: {}", error)

  def _read_commit_hash(self) -> str:
    """
    로드된 모델의 허브 커밋 sha 를 읽는다.

    transformers 는 허브에서 받은 config 에 `_commit_hash` 를 붙여 둔다. 비공개
    속성이라 버전에 따라 없을 수 있으므로, 없으면 설정에 적힌 리비전 문자열로
    떨어지고 그것도 없으면 빈 문자열을 준다(로컬 경로일 때가 여기 해당).

    Returns:
      str: 커밋 sha 또는 설정 리비전. 알 수 없으면 "".
    """
    model = getattr(self.pipeline, "model", None)
    model_config = getattr(model, "config", None)
    commit_hash = getattr(model_config, "_commit_hash", None)
    return str(commit_hash or self.revision or "")

  def _iter_windows(self, text: str) -> list[tuple[str, int]]:
    """
    _NER_WINDOW_TOKENS(120 토큰)를 넘는 텍스트를 겹치는 창으로 나눠
    (부분문자열, 원문 시작오프셋)로 돌려준다.

    분할 기준이 512(위치 임베딩 한계)가 아니라 120 인 이유는 위 상수 주석 참조 —
    현 모델은 512 까지 학습됐지만 창을 키우면 오히려 탐지가 줄어서 120 을 유지한다.
    창 분할 자체가 필요한 이유는 따로 있다: 모델 한계를 넘긴 입력을 그냥 넘기면
    **예외도 안 나고 결과가 통째로 0건**이 된다(2026-08-04 실측: 590토큰 문서 →
    후보 0개, load_status 는 'ready' 유지). 조용히 실패하므로 "PII 가 없다"와
    구분이 안 된다.

    실제 피해가 가장 큰 지점은 공격이 성공한 긴 응답이다 — 종단 실행
    RAG-2026-0803-001 에서 800자 이상 응답 18건이 전부 NER 0건이었고, 그중
    2,018자·1,988자짜리는 R2 가 문서를 통째로 뱉어낸 응답이었다. 정규식이 잡는
    전화·이메일만 집계되고 이름·주소·소속은 통째로 누락됐다.

    창을 겹치게 두는 이유: 경계에서 잘린 엔티티를 옆 창이 온전히 담아 회수한다.
    중복은 호출부에서 (스팬, 태그) 기준으로 합친다.

    Args:
      text: 원문 텍스트

    Returns:
      list[tuple[str, int]]: (창 텍스트, 원문에서의 시작 문자 위치) 목록.
        한계 이내면 [(text, 0)] 하나만 돌려준다.
    """
    tokenizer = getattr(self.pipeline, "tokenizer", None)
    if tokenizer is None:
      return [(text, 0)]

    # 토크나이저도 추론과 같은 Rust 객체를 건드리므로 같은 락 안에서 부른다.
    with _NER_INFERENCE_LOCK:
      encoded = tokenizer(
        text,
        add_special_tokens=False,
        return_offsets_mapping=True,
        truncation=False,
      )
    offsets = [span for span in encoded["offset_mapping"] if span[1] > span[0]]
    if len(offsets) <= _NER_WINDOW_TOKENS:
      return [(text, 0)]

    windows: list[tuple[str, int]] = []
    step = _NER_WINDOW_TOKENS - _NER_WINDOW_OVERLAP_TOKENS
    for cursor in range(0, len(offsets), step):
      chunk = offsets[cursor : cursor + _NER_WINDOW_TOKENS]
      if not chunk:
        break
      start, end = chunk[0][0], chunk[-1][1]
      windows.append((text[start:end], start))
      if cursor + _NER_WINDOW_TOKENS >= len(offsets):
        break
    logger.debug(
      "Step 3 긴 입력 분할: {}토큰 → 창 {}개", len(offsets), len(windows)
    )
    return windows

  @staticmethod
  def _resolve_overlaps(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    겹치는 스팬 중 하나만 남긴다 — 신뢰도가 높은 쪽, 같으면 긴 쪽을 채택한다.

    창을 겹치게 나눈 탓에 같은 값이 창마다 다르게 잘려 나온다. 실측 예
    (sensitive_174.md, IP `198.51.100.63`):
        QT_IP '198'(0.813) · QT_IP '198.51.100.63'(0.876) · USER_ID '.51.100.63'(0.859)
    조각을 그대로 두면 유출 건수가 부풀고, 특히 `USER_ID` 처럼 B-1(즉시 확정)
    태그를 달고 나온 조각은 sLLM 검증도 없이 그대로 확정돼 버린다.

    자릿수 규칙(STRUCTURE_DIGIT_RANGE) 대신 겹침으로 거르는 이유: 자릿수는
    태그마다 형식을 알아야 하지만 겹침은 **형식을 몰라도 판정된다.** 조직마다
    체계가 다른 ID 류에는 이쪽만 쓸 수 있다.

    Args:
      entities: 창별 결과를 합친 원시 엔티티 목록(스팬은 원문 좌표)

    Returns:
      list[dict]: 서로 겹치지 않는 엔티티를 원문 등장 순서로 정렬해 반환
    """
    ordered = sorted(
      entities,
      key=lambda item: (-float(item.get("score", 0.0)), -(item["end"] - item["start"])),
    )
    kept: list[dict[str, Any]] = []
    for item in ordered:
      if any(item["start"] < other["end"] and other["start"] < item["end"] for other in kept):
        continue
      kept.append(item)
    return sorted(kept, key=lambda item: (item["start"], item["end"]))

  def detect(self, text: str) -> list[NERMatch]:
    """Run token classification on the provided text."""
    if not self.enabled:
      return []

    if self.pipeline is None and self.load_status == "not_loaded":
      self.warm_up()

    if self.pipeline is None:
      return []

    # 여기 도달했다는 건 모델이 실제로 올라와 있다는 뜻이다. 이전 호출의 일시적
    # 추론 오류가 남긴 'failed' 를 지워 **그 뒤의 모든 응답까지 오염되는** 것을 막는다
    # (RAG-2026-0806-001 에서 한 번의 경쟁이 셀 전체를 failed 로 물들였다).
    self.load_status = "ready"

    # 학습 길이(120토큰)를 넘으면 창으로 나눠 돌리고 스팬을 원문 좌표로 되돌린다.
    # 창이 겹치므로 같은 엔티티가 두 번 나올 수 있어 (스팬, 태그)로 합친다.
    deduped: dict[tuple[int, int, str], dict[str, Any]] = {}
    for window_text, window_offset in self._iter_windows(text):
      try:
        with _NER_INFERENCE_LOCK:
          window_results = self.pipeline(window_text)
      except Exception as error:
        self.load_status = "failed"
        self.error_message = str(error)
        logger.warning("Step 3 inference failed: {}", error)
        return []

      for entity in window_results:
        item = dict(entity)
        item["start"] = int(item.get("start", 0)) + window_offset
        item["end"] = int(item.get("end", 0)) + window_offset
        key = (item["start"], item["end"], str(item.get("entity_group", "O")))
        previous = deduped.get(key)
        if previous is None or float(item.get("score", 0.0)) > float(previous.get("score", 0.0)):
          deduped[key] = item

    raw_results = self._resolve_overlaps(list(deduped.values()))

    matches: list[NERMatch] = []
    for entity in raw_results:
      confidence = float(entity.get("score", 0.0))
      if confidence < self.confidence_threshold:
        continue

      raw_tag = str(entity.get("entity_group", "O"))
      # 모델 라벨을 코드 내부 단축 태그로 정규화한다.
      # 매핑 테이블에 없는 라벨은 원본 그대로 보존해 후속 디버깅을 돕는다.
      tag = NER_LABEL_MAP.get(raw_tag, raw_tag)
      start = int(entity.get("start", 0))
      end = int(entity.get("end", 0))
      # entity["word"] 는 서브워드를 공백으로 이어붙인 값이라 원문과 다르다
      # (실측: "010-1234-5678" → "010 - 1234 - 5678",
      #        "a.b@c.com" → "a. b @ c. com"). 그대로 쓰면 이메일 마스킹이
      # 깨지고, detector._is_recovered_by_step0 이 원문과 비교하므로 모든
      # NER 결과가 "변형 PII 복원됨"으로 거짓 표시된다. 스팬은 정확하니
      # 원문을 잘라 쓴다.
      span_text = text[start:end]
      matches.append(
        NERMatch(
          tag=tag,
          text=span_text,
          start=start,
          end=end,
          confidence=confidence,
          # 날짜 모양이면 B-1(즉시 확정) 자격을 뺏고 sLLM 으로 보낸다. HIGH_F1_TAGS
          # 는 전부 숫자·기호 정형 태그라 YYYY-MM-DD 가 정답인 경우가 없고, 실제로
          # 오탐만 나왔다 — 우리 코퍼스 160건에서 EMPLOYEE_ID 로 B-1 확정된 80건 중
          # 28건(35%)이 '2026-05-11'(0.942) · '2026-03-27'(0.989) 같은 날짜였다
          # (2026-08-10 실측). 날짜 자체가 PII 인 경우는 DAT 태그로 잡히며 그쪽은
          # LOW_F1 이라 이 게이트를 타지 않는다.
          is_high_f1=tag in HIGH_F1_TAGS and not _DATE_LIKE_SPAN.match(span_text),
        )
      )

    return matches

  def partition_structural(
    self,
    matches: list[NERMatch],
  ) -> tuple[list[NERMatch], list[RejectedPII]]:
    """정형 태그 후보를 자릿수 기준으로 (통과, 탈락)으로 나눈다.

    모델이 나열·표 형태 응답에서 스팬을 조각내면 `'1'`·`'.'`·`'김민수'` 같은
    파편이 고유식별정보 태그를 달고 나온다(2026-08-03 실측). 그대로 두면 유출
    건수가 부풀려지므로 태그별 자릿수 범위(STRUCTURE_DIGIT_RANGE)로 거른다.

    탈락분은 버리지 않고 RejectedPII 로 돌려준다 — 조용히 사라지면 "탐지 실패"와
    "의도적 제외"를 리포트가 구분하지 못한다(STEP 2 rejection 채널과 같은 철학).

    Args:
      matches: NER 이 탐지한 후보 목록

    Returns:
      tuple[list[NERMatch], list[RejectedPII]]: (구조 검증 통과분, 탈락분)
    """
    kept: list[NERMatch] = []
    rejected: list[RejectedPII] = []

    for match in matches:
      # 비정형 태그(PER·ORG·LOC 등)는 표에 없으므로 자릿수를 보지 않고 통과한다.
      low, high = STRUCTURE_DIGIT_RANGE.get(match.tag, (0, 10**6))
      digit_count = sum(character.isdigit() for character in match.text)
      if low <= digit_count <= high:
        kept.append(match)
        continue
      rejected.append(
        RejectedPII(
          tag=match.tag,
          text=match.text,
          start=match.start,
          end=match.end,
          reason="ner_structure_mismatch",
          validator="digit_count",
          source="ner",
        )
      )
      logger.debug("NER 구조 불일치로 탈락(보존): [{}] {!r}", match.tag, match.text)

    return kept, rejected

  def split_by_route(
    self,
    matches: list[NERMatch],
  ) -> tuple[list[NERMatch], list[NERMatch]]:
    """Split NER findings into direct-confirm and sLLM-review buckets."""
    route_b1 = [match for match in matches if match.is_high_f1]
    route_b2 = [match for match in matches if not match.is_high_f1]
    return route_b1, route_b2

  def is_available(self) -> bool:
    """Return whether Step 3 is usable for the current process."""
    return self.enabled and self.pipeline is not None and self.load_status == "ready"

  def get_runtime_status(
    self,
    *,
    match_count: int = 0,
    route_b1_count: int = 0,
    route_b2_count: int = 0,
    structure_rejected_count: int = 0,
  ) -> dict[str, Any]:
    """Return a serializable Step 3 runtime status snapshot."""
    return {
      "structure_rejected_count": structure_rejected_count,
      "enabled": self.enabled,
      "model_path": self.model_path,
      "resolved_model_identifier": self.resolved_model_identifier,
      # 어느 가중치로 뽑은 수치인지 산출물만 보고 답할 수 있어야 한다.
      "resolved_revision": self.resolved_revision,
      "model_source": self.model_source,
      "load_status": self.load_status,
      "error": self.error_message,
      "match_count": match_count,
      "route_b1_count": route_b1_count,
      "route_b2_count": route_b2_count,
    }
