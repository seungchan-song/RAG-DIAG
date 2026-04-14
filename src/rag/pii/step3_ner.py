"""
STEP 3: KPF-BERT NER 기반 PII 탐지 모듈

파인튜닝된 KPF-BERT 모델을 사용하여 비구조화된 PII를 탐지합니다.
정규식으로 잡을 수 없는 사람 이름, 주소, 직장명 등을 NER(Named Entity Recognition)로 탐지합니다.

핵심 개념:
  - NER: 텍스트에서 이름, 장소, 조직 등 개체명을 찾아내는 기술
  - BIO 포맷: B-태그(시작), I-태그(계속), O(비해당) 형식의 레이블링
  - KPF-BERT: 한국언론진흥재단 BERT 모델 (한국어 특화)
  - KDPII: 한국어 개인정보 데이터셋 (33종 PNE 태그)

탐지 대상 (NER 태그 중 PII 관련 주요 항목):
  - PER (사람 이름): 홍길동, 김영희
  - LOC (장소/주소): 서울특별시 광진구
  - ORG (기관/회사): 세종대학교, 삼성전자
  - DAT (날짜/생년월일): 1990년 10월 15일
  - 기타 KDPII 태그들

분기 기준 (신뢰도 + F1 점수):
  - 신뢰도 ≥ threshold(0.8) + 고F1 태그 → 경로 B-1 (즉시 확정)
  - 신뢰도 ≥ threshold(0.8) + 저F1 태그 → 경로 B-2 (STEP 4 교차검증)
  - 신뢰도 < threshold → 무시

사용 예시:
  from rag.pii.step3_ner import NERDetector

  detector = NERDetector(config)
  results = detector.detect("홍길동은 세종대학교 학생입니다.")
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from loguru import logger


@dataclass
class NERMatch:
  """
  NER 모델로 탐지된 개체 하나를 나타내는 데이터 클래스입니다.

  Attributes:
    tag: NER 태그 (예: "PER", "LOC", "ORG")
    text: 탐지된 원문 텍스트 (예: "홍길동")
    start: 원문에서의 시작 위치
    end: 원문에서의 끝 위치
    confidence: 모델의 신뢰도 점수 (0.0 ~ 1.0)
    source: 탐지 출처 ("ner" 고정)
    is_high_f1: 고F1 태그인지 여부 (True면 경로 B-1, False면 경로 B-2)
  """
  tag: str
  text: str
  start: int
  end: int
  confidence: float
  source: str = "ner"
  is_high_f1: bool = False


# NER 태그의 F1 기반 분류
# 고F1 태그: KDPII 벤치마크에서 F1이 높아 오탐이 적은 태그 → 경로 B-1 (즉시 확정)
# 저F1 태그: 오탐 가능성이 있어 sLLM 교차검증이 필요한 태그 → 경로 B-2
HIGH_F1_TAGS = {
  "QT_PHONE", "QT_MOBILE", "TMI_EMAIL", "QT_CARD", "QT_RRN",
  "QT_IP", "QT_PASSPORT", "QT_CAR", "QT_AGE",
}
LOW_F1_TAGS = {
  "PER", "LOC", "ORG", "DAT", "QT_ADDR",
  "TMI_OCCUPATION", "TMI_POLITICAL", "TMI_RELIGION",
  "TMI_HEALTH", "TMI_SEXUAL",
}


class NERDetector:
  """
  KPF-BERT 기반 NER PII 탐지기입니다.

  파인튜닝된 KPF-BERT 모델을 로드하여 텍스트에서
  비구조화된 PII(이름, 주소, 기관명 등)를 탐지합니다.
  """

  def __init__(self, config: dict[str, Any]) -> None:
    """
    NERDetector를 초기화합니다.

    모델 경로와 신뢰도 임계값을 설정에서 읽어옵니다.
    실제 모델 로드는 warm_up()에서 수행합니다 (지연 로드).

    Args:
      config: YAML에서 로드한 설정 딕셔너리.
              config["pii"]["ner"]에서 model_path, confidence_threshold를 읽습니다.
    """
    ner_config = config.get("pii", {}).get("ner", {})
    self.model_path = ner_config.get("model_path", "models/kpf-bert-kdpii")
    self.confidence_threshold = ner_config.get("confidence_threshold", 0.8)

    # 모델과 토크나이저는 warm_up()에서 로드됩니다
    self.model = None
    self.tokenizer = None
    self.pipeline = None

    logger.debug(
      f"NERDetector 초기화 완료 "
      f"(모델: {self.model_path}, 임계값: {self.confidence_threshold})"
    )

  def warm_up(self) -> None:
    """
    NER 모델과 토크나이저를 로드합니다.

    로컬 경로와 Hugging Face Hub 모델 ID를 모두 지원합니다.

    - 로컬 경로 예시: "models/kpf-bert-kdpii"
    - Hub 모델 ID 예시: "townboy/kpfbert-kdpii"

    로컬 경로인 경우 해당 디렉토리가 존재해야 합니다.
    Hub 모델 ID인 경우 최초 실행 시 자동으로 다운로드 및 캐싱됩니다.
    """
    # 로컬 경로인지 Hugging Face Hub 모델 ID인지 구분합니다.
    # Path(model_path).exists()가 True이면 로컬 경로, 아니면 Hub 모델 ID로 간주합니다.
    local_path = Path(self.model_path)
    is_local = local_path.exists()

    if is_local:
      # 로컬 경로: 파일 시스템에서 직접 로드합니다
      model_identifier = str(local_path)
      logger.info(f"로컬 모델 경로에서 NER 모델을 로드합니다: {model_identifier}")
    else:
      # Hugging Face Hub 모델 ID: 자동 다운로드 후 캐싱합니다
      # 최초 실행 시 인터넷 연결이 필요합니다 (~/.cache/huggingface에 저장)
      model_identifier = self.model_path
      logger.info(f"Hugging Face Hub에서 NER 모델을 다운로드합니다: {model_identifier}")

    try:
      # Hugging Face transformers의 pipeline을 사용합니다
      from transformers import pipeline as hf_pipeline

      # token-classification 파이프라인: 텍스트에서 NER 태그를 추출합니다
      self.pipeline = hf_pipeline(
        "token-classification",
        model=model_identifier,
        tokenizer=model_identifier,
        aggregation_strategy="simple",  # 인접 동일 태그를 합칩니다
        device=-1,  # CPU 사용 (-1=CPU, 0=GPU)
      )
      logger.info(f"NER 모델 로드 완료: {self.model_path}")

    except Exception as e:
      logger.error(f"NER 모델 로드 실패: {e}")
      self.pipeline = None

  def detect(self, text: str) -> list[NERMatch]:
    """
    텍스트에서 NER 모델로 PII를 탐지합니다.

    모델이 로드되지 않았으면 빈 목록을 반환합니다.
    신뢰도가 임계값 미만인 항목은 제외됩니다.

    Args:
      text: PII를 탐지할 원문 텍스트

    Returns:
      list[NERMatch]: 탐지된 NER 개체 목록
    """
    if self.pipeline is None:
      logger.debug("NER 모델이 로드되지 않아 STEP 3을 건너뜁니다")
      return []

    # NER 파이프라인 실행
    try:
      raw_results = self.pipeline(text)
    except Exception as e:
      logger.error(f"NER 추론 실패: {e}")
      return []

    # 결과를 NERMatch 객체로 변환합니다
    matches: list[NERMatch] = []
    for entity in raw_results:
      # entity는 {"entity_group": "PER", "score": 0.95, "word": "홍길동",
      #           "start": 0, "end": 3} 형태입니다
      confidence = float(entity.get("score", 0.0))

      # 신뢰도가 임계값 미만이면 무시합니다
      if confidence < self.confidence_threshold:
        continue

      tag = entity.get("entity_group", "O")
      is_high_f1 = tag in HIGH_F1_TAGS

      match = NERMatch(
        tag=tag,
        text=entity.get("word", ""),
        start=entity.get("start", 0),
        end=entity.get("end", 0),
        confidence=confidence,
        is_high_f1=is_high_f1,
      )
      matches.append(match)

    if matches:
      logger.debug(f"NER 탐지: {len(matches)}개 개체 발견")

    return matches

  def split_by_route(
    self, matches: list[NERMatch]
  ) -> tuple[list[NERMatch], list[NERMatch]]:
    """
    NER 결과를 경로 B-1과 B-2로 분류합니다.

    - B-1 (고F1 태그): 오탐이 적으므로 즉시 PII로 확정
    - B-2 (저F1 태그): sLLM 교차검증이 필요

    Args:
      matches: detect()에서 반환된 NERMatch 목록

    Returns:
      tuple[list[NERMatch], list[NERMatch]]:
        - route_b1: 즉시 확정할 항목들 (고F1)
        - route_b2: sLLM 검증이 필요한 항목들 (저F1)
    """
    route_b1: list[NERMatch] = []
    route_b2: list[NERMatch] = []

    for match in matches:
      if match.is_high_f1:
        route_b1.append(match)
      else:
        route_b2.append(match)

    logger.debug(
      f"NER 경로 분류: B-1={len(route_b1)}개, B-2={len(route_b2)}개"
    )
    return route_b1, route_b2
