"""
STEP 1: 정규식 기반 PII 탐지 모듈

구조화된 형태의 개인식별정보(PII)를 정규식 패턴으로 탐지합니다.
각 패턴에는 PII 태그(예: QT_MOBILE, TMI_EMAIL)가 부여됩니다.

여기에는 **국가·업계 표준으로 형식이 정해진 것만** 넣습니다(정규식 12개 ·
아래 6번 QT_ARN 은 QT_RRN 매칭 후처리로 분기):
  1. QT_MOBILE    - 휴대전화번호 (010-XXXX-XXXX) — 이동전화 번호계획
  2. QT_PHONE     - 일반전화번호 (02-XXXX-XXXX) — 지역번호 체계
  3. TMI_EMAIL    - 이메일 주소 (user@domain.com)
  4. QT_CARD      - 신용카드번호 (16자리 + Luhn)
  5. QT_RRN       - 주민등록번호 (YYMMDD-XXXXXXX + mod 11)
  6. QT_ARN       - 외국인등록번호 (뒷자리 첫째 5~8)
  7. QT_PASSPORT  - 여권번호 (영문 1 + 숫자 8, 구형)
  8. QT_CAR       - 차량번호 (12가1234) — 등록번호판 규격
  9. QT_IP        - IP 주소 (192.168.0.1)
  10. QT_AGE      - 나이 표현 (25세, 만 30세) — 한국어 표현 패턴
  11. QT_ADDR     - 주소 (실제 광역자치단체명 + 시/군/구 + 로/길/동)
  12. ZIPCODE     - 우편번호 (5자리, "우편번호 06234" 문맥 한정)

  ⚠️ **조직별 ID(사원번호·회원 ID·참가자 ID·계정 ID)는 여기 넣지 않습니다.**
  회사마다 체계가 달라 표준 형식이라는 게 없기 때문입니다. 예전엔 우리 합성
  코퍼스의 접두사(`EMP-`·`MBR`·`PART-`·`admin_`)를 박아 뒀는데, 그러면 우리
  데이터에서만 맞고 **남의 RAG 를 진단하면 무조건 0건**이 나옵니다. 지금은
  `config` 의 `pii.custom_id_patterns` 로 배포처가 선언하며(기본 비움),
  선언이 없으면 문맥을 보는 NER(STEP 3)이 전담합니다.
  CITY(도시명)도 같은 이유로 NER 담당입니다 — "서울" 같은 맨 단어라 정규식으로
  잡으면 오탐이 폭증합니다.

동작 방식:
  - 입력 텍스트에서 각 패턴을 검색합니다
  - 매칭된 부분의 위치(start, end), 원문, 태그를 반환합니다
  - 하나의 텍스트에서 여러 종류의 PII가 동시에 탐지될 수 있습니다

사용 예시:
  from rag.pii.step1_regex import RegexDetector

  detector = RegexDetector()
  results = detector.detect("홍길동의 전화번호는 010-1234-5678입니다.")
  # → [PIIMatch(tag="QT_MOBILE", text="010-1234-5678", start=10, end=23)]
"""

import re
from dataclasses import dataclass
from typing import Any, ClassVar

from loguru import logger


@dataclass
class PIIMatch:
  """
  정규식으로 탐지된 PII 하나를 나타내는 데이터 클래스입니다.

  Attributes:
    tag: PII 유형 태그 (예: "QT_MOBILE", "TMI_EMAIL")
    text: 탐지된 원문 텍스트 (예: "010-1234-5678")
    start: 원문에서의 시작 위치 (인덱스)
    end: 원문에서의 끝 위치 (인덱스)
    source: 탐지 출처 ("regex" 고정)
    needs_validation: 체크섬 등 추가 검증이 필요한지 여부
  """
  tag: str
  text: str
  start: int
  end: int
  source: str = "regex"
  needs_validation: bool = False


# === PII 태그별 정규식 패턴 정의 ===
# 각 패턴은 (태그명, 정규식, 추가검증필요여부) 튜플로 정의합니다.
# needs_validation=True인 패턴은 STEP 2에서 체크섬 검증을 거칩니다.

@dataclass
class PIIPattern:
  """
  하나의 PII 정규식 패턴을 정의하는 데이터 클래스입니다.

  Attributes:
    tag: PII 유형 태그
    pattern: 컴파일된 정규식 패턴
    description: 이 패턴이 무엇을 탐지하는지 설명
    needs_validation: STEP 2 체크섬 검증 필요 여부
  """
  tag: str
  pattern: re.Pattern
  description: str
  needs_validation: bool = False


# === 한국어 경계: `\b` 를 쓰면 안 되는 이유 ==================================
# `\b` 는 유니코드 단어문자 기준이라 **한글도 단어문자로 본다.** 한국어는 조사가 값에
# 바로 붙으므로("203.0.113.11를", "우편번호 06234가", "EMP-2024-13579로") 값과 조사
# 사이에 단어 경계가 생기지 않아 `\b` 로 끝나는 패턴이 통째로 실패한다.
#
# 실측(2026-08-03): 우리 clean 코퍼스에서 IP 331건 중 **112건(34%)** 을 이 이유로
# 놓치고 있었다. 더 나쁜 건 `MBR1234567은` 처럼 조사가 붙으면 MEMBER_ID 가 실패해
# **D13 에서 고쳤던 여권번호 오분류(QT_PASSPORT)가 되살아난다** — 가장 위험한
# 고유식별 등급의 건수를 부풀리는 그 문제다.
#
# 그래서 경계를 ASCII 영숫자/밑줄로만 한정한다. 한글·공백·문장부호는 경계로 인정한다.
ASCII_LEFT_BOUNDARY = r"(?<![0-9A-Za-z_])"
ASCII_RIGHT_BOUNDARY = r"(?![0-9A-Za-z_])"


class RegexDetector:
  """
  정규식 기반 PII 탐지기입니다.

  내장 국가표준 패턴 11종에 배포처가 선언한 조직별 ID 패턴
  (`pii.custom_id_patterns`)을 더해 텍스트에서 개인정보를 탐지합니다.
  ⚠️ `detect()` 는 `self.PATTERNS`(내장)가 아니라 `self.patterns`(내장+조직별)를 순회한다.
  탐지된 각 항목은 PIIMatch 객체로 반환됩니다.
  """

  # 클래스 변수: 모든 PII 패턴 목록
  # ClassVar로 선언하여 인스턴스가 아닌 클래스에 속하게 합니다
  PATTERNS: ClassVar[list[PIIPattern]] = [
    # === 1. 휴대전화번호 ===
    # 010-1234-5678, 010.1234.5678, 01012345678 등
    PIIPattern(
      tag="QT_MOBILE",
      pattern=re.compile(
        ASCII_LEFT_BOUNDARY
        + r"01[016789]"        # 010, 011, 016, 017, 018, 019
        + r"[-.\s]?"           # 구분자: 하이픈, 점, 공백 (선택)
        + r"\d{3,4}"           # 중간 3~4자리
        + r"[-.\s]?"           # 구분자 (선택)
        + r"\d{4}"             # 끝 4자리
        + ASCII_RIGHT_BOUNDARY
      ),
      description="휴대전화번호 (010-XXXX-XXXX 등)",
    ),

    # === 2. 일반전화번호 ===
    # 02-1234-5678, 031-123-4567, 042-123-4567 등
    # ⚠️ 경계가 없으면 이 패턴이 **주민등록번호 앞부분을 삼킨다.**
    # `051109-3345671`(2002~2006년생) 에서 `051109-3345` 를 일반전화로 매칭해,
    # 겹침 해소에서 온전한 QT_RRN 을 밀어내고 고유식별 → 연락처로 등급을 낮췄다.
    # 경계를 붙이면 매치가 숫자 중간에서 끝날 수 없어 이 조합 자체가 성립하지 않는다.
    PIIPattern(
      tag="QT_PHONE",
      pattern=re.compile(
        ASCII_LEFT_BOUNDARY
        + r"0[2-6][1-5]?"      # 지역번호 (02, 031, 042 등)
        + r"[-.\s]?"
        + r"\d{3,4}"
        + r"[-.\s]?"
        + r"\d{4}"
        + ASCII_RIGHT_BOUNDARY
      ),
      description="일반전화번호 (02-XXXX-XXXX, 031-XXX-XXXX 등)",
    ),

    # === 3. 이메일 주소 ===
    # user@domain.com, test.email@company.co.kr 등
    PIIPattern(
      tag="TMI_EMAIL",
      pattern=re.compile(
        r"[a-zA-Z0-9._%+\-]+"  # 로컬 파트 (user.name 등)
        r"@"                    # @ 기호
        r"[a-zA-Z0-9.\-]+"     # 도메인 (company.co)
        r"\.[a-zA-Z]{2,}"      # 최상위 도메인 (.com, .kr 등)
      ),
      description="이메일 주소",
    ),

    # === 4. 신용카드번호 ===
    # 4532-1234-5678-9012, 4532123456789012 등 (16자리)
    # needs_validation=True → STEP 2에서 Luhn 알고리즘으로 검증
    # 경계가 없으면 20자리 계좌번호 같은 긴 숫자열의 **앞 16자리만** 카드번호로
    # 집어가 Luhn 탈락 → rejection 채널을 오염시킨다.
    PIIPattern(
      tag="QT_CARD",
      pattern=re.compile(
        ASCII_LEFT_BOUNDARY
        + r"\d{4}"             # 앞 4자리
        + r"[-.\s]?"
        + r"\d{4}"
        + r"[-.\s]?"
        + r"\d{4}"
        + r"[-.\s]?"
        + r"\d{4}"             # 끝 4자리
        + ASCII_RIGHT_BOUNDARY
      ),
      description="신용카드번호 (16자리)",
      needs_validation=True,
    ),

    # === 5. 주민등록번호 ===
    # 900101-1234567 (13자리, 하이픈 포함)
    # needs_validation=True → STEP 2에서 mod 11 체크섬으로 검증
    # 뒷자리 첫째 1~4이면 주민등록번호(RRN), 5~8이면 외국인등록번호(ARN)
    PIIPattern(
      tag="QT_RRN",
      pattern=re.compile(
        ASCII_LEFT_BOUNDARY
        + r"\d{2}"             # 출생년도 뒤 2자리 (90)
        + r"[01]\d"            # 출생월 (01~12)
        + r"[0-3]\d"           # 출생일 (01~31)
        + r"[-.\s]?"           # 구분자
        + r"[1-8]"             # 성별/외국인 코드 (1~8)
        + r"\d{6}"             # 나머지 6자리
        + ASCII_RIGHT_BOUNDARY
      ),
      description="주민등록번호 또는 외국인등록번호 (13자리)",
      needs_validation=True,
    ),

    # === 6. 여권번호 ===
    # M12345678, S99585004 등 — 대한민국 여권번호는 **영문 1글자 + 숫자 8자리**다.
    #
    # 이전 패턴 `[A-Z]{1,2}\d{7,8}` 은 근거 없이 넓혀 놓은 것이라 두 방향으로 틀렸다.
    #   · 너무 헐렁: `MBR1234567` 의 뒤 9글자를 `BR1234567` 여권번호로 집어가
    #     고유식별 등급 건수를 부풀렸다. MEMBER_ID 정규식이 사실상 이 오탐을
    #     막는 방패로 존재해 왔다(D13). 영문 1글자로 좁히면 방패가 필요 없다.
    #   · 너무 좁음: 2021년 이후 신형 여권은 숫자 사이에 영문이 섞인다
    #     (`M303C0624`). 이건 임의 영숫자 코드와 구조상 구분이 불가능해
    #     정규식으로 잡으려 하면 오탐이 폭증한다 → **NER 에 맡긴다**
    #     (실측: 팀원 데이터셋 48건 중 정규식 21건 / NER 48건 전량 탐지).
    PIIPattern(
      tag="QT_PASSPORT",
      pattern=re.compile(
        ASCII_LEFT_BOUNDARY
        + r"[A-Z]"            # 영문 대문자 1자리 (여권 종류: M/S/R/D/O 등)
        + r"\d{8}"            # 숫자 8자리
        + ASCII_RIGHT_BOUNDARY
      ),
      description="여권번호 (영문 1자리 + 숫자 8자리, 구형)",
    ),

    # === 7. 차량번호 ===
    # 12가1234, 서울12가1234 등
    PIIPattern(
      tag="QT_CAR",
      pattern=re.compile(
        r"(?:[가-힣]{2})?"     # 지역명 (선택): 서울, 경기 등
        r"\s?"
        r"\d{2,3}"             # 숫자 2~3자리
        r"\s?"
        r"[가-힣]"             # 한글 1글자 (가, 나, 다 ...)
        r"\s?"
        r"\d{4}"               # 숫자 4자리
      ),
      description="차량번호 (12가1234, 서울12가1234 등)",
    ),

    # === 8. IP 주소 ===
    # 192.168.0.1, 10.0.0.1 등 (IPv4)
    PIIPattern(
      tag="QT_IP",
      pattern=re.compile(
        ASCII_LEFT_BOUNDARY
        + r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"  # 앞 3개 옥텟
        + r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"           # 마지막 옥텟
        + ASCII_RIGHT_BOUNDARY
      ),
      description="IP 주소 (IPv4)",
    ),

    # === 9. 나이 표현 ===
    # 25세, 만 30세, 만30세 등
    PIIPattern(
      tag="QT_AGE",
      pattern=re.compile(
        r"만?\s?\d{1,3}세"     # "만" (선택) + 숫자 + "세"
      ),
      description="나이 표현 (25세, 만 30세 등)",
    ),

    # === 10. 주소 (도로명) ===
    # "서울특별시 광진구 능동로 209" 등
    PIIPattern(
      tag="QT_ADDR",
      pattern=re.compile(
        r"(?:"
        r"서울|부산|대구|인천|광주|대전|울산|세종|"  # 광역시/특별시
        r"경기|강원|충북|충남|전북|전남|경북|경남|제주"  # 도
        r")"
        r"(?:특별시|광역시|특별자치시|특별자치도|도)?"
        r"\s?"
        r"[가-힣]{1,4}"       # 시/군/구
        r"(?:시|군|구)"
        r"\s?"
        r"[가-힣0-9\s]{1,20}" # 도로명/동/읍/면 등
        r"(?:로|길|동|읍|면|리)"
        r"\s?"
        r"\d{1,5}"            # 번지/건물번호
      ),
      description="도로명/지번 주소",
    ),

    # === 11. 우편번호 (신규 33종) ===
    # 맨 5자리 숫자는 금액·수량과 구분되지 않으므로 '우편번호' 라벨 뒤에서만 잡는다.
    # ponytail: 고정폭 lookbehind 라 "우편번호: 06234"(콜론) 형태는 놓친다.
    #           코퍼스가 "우편번호 06234" 한 가지 형식만 쓰므로 지금은 충분하고,
    #           다른 표기가 나오면 라벨 부분까지 매칭에 포함시키는 쪽으로 넓힌다.
    PIIPattern(
      tag="ZIPCODE",
      pattern=re.compile(r"(?<=우편번호\s)\d{5}" + ASCII_RIGHT_BOUNDARY),
      description="우편번호 (5자리, '우편번호' 문맥 한정)",
    ),

  ]

  def __init__(self, config: dict[str, Any] | None = None) -> None:
    """
    내장 표준 패턴에 조직별 ID 패턴(`pii.custom_id_patterns`)을 얹어 초기화한다.

    사원번호·회원 ID·참가자 ID·계정 ID 는 **조직마다 체계가 달라 국가 표준이
    없다.** 예전엔 우리 합성 코퍼스의 접두사(`EMP-`·`MBR`·`PART-`·`admin_`)를
    코드에 박아 뒀는데, 그건 우리 데이터에서만 맞고 남의 RAG 를 진단하면
    **무조건 0건**이 나온다. 이 도구의 목적이 남의 RAG 진단이므로 그런 값은
    코드가 아니라 배포처 설정에 있어야 한다.

    기본값은 비어 있다 — 아무것도 선언하지 않으면 ID 류는 문맥을 보는 NER 이
    전담한다. 우리 코퍼스용 패턴은 `config/default.yaml` 에만 선언돼 있다.

    Args:
      config: 전체 설정 딕셔너리. `pii.custom_id_patterns` 를 {태그: 정규식}
        형태로 읽는다. None 이면 내장 표준 패턴만 사용한다.
    """
    self.patterns: list[PIIPattern] = list(self.PATTERNS)

    custom = ((config or {}).get("pii", {}) or {}).get("custom_id_patterns", {}) or {}
    for tag, expression in custom.items():
      try:
        compiled = re.compile(
          ASCII_LEFT_BOUNDARY + f"(?:{expression})" + ASCII_RIGHT_BOUNDARY
        )
      except re.error as error:
        # 설정 오타로 전체 파이프라인이 죽으면 안 된다. 해당 항목만 건너뛴다.
        logger.warning("custom_id_patterns[{}] 정규식 오류로 건너뜁니다: {}", tag, error)
        continue
      self.patterns.append(
        PIIPattern(tag=str(tag), pattern=compiled, description=f"조직별 ID 패턴 ({tag})")
      )

    if custom:
      logger.debug("조직별 ID 패턴 {}종 적용: {}", len(custom), sorted(custom))

  def detect(self, text: str) -> list[PIIMatch]:
    """
    텍스트에서 정규식 패턴으로 PII를 탐지합니다.

    모든 패턴을 순회하며 매칭되는 모든 PII를 찾아 반환합니다.
    하나의 텍스트에서 여러 종류의 PII가 동시에 탐지될 수 있습니다.

    Args:
      text: PII를 탐지할 원문 텍스트

    Returns:
      list[PIIMatch]: 탐지된 PII 목록.
        각 항목에는 태그, 원문, 위치, 검증 필요 여부가 포함됩니다.
    """
    matches: list[PIIMatch] = []

    for pii_pattern in self.patterns:
      # 정규식으로 텍스트에서 모든 매칭을 찾습니다
      for match in pii_pattern.pattern.finditer(text):
        pii_match = PIIMatch(
          tag=pii_pattern.tag,
          text=match.group(),
          start=match.start(),
          end=match.end(),
          needs_validation=pii_pattern.needs_validation,
        )
        matches.append(pii_match)

    # 주민등록번호(QT_RRN)의 뒷자리 첫째가 5~8이면 외국인등록번호(QT_ARN)로 태그 변경
    for m in matches:
      if m.tag == "QT_RRN":
        # 하이픈/공백/점을 제거한 순수 숫자에서 7번째 자리(뒷자리 첫째) 확인
        digits = re.sub(r"[-.\s]", "", m.text)
        if len(digits) == 13 and digits[6] in "5678":
          m.tag = "QT_ARN"

    if matches:
      logger.debug(f"정규식 탐지: {len(matches)}개 PII 발견")

    return matches

  def detect_with_summary(self, text: str) -> dict:
    """
    PII 탐지 결과를 태그별로 요약하여 반환합니다.

    Args:
      text: PII를 탐지할 원문 텍스트

    Returns:
      dict: 탐지 결과 요약
        - "matches": PIIMatch 목록
        - "summary": 태그별 탐지 건수 (예: {"QT_MOBILE": 2, "TMI_EMAIL": 1})
        - "total": 전체 탐지 건수
    """
    matches = self.detect(text)

    # 태그별 건수를 집계합니다
    summary: dict[str, int] = {}
    for m in matches:
      summary[m.tag] = summary.get(m.tag, 0) + 1

    return {
      "matches": matches,
      "summary": summary,
      "total": len(matches),
    }
