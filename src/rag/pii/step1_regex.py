"""
STEP 1: 정규식 기반 PII 탐지 모듈

구조화된 형태의 개인식별정보(PII)를 정규식 패턴으로 탐지합니다.
각 패턴에는 PII 태그(예: QT_MOBILE, TMI_EMAIL)가 부여됩니다.

탐지 대상 (11개 패턴):
  1. QT_MOBILE    - 휴대전화번호 (010-XXXX-XXXX)
  2. QT_PHONE     - 일반전화번호 (02-XXXX-XXXX, 031-XXX-XXXX)
  3. TMI_EMAIL    - 이메일 주소 (user@domain.com)
  4. QT_CARD      - 신용카드번호 (XXXX-XXXX-XXXX-XXXX)
  5. QT_RRN       - 주민등록번호 (YYMMDD-XXXXXXX)
  6. QT_ARN       - 외국인등록번호 (YYMMDD-XXXXXXX, 뒷자리 5~8)
  7. QT_PASSPORT  - 여권번호 (M12345678)
  8. QT_CAR       - 차량번호 (12가1234, 서울12가1234)
  9. QT_IP        - IP 주소 (192.168.0.1)
  10. QT_AGE      - 나이 표현 (25세, 만 30세)
  11. QT_ADDR     - 주소 패턴 (서울특별시 ..., ...로 123)

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
from typing import ClassVar

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


class RegexDetector:
  """
  정규식 기반 PII 탐지기입니다.

  11개의 한국형 PII 패턴을 사용하여 텍스트에서 개인정보를 탐지합니다.
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
        r"01[016789]"          # 010, 011, 016, 017, 018, 019
        r"[-.\s]?"             # 구분자: 하이픈, 점, 공백 (선택)
        r"\d{3,4}"             # 중간 3~4자리
        r"[-.\s]?"             # 구분자 (선택)
        r"\d{4}"               # 끝 4자리
      ),
      description="휴대전화번호 (010-XXXX-XXXX 등)",
    ),

    # === 2. 일반전화번호 ===
    # 02-1234-5678, 031-123-4567, 042-123-4567 등
    PIIPattern(
      tag="QT_PHONE",
      pattern=re.compile(
        r"0[2-6][1-5]?"        # 지역번호 (02, 031, 042 등)
        r"[-.\s]?"
        r"\d{3,4}"
        r"[-.\s]?"
        r"\d{4}"
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
    PIIPattern(
      tag="QT_CARD",
      pattern=re.compile(
        r"\d{4}"               # 앞 4자리
        r"[-.\s]?"
        r"\d{4}"
        r"[-.\s]?"
        r"\d{4}"
        r"[-.\s]?"
        r"\d{4}"               # 끝 4자리
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
        r"\d{2}"               # 출생년도 뒤 2자리 (90)
        r"[01]\d"              # 출생월 (01~12)
        r"[0-3]\d"             # 출생일 (01~31)
        r"[-.\s]?"             # 구분자
        r"[1-8]"               # 성별/외국인 코드 (1~8)
        r"\d{6}"               # 나머지 6자리
      ),
      description="주민등록번호 또는 외국인등록번호 (13자리)",
      needs_validation=True,
    ),

    # === 6. 여권번호 ===
    # M12345678, S12345678 등 (영문 1~2자리 + 숫자 7~8자리)
    PIIPattern(
      tag="QT_PASSPORT",
      pattern=re.compile(
        r"[A-Z]{1,2}"         # 영문 대문자 1~2자리
        r"\d{7,8}"            # 숫자 7~8자리
      ),
      description="여권번호 (영문+숫자)",
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
        r"\b"
        r"(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"  # 앞 3개 옥텟
        r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"            # 마지막 옥텟
        r"\b"
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

  ]

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

    for pii_pattern in self.PATTERNS:
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
