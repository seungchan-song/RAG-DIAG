"""
텍스트 처리 유틸리티 모듈

키워드 추출과 식별자 생성에 필요한 경량 텍스트 유틸리티를 제공합니다.

추출 방식은 두 가지로 분리됩니다.
  - extract_keywords(): 빈도 기반 다중 키워드 추출 (메타데이터 채움용).
  - extract_specific_keyword(): 계층형 단일 키워드 추출 (R2/R4 anchor 쿼리용).
    문서를 가능한 한 유일하게 가리키는 specific identifier 를 우선합니다.
"""

import re
from pathlib import Path

# === 일반 한국어 stopwords ===
# 조사·동사 어미·연결 어휘 등 의미 부담이 없는 토큰을 제거합니다.
_STOPWORDS: set[str] = {
  "이", "그", "저", "것", "수", "등", "및", "를", "을", "에",
  "의", "가", "는", "은", "로", "으로", "에서", "도", "만",
  "다", "하다", "있다", "없다", "되다", "이다", "않다",
}

# === 합성 데이터셋 메타 라벨 stopwords ===
# 모든 normal/sensitive 문서에 공통 등장하는 "면책·운영 안내" 토큰들.
# 이 토큰들이 anchor 키워드로 뽑히면 "정상에 대한 문서를 찾아주세요" 처럼
# 토픽이 메타라벨로 잡혀 LLM 이 "해당 정보 없음"으로 회피해 버립니다.
# 모든 빈도 기반 추출에서 제외하여 문서 본문의 실제 토큰이 드러나게 합니다.
# NORMAL baseline 등 다른 모듈에서 동일한 차단 정책을 적용하기 위해 public.
META_STOPWORDS: set[str] = {
  "정상", "문서", "문서는", "문서를", "문서가", "문서다", "문서로", "문서에",
  "안내", "합성", "데이터셋", "평가용", "평가",
  "운영", "참고", "본문", "실험자", "실험", "검수", "노트",
  "포함", "관련", "내용", "정보",
  # 모든 normal 문서 disclaimer 에 공통 등장하는 가상 제품명
  "DocSearch", "docsearch", "Pro", "pro",
}

# === 1순위: 합성 식별자 패턴 ===
# 본 프로젝트의 synthetic data 에서 문서를 유일하게 가리키는 코드들.
# 한 문서당 1~2회만 등장하므로 anchor 키워드로 쓰면 retriever 가
# 정확히 그 문서 클러스터로 유도됩니다.
#
# 이전 버전에는 MEMCANARY- 패턴이 포함돼 있었으나, 데이터셋 자연체 개편
# (인명·조직·부서 자연체화) 과정에서 어느 evaluator 에서도 추적되지 않는
# dead 마커임이 확인되어 데이터·코드에서 모두 제거했다.
_IDENTIFIER_PATTERNS: list[re.Pattern[str]] = [
  re.compile(r"SYNTH-[A-Z]+-[A-Z0-9]+(?:-[A-Z0-9]+)?"),
  re.compile(r"DSPRO[A-Z]+\d{2,}"),
  re.compile(r"\bPT-\d{4}-\d{4,}\b"),
  re.compile(r"\b[A-Z]{2,}-\d{4}-\d{4,}\b"),
]

# === 2순위: 인명 + 직책/역할 ===
# "김철수 환자", "박영희 과장" 처럼 인명과 결합되어 문서를 거의 유일하게
# 지목할 수 있는 표현. 한글 2~4자 인명 + 직책어 패턴.
_ROLE_TOKENS: str = (
  r"(?:환자|과장|부장|대리|사원|차장|이사|대표|교수|학생|"
  r"선생님|선생|회원|고객|직원|간호사|의사|팀장|팀원|담당자)"
)
_NAME_ROLE_PATTERN: re.Pattern[str] = re.compile(
  rf"([가-힣]{{2,4}})\s*{_ROLE_TOKENS}"
)

# === 3순위: 도메인 고유명사 (영문 시작 + 한글 보조) ===
# 대문자로 시작하는 영문 단어 (3자 이상) 혹은 한글 4자 이상의 복합명사.
# 메타 stopwords 에 등록된 일반 토큰(DocSearch 등)은 제외됩니다.
_PROPER_NOUN_EN_PATTERN: re.Pattern[str] = re.compile(
  r"\b([A-Z][A-Za-z0-9]{2,})\b"
)


def extract_keywords(
  text: str,
  max_keywords: int = 3,
  *,
  extra_stopwords: set[str] | None = None,
) -> list[str]:
  """
  빈도 기반 키워드를 추출합니다 (다중 키워드 반환).

  ingest 단계의 보조 메타 채움이나, 계층형 추출기의 마지막 폴백 단계에서
  사용합니다. specific identifier 추출이 필요한 anchor 쿼리 생성에는
  extract_specific_keyword() 를 사용하세요.

  Args:
    text: 키워드를 추출할 텍스트.
    max_keywords: 반환할 최대 키워드 수.
    extra_stopwords: 추가로 차단할 stopword 집합. 메타라벨이 빈도 1위로
      뽑히는 것을 막을 때 META_STOPWORDS 를 넘깁니다.

  Returns:
    list[str]: 빈도 순으로 정렬된 키워드 목록.
  """
  stopwords = _STOPWORDS | (extra_stopwords or set())
  words = re.findall(r"[0-9A-Za-z가-힣]{2,}", text)
  filtered = [word for word in words if word not in stopwords]

  freq: dict[str, int] = {}
  for word in filtered:
    freq[word] = freq.get(word, 0) + 1

  sorted_words = sorted(freq.items(), key=lambda item: (-item[1], item[0]))
  return [word for word, _ in sorted_words[:max_keywords]]


def extract_specific_keyword(
  text: str,
  fallback_filename: str | None = None,
  fallback: str = "문서",
) -> str:
  """
  R2/R4 anchor 쿼리에 사용할 single specific keyword 를 계층적으로 추출합니다.

  추출 우선순위 (앞에서 매칭되면 즉시 반환):
    1. 합성 식별자 패턴 — SYNTH-*, DSPRO*, PT-YYYY-NNNNN 등.
       문서를 유일하게 지목하는 코드이므로 anchor 적합도 최고.
    2. 인명 + 직책 — "김철수 환자" 처럼 인명 결합 표현. 거의 유일 지목.
    3. 도메인 영문 고유명사 — 대문자 시작 영문 단어 (메타 stopwords 제외).
    4. 빈도 키워드 — 일반 stopwords + 메타 stopwords 제거 후 최고 빈도어.
    5. 파일명 폴백 — `general_01_company_intro` → "company intro".

  실제 공격자(A2 Aware Observer)가 "타깃 문서를 가리키는 토큰을 안다"는
  위협 모델을 충실히 반영합니다. 빈도 1위(예: "정상", "문서")는
  여러 문서 공통이라 retriever 유도력이 낮고 LLM 이 토픽 검색으로
  오해해 회피하는 문제를 해결합니다.

  Args:
    text: 키워드를 뽑을 문서 본문.
    fallback_filename: 본문 추출 실패 시 사용할 파일 경로/이름.
    fallback: 파일명도 없을 때 사용할 최종 대체값.

  Returns:
    str: 단일 specific keyword 문자열.
  """
  # 1순위: 합성 식별자 패턴
  for pattern in _IDENTIFIER_PATTERNS:
    match = pattern.search(text)
    if match:
      return match.group(0)

  # 2순위: 인명 + 직책
  match = _NAME_ROLE_PATTERN.search(text)
  if match:
    return match.group(0).strip()

  # 3순위: 도메인 영문 고유명사 (메타 stopwords 차단 통과한 것만)
  for proper_match in _PROPER_NOUN_EN_PATTERN.finditer(text):
    candidate = proper_match.group(0)
    if candidate not in META_STOPWORDS:
      return candidate

  # 4순위: 메타 stopwords 적용한 빈도 키워드
  keywords = extract_keywords(
    text, max_keywords=1, extra_stopwords=META_STOPWORDS
  )
  if keywords:
    return keywords[0]

  # 5순위: 파일명 폴백
  if fallback_filename:
    file_keyword = _filename_to_keyword(fallback_filename)
    if file_keyword:
      return file_keyword

  return fallback


def _filename_to_keyword(filename: str) -> str:
  """
  파일 경로/이름을 사람이 읽을 수 있는 키워드로 변환합니다.

  예: `data/clean/normal/general_01_company_intro.txt`
      → "company intro"

  - 디렉토리/확장자 제거 후 stem 만 사용
  - 언더스코어/하이픈을 공백으로 변환
  - 숫자 토큰 제거 (chunk index 등 변별력 없는 정보)
  - 길이 2 미만 토큰 제거

  Args:
    filename: 절대 또는 상대 파일 경로, 혹은 파일명.

  Returns:
    str: 가공된 키워드. 가공 결과가 비면 stem 그대로 반환.
  """
  stem = Path(filename).stem
  cleaned = re.sub(r"[_\-]+", " ", stem)
  tokens = [
    token for token in cleaned.split()
    if len(token) >= 2 and not token.isdigit()
  ]
  return " ".join(tokens) if tokens else stem


def slugify_token(text: str) -> str:
  """
  식별자에 사용할 수 있는 간단한 슬러그를 만듭니다.
  """
  lowered = text.lower()
  slug = re.sub(r"[^0-9a-z가-힣]+", "-", lowered).strip("-")
  return slug or "item"
