"""
텍스트 처리 유틸리티 모듈

키워드 추출과 식별자 생성에 필요한 경량 텍스트 유틸리티를 제공합니다.
"""

import re

_STOPWORDS = {
  "이", "그", "저", "것", "수", "등", "및", "를", "을", "에",
  "의", "가", "는", "은", "로", "으로", "에서", "도", "만",
  "다", "하다", "있다", "없다", "되다", "이다", "않다",
}


def extract_keywords(text: str, max_keywords: int = 3) -> list[str]:
  """
  텍스트에서 핵심 키워드를 추출합니다.

  현재는 경량 빈도 기반 추출기를 사용하며,
  공격 쿼리 생성과 ingest 메타데이터 보강에 공통으로 사용합니다.
  """
  words = re.findall(r"[0-9A-Za-z가-힣]{2,}", text)
  filtered = [word for word in words if word not in _STOPWORDS]

  freq: dict[str, int] = {}
  for word in filtered:
    freq[word] = freq.get(word, 0) + 1

  sorted_words = sorted(freq.items(), key=lambda item: (-item[1], item[0]))
  return [word for word, _ in sorted_words[:max_keywords]]


def slugify_token(text: str) -> str:
  """
  식별자에 사용할 수 있는 간단한 슬러그를 만듭니다.
  """
  lowered = text.lower()
  slug = re.sub(r"[^0-9a-z가-힣]+", "-", lowered).strip("-")
  return slug or "item"
