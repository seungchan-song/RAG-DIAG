"""
한국어 ROUGE-L 스코어러 모듈

기본 rouge_score 라이브러리는 영문 알파벳만 토크나이즈하므로
한국어 텍스트에 대해 ROUGE-L 점수가 항상 0이 됩니다.

이 모듈은 한국어를 공백+문자 단위로 토크나이즈하는
커스텀 토크나이저를 적용한 RougeScorer를 제공합니다.

토크나이즈 방식:
  - 공백 기준으로 1차 분할
  - 각 토큰을 그대로 사용 (한국어 형태소 분석 없이)
  - 빈 토큰 제거

사용 예시:
  from rag.evaluator.korean_tokenizer import create_korean_scorer
  scorer = create_korean_scorer()
  scores = scorer.score("타깃 문서 내용", "응답 내용")
"""


from rouge_score import rouge_scorer, tokenizers


class KoreanTokenizer(tokenizers.Tokenizer):
  """
  한국어를 처리할 수 있는 ROUGE 토크나이저입니다.

  기본 DefaultTokenizer는 [a-z] 범위만 토큰으로 인식하여
  한국어가 모두 무시됩니다. 이 토크나이저는 공백 기준으로
  분할하여 한국어 토큰을 올바르게 반환합니다.
  """

  def tokenize(self, text: str) -> list[str]:
    """
    텍스트를 공백 기준으로 토크나이즈합니다.

    소문자 변환 후 공백으로 분할하고,
    빈 토큰은 제거합니다.

    Args:
      text: 토크나이즈할 텍스트

    Returns:
      list[str]: 토큰 리스트
    """
    # 소문자 변환 (영문 혼용 시 대소문자 통일)
    text = text.lower()
    # 공백 기준 분할, 빈 토큰 제거
    tokens = [t for t in text.split() if t.strip()]
    return tokens


def create_korean_scorer() -> rouge_scorer.RougeScorer:
  """
  한국어를 지원하는 RougeScorer를 생성합니다.

  Returns:
    RougeScorer: 한국어 토크나이저가 적용된 ROUGE-L 스코어러
  """
  scorer = rouge_scorer.RougeScorer(
    ["rougeL"], use_stemmer=False, tokenizer=KoreanTokenizer()
  )
  return scorer
