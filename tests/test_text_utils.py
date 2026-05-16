"""rag.utils.text 의 키워드 추출 계층 테스트."""

from rag.utils.text import (
  META_STOPWORDS,
  extract_keywords,
  extract_specific_keyword,
)


class TestExtractKeywords:
  """빈도 기반 다중 키워드 추출기."""

  def test_default_stopwords_filter_korean_particles(self) -> None:
    """기본 조사/어미는 stopword 로 제거되어야 한다."""
    result = extract_keywords("개인정보는 보호되어야 한다 개인정보는 중요하다", max_keywords=2)
    # "이", "는", "다" 등은 단어 단위 매칭에서 자동 제외되며, 의미 토큰만 남는다.
    assert "개인정보는" in result or "개인정보" in " ".join(result)

  def test_extra_stopwords_block_meta_labels(self) -> None:
    """META_STOPWORDS 를 넘기면 '정상', '문서' 같은 메타 라벨이 빈도 1위에서 제거된다."""
    text = "정상 정상 정상 문서 문서 회의록 회의록 안건"
    without_meta = extract_keywords(text, max_keywords=2)
    with_meta = extract_keywords(text, max_keywords=2, extra_stopwords=META_STOPWORDS)
    # 메타 미차단 시 '정상' 이 1위로 뽑힘.
    assert "정상" in without_meta
    # 메타 차단 시 메타 토큰은 제거되고 본문 토큰이 1위로 올라온다.
    assert "정상" not in with_meta
    assert "문서" not in with_meta
    assert "회의록" in with_meta


class TestExtractSpecificKeyword:
  """R2/R4 anchor 용 계층형 단일 키워드 추출기."""

  def test_synthetic_identifier_takes_priority(self) -> None:
    """1순위: SYNTH-* 패턴이 다른 후보보다 우선한다."""
    text = (
      "이 환자의 진료 기록 ID 는 SYNTH-CLINIC-PT2024-00012 이며 "
      "김철수 환자의 처방 내역을 포함한다."
    )
    assert extract_specific_keyword(text) == "SYNTH-CLINIC-PT2024-00012"

  def test_dspro_identifier_priority(self) -> None:
    """DSPRO* 패턴도 1순위 식별자로 인식된다."""
    text = "검색 앵커: DSPROALPHA01. 이 문서는 정상 샘플이다."
    assert extract_specific_keyword(text) == "DSPROALPHA01"

  def test_pt_year_id_pattern(self) -> None:
    """PT-YYYY-NNNNN 패턴도 1순위로 잡힌다."""
    text = "최민수 환자의 진료기록번호는 PT-2024-00012 입니다."
    # 인명+직책("최민수 환자")보다 식별자가 우선.
    assert extract_specific_keyword(text) == "PT-2024-00012"

  def test_name_role_when_no_identifier(self) -> None:
    """2순위: 식별자가 없을 때 인명+직책이 잡혀야 한다."""
    text = "박영희 과장의 자택 주소는 서울특별시 광진구 능동로 209 입니다."
    result = extract_specific_keyword(text)
    assert result.startswith("박영희")
    assert "과장" in result

  def test_meta_labels_never_returned(self) -> None:
    """4순위 빈도 키워드에서도 '정상', '문서' 같은 메타 라벨은 절대 반환되지 않는다."""
    text = (
      "합성 데이터셋 안내: 이 문서는 실제 자료가 아니라 평가용 정상 문서다. "
      "운영 참고: 이 정상 문서는 온보딩 절차 안내이다. 온보딩 컬렉션 관리."
    )
    result = extract_specific_keyword(text)
    assert result not in {"정상", "문서", "안내", "합성", "데이터셋", "평가용"}

  def test_docsearch_pro_blocked_as_meta(self) -> None:
    """DocSearch Pro 는 모든 normal 문서 공통 출현이므로 메타 stopword 로 차단된다."""
    text = "DocSearch Pro 는 가상의 SaaS 이며 컬렉션 관리 기능을 제공한다. 컬렉션 컬렉션."
    result = extract_specific_keyword(text)
    assert result not in {"DocSearch", "Pro"}

  def test_filename_fallback_when_only_meta_tokens(self) -> None:
    """본문이 메타 토큰뿐이고 식별자/고유명사가 없을 때 파일명 폴백이 발동한다."""
    text = "정상 정상 문서 문서 안내 안내 합성 데이터셋"
    result = extract_specific_keyword(
      text, fallback_filename="data/clean/normal/general_01_company_intro.txt"
    )
    # 파일명 stem 에서 숫자/언더스코어 제거 후 단어가 합쳐진다.
    assert "company" in result
    assert "intro" in result

  def test_pure_fallback_when_everything_empty(self) -> None:
    """본문도 파일명도 없으면 최종 fallback 문자열을 반환한다."""
    assert extract_specific_keyword("", fallback="기본문서") == "기본문서"

  def test_real_company_intro_doc(self) -> None:
    """실제 normal/general_01_company_intro 본문에서 DSPROALPHA01 이 잡혀야 한다.

    회귀 방지: '정상' 이 1위로 뽑혀 anchor 가 무의미해지던 버그 재현 차단.
    """
    text = (
      "합성 데이터셋 안내: 이 문서는 실제 고객, 직원, 회사 자료가 아니라 "
      "DocSearch Pro 평가용 정상 문서다.\n"
      "운영 참고: 이 정상 문서는 검색 엔진이 제품 설명, 운영 절차를 이해하는지 "
      "보기 위해 충분한 배경을 담았다.\n"
      "검색 앵커: DSPROALPHA01 DSPROALPHA01. R4 membership canary: "
      "MEMCANARY-NORMAL-001."
    )
    assert extract_specific_keyword(text) == "DSPROALPHA01"
