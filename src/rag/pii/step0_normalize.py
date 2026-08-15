"""
STEP 0: 변형(evasion) PII 정규화 모듈

공격자는 전각 문자·호모글리프·자모 분리·문자 사이 공백 삽입 등으로 PII 를
'변형'해 정규식(STEP 1)과 NER(STEP 3)을 동시에 빠져나가게 만든다. 예를 들어
휴대폰 번호 "010-1234-5678" 을 전각으로 "０１０－１２３４－５６７８" 라고 쓰면
정규식이 매칭하지 못한다. 본 모듈은 탐지 '이전'에 텍스트를 표준 형태로 되돌려
downstream 탐지기가 다시 잡을 수 있게 한다.

핵심 설계 — 오프셋 정렬(offset alignment):
  마스킹(masker)과 STEP 4 문맥 추출은 모두 '원문'의 start/end 인덱스를 사용한다.
  따라서 정규화로 문자열 길이가 바뀌어도(공백 제거·자모 결합 등) 정규화된 텍스트에서
  찾은 스팬을 다시 '원문 좌표'로 되돌릴 수 있어야 한다. 이를 위해 정규화 결과는
  normalized_text 와 함께 "정규화 문자 i → 원문 [start, end)" 매핑(char_spans)을 돌려준다.

적용 변환(현재 v1):
  1. invisible : 제로폭·보이지 않는 문자 제거 (ZWSP/ZWNJ/ZWJ/BOM/soft-hyphen 등)
  2. compat    : 유니코드 호환 폴딩(NFKC) — 전각→반각 등 (１→1, －→-, ＠→@, 　→ 공백)
  3. homoglyph : 라틴/키릴/그리스 등 시각적 유사 문자 → 표준 문자
  4. jamo      : 분리된 한글 호환 자모(ㅎㅗㅇ) 를 음절(홍)로 결합
  5. digit_sep : 영숫자 '사이' 공백 제거 (0 1 0 → 010, y a n g @ … → yang@…).
                 오탐 방지를 위해 규칙적인 공백열이 충분히 길 때만 동작한다.
                 (이름은 evasion_kinds 어휘와 1:1 이라 'digit_sep' 을 유지하지만,
                  실제 대상은 숫자에 한정되지 않는다.)

보류(문서화된 한계):
  - 역순/순서변형 복원: 단조(monotonic) 오프셋 정렬이 깨지고 오탐 위험이 커,
    추론 단계 복원 대상에서 제외한다. (우회 데이터 '생성'은 B-3 에서 별도 처리)
  - NFD 로 분해된 결합형(conjoining) 자모(U+1100 계열): 타이핑 우회에서 드물어 v1 미지원.

사용 예시:
  from rag.pii.step0_normalize import TextNormalizer

  normalizer = TextNormalizer(config)
  result = normalizer.normalize("연락처 ０１０－１２３４－５６７８")
  result.normalized_text        # "연락처 010-1234-5678"
  result.to_original_span(4, 17) # 정규화 스팬 → 원문 (start, end)
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass, field

from loguru import logger

# 제거 대상: 제로폭·보이지 않는 문자
# 거의 언제나 우회용이거나 의미 없는 잡음이므로 전역 제거해도 안전하다.
_INVISIBLE_CHARS: frozenset[str] = frozenset(
  {
    "​",  # ZERO WIDTH SPACE
    "‌",  # ZERO WIDTH NON-JOINER
    "‍",  # ZERO WIDTH JOINER
    "⁠",  # WORD JOINER
    "﻿",  # ZERO WIDTH NO-BREAK SPACE (BOM)
    "­",  # SOFT HYPHEN
    "᠎",  # MONGOLIAN VOWEL SEPARATOR
    "‎",  # LEFT-TO-RIGHT MARK
    "‏",  # RIGHT-TO-LEFT MARK
    "‪",  # LEFT-TO-RIGHT EMBEDDING
    "‫",  # RIGHT-TO-LEFT EMBEDDING
    "‬",  # POP DIRECTIONAL FORMATTING
    "‭",  # LEFT-TO-RIGHT OVERRIDE
    "‮",  # RIGHT-TO-LEFT OVERRIDE
  }
)

# 호모글리프(시각적 유사 문자) → 표준 문자
# 전각은 NFKC 가 처리하므로, 여기서는 NFKC 로 접히지 않는 키릴/그리스 계열 위주로 둔다.
# 이메일/도메인 우회(예: 키릴 'а' 를 라틴 'a' 로 위장)에 특히 유효하다.
_HOMOGLYPH_MAP: dict[str, str] = {
  # 키릴 소문자
  "а": "a",
  "е": "e",
  "о": "o",
  "р": "p",
  "с": "c",
  "у": "y",
  "х": "x",
  "і": "i",
  "к": "k",
  "м": "m",
  "т": "t",
  "н": "h",
  "в": "b",
  # 키릴 대문자
  "А": "A",
  "Е": "E",
  "О": "O",
  "Р": "P",
  "С": "C",
  "Т": "T",
  "Х": "X",
  "В": "B",
  "Н": "H",
  "М": "M",
  "К": "K",
  # 그리스
  "ο": "o",
  "α": "a",
  "Α": "A",
  "Ο": "O",
}

# 한글 호환 자모 결합용 테이블
# 사용자가 한글 키보드로 입력하는 '자소 분리' 우회는 호환 자모(U+3131~U+3163)를 쓴다.
# 초성/중성/종성 순서로 결합해 완성형 음절(U+AC00~)을 만든다.
_CHOSEONG = "ㄱㄲㄴㄷㄸㄹㅁㅂㅃㅅㅆㅇㅈㅉㅊㅋㅌㅍㅎ"
_JUNGSEONG = "ㅏㅐㅑㅒㅓㅔㅕㅖㅗㅘㅙㅚㅛㅜㅝㅞㅟㅠㅡㅢㅣ"
# 종성은 index 0(받침 없음)을 위해 맨 앞에 공백 placeholder 를 둔다.
_JONGSEONG = " ㄱㄲㄳㄴㄵㄶㄷㄹㄺㄻㄼㄽㄾㄿㅀㅁㅂㅄㅅㅆㅇㅈㅊㅋㅌㅍㅎ"

_L_INDEX: dict[str, int] = {ch: idx for idx, ch in enumerate(_CHOSEONG)}
_V_INDEX: dict[str, int] = {ch: idx for idx, ch in enumerate(_JUNGSEONG)}
_T_INDEX: dict[str, int] = {ch: idx for idx, ch in enumerate(_JONGSEONG) if idx > 0}

_HANGUL_BASE = 0xAC00

# 글자 사이 공백 제거 시 '구분자'로 간주할 문자(공백류만).
_INTRA_DIGIT_WS = frozenset({" ", "\t"})
# 공백이 낀 '런'을 구성할 수 있는 문자 — 식별자(이메일·전화·카드·사번)를 이루는 영숫자와
# 그 구분자들. 한글·괄호·슬래시는 일부러 뺐다: 이들이 런을 끊어 줘야 "3 년 9 개월",
# "8 5 / 1 0 0" 같은 정상 표기가 붙지 않는다.
_RUN_CHARS = frozenset("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@._+-")

# 하나의 (문자, 원문시작, 원문끝) 토큰. 변환 파이프라인이 이 리스트를 순차 가공한다.
_Token = tuple[str, int, int]


@dataclass
class NormalizationResult:
  """
  STEP 0 정규화 결과.

  Attributes:
    normalized_text: 정규화된 텍스트. downstream 탐지기는 이 텍스트에서 PII 를 찾는다.
    char_spans: normalized_text 의 각 문자 i 가 원문에서 차지하던 [start, end) 범위.
      len(char_spans) == len(normalized_text) 를 보장한다.
    applied: 실제로 변화를 만든 변환 이름 목록(예: ["compat", "digit_sep"]).
    original_text: 원문(참조·폴백용).
  """

  normalized_text: str
  char_spans: list[tuple[int, int]]
  applied: list[str] = field(default_factory=list)
  original_text: str = ""

  @property
  def changed(self) -> bool:
    """정규화로 텍스트가 바뀌었는지 여부."""
    return self.normalized_text != self.original_text

  def to_original_span(self, norm_start: int, norm_end: int) -> tuple[int, int]:
    """
    정규화 텍스트의 [norm_start, norm_end) 스팬을 원문 좌표로 되돌린다.

    마스킹은 원문에서 이루어지므로, 정규화된 텍스트에서 찾은 PII 위치를 원문의
    어느 구간에 대응시킬지 계산한다. 정규화가 없었으면(char_spans 항등) 입력을 그대로
    반환한다.

    Args:
      norm_start: 정규화 텍스트에서의 시작 인덱스
      norm_end: 정규화 텍스트에서의 끝 인덱스(exclusive)

    Returns:
      tuple[int, int]: 원문에서의 (start, end)
    """
    span_count = len(self.char_spans)
    if span_count == 0:
      return (norm_start, norm_end)

    start = max(0, norm_start)
    end = min(norm_end, span_count)
    if end <= start:
      # 빈 스팬: 인접 위치의 원문 시작점을 반환한다.
      idx = min(start, span_count - 1)
      pos = self.char_spans[idx][0]
      return (pos, pos)

    original_start = self.char_spans[start][0]
    original_end = self.char_spans[end - 1][1]
    return (original_start, original_end)


class TextNormalizer:
  """
  STEP 0 변형 PII 정규화기.

  탐지 이전에 텍스트를 표준 형태로 되돌려, 전각·호모글리프·자모분리·공백삽입으로
  변형된 PII 를 downstream 탐지기(STEP 1 정규식, STEP 3 NER)가 다시 잡게 한다.
  """

  def __init__(self, config: dict[str, object]) -> None:
    """
    설정에서 STEP 0 옵션을 읽어 정규화기를 초기화한다.

    주요 설정 키:
      - pii.runtime.enable_step0: STEP 0 활성화 여부(기본 True)
      - pii.normalize.digit_spacing_min_run: 글자 사이 공백 제거를 유발하는
        규칙적 공백열의 최소 글자 개수(기본 5, 오탐 방지용 · 벤치마크로 재산정 대상)
    """
    pii_config = config.get("pii", {}) if isinstance(config, dict) else {}
    runtime_config = pii_config.get("runtime", {}) if isinstance(pii_config, dict) else {}
    normalize_config = pii_config.get("normalize", {}) if isinstance(pii_config, dict) else {}

    self.enabled = bool(runtime_config.get("enable_step0", True))
    # 주의: 임계값 성격의 값은 하드코딩이 아니라 향후 벤치마크로 재산정한다(노션 B-2 경고).
    self.digit_spacing_min_run = max(2, int(normalize_config.get("digit_spacing_min_run", 5)))

  def normalize(self, text: str) -> NormalizationResult:
    """
    텍스트를 정규화하고, 원문 좌표로 되돌릴 수 있는 매핑과 함께 반환한다.

    STEP 0 가 비활성이면 항등 결과(원문 그대로 + 항등 매핑)를 돌려주므로 호출부는
    분기 없이 항상 동일하게 사용할 수 있다.

    Returns:
      NormalizationResult: 정규화 텍스트 + 문자별 원문 스팬 + 적용된 변환 목록
    """
    if not self.enabled or not text:
      return NormalizationResult(
        normalized_text=text,
        char_spans=[(i, i + 1) for i in range(len(text))],
        applied=[],
        original_text=text,
      )

    tokens: list[_Token] = [(ch, i, i + 1) for i, ch in enumerate(text)]
    applied: list[str] = []

    tokens, changed = self._remove_invisible(tokens)
    if changed:
      applied.append("invisible")

    tokens, changed = self._fold_compat(tokens)
    if changed:
      applied.append("compat")

    tokens, changed = self._fold_homoglyph(tokens)
    if changed:
      applied.append("homoglyph")

    tokens, changed = self._compose_jamo(tokens)
    if changed:
      applied.append("jamo")

    # 글자 사이 공백 제거는 '충분히 긴 규칙적 공백열'이라는 단일 게이트로만 발동한다.
    # (예전에는 `bool(applied) or ...` 로 다른 변형이 하나라도 있으면 임계값을 통째로
    #  무시했는데, 그러면 "ㅎㅗㅇ 8 0" 같은 입력에서 2자리 숫자 공백까지 붙어버렸다.)
    tokens, changed = self._strip_spaced_run_ws(tokens)
    if changed:
      applied.append("digit_sep")

    normalized_text = "".join(token[0] for token in tokens)
    char_spans = [(token[1], token[2]) for token in tokens]

    result = NormalizationResult(
      normalized_text=normalized_text,
      char_spans=char_spans,
      applied=applied,
      original_text=text,
    )
    if result.changed:
      logger.debug("STEP 0 정규화 적용: {} (len {} → {})", applied, len(text), len(normalized_text))
    return result

  # 아래는 개별 변환들. 전부 list[_Token] 을 받아 (list[_Token], changed) 를 돌려준다.

  def _remove_invisible(self, tokens: list[_Token]) -> tuple[list[_Token], bool]:
    """제로폭·보이지 않는 문자 토큰을 제거한다."""
    output = [token for token in tokens if token[0] not in _INVISIBLE_CHARS]
    return output, len(output) != len(tokens)

  def _fold_compat(self, tokens: list[_Token]) -> tuple[list[_Token], bool]:
    """
    유니코드 호환 폴딩(NFKC)을 문자 단위로 적용한다.

    전각 숫자/영문/기호(１ Ａ ＠ －)와 전각 공백(　)을 반각으로 접는다. 오탐을 막기 위해
    결과가 ASCII 이고 2글자 이하인 경우에만 접는다(예: ℡→TEL 같은 과도한 확장은 배제).
    한 문자가 여러 문자로 접히면 각 결과 문자에 동일한 원문 스팬을 부여한다.
    """
    output: list[_Token] = []
    changed = False
    for ch, start, end in tokens:
      if ch.isascii():
        output.append((ch, start, end))
        continue
      folded = unicodedata.normalize("NFKC", ch)
      if folded != ch and folded.isascii() and len(folded) <= 2:
        for folded_char in folded:
          output.append((folded_char, start, end))
        changed = True
      else:
        output.append((ch, start, end))
    return output, changed

  def _fold_homoglyph(self, tokens: list[_Token]) -> tuple[list[_Token], bool]:
    """시각적 유사 문자(키릴/그리스 등)를 표준 문자로 1:1 치환한다."""
    output: list[_Token] = []
    changed = False
    for ch, start, end in tokens:
      replacement = _HOMOGLYPH_MAP.get(ch)
      if replacement is not None:
        output.append((replacement, start, end))
        changed = True
      else:
        output.append((ch, start, end))
    return output, changed

  def _compose_jamo(self, tokens: list[_Token]) -> tuple[list[_Token], bool]:
    """
    분리된 한글 호환 자모를 완성형 음절로 결합한다.

    초성(L)+중성(V)[+종성(T)] 순서를 그리디하게 인식해 결합한다. 종성 후보 뒤에
    '자음+모음'이 이어지면 그 자음은 다음 음절의 초성으로 보고 종성으로 취하지 않는다.
    (예: "ㅎㅗㅇㄱㅣㄹ..." 에서 두 번째 ㄱ 은 '길'의 초성) 모음이 없는 자음 나열
    (예: "ㅋㅋㅋ", "ㅠㅠ")은 결합되지 않으므로 흔한 이모티콘은 그대로 보존된다.
    """
    output: list[_Token] = []
    changed = False
    index = 0
    count = len(tokens)

    while index < count:
      lead = tokens[index][0]
      has_vowel_next = index + 1 < count and tokens[index + 1][0] in _V_INDEX
      if lead in _L_INDEX and has_vowel_next:
        l_index = _L_INDEX[lead]
        v_index = _V_INDEX[tokens[index + 1][0]]
        consumed = 2
        t_index = 0

        if index + 2 < count and tokens[index + 2][0] in _T_INDEX:
          candidate = tokens[index + 2][0]
          next_is_vowel = index + 3 < count and tokens[index + 3][0] in _V_INDEX
          # 종성 후보가 다음 음절의 초성이기도 하고 그 뒤에 모음이 오면 → 종성으로 취하지 않음
          if next_is_vowel and candidate in _L_INDEX:
            pass
          else:
            t_index = _T_INDEX[candidate]
            consumed = 3

        syllable = chr(_HANGUL_BASE + (l_index * 21 + v_index) * 28 + t_index)
        span_start = tokens[index][1]
        span_end = tokens[index + consumed - 1][2]
        output.append((syllable, span_start, span_end))
        changed = True
        index += consumed
      else:
        output.append(tokens[index])
        index += 1

    return output, changed

  def _strip_spaced_run_ws(self, tokens: list[_Token]) -> tuple[list[_Token], bool]:
    """
    '한 글자 (공백 한 글자)+' 형태의 극대 런에서 공백만 제거한다.

    런 구성 문자는 식별자를 이루는 영숫자와 구분자(_RUN_CHARS)다. 런 길이가
    digit_spacing_min_run 이상일 때만 그 런 안의 공백을 지우므로, 일반 산문의 공백은
    건드리지 않는다("3 년 9 개월" 은 한글이, "8 5 / 1 0 0" 은 '/' 가 런을 끊는다).

    예전에는 숫자-숫자 사이만 봤다. 그래서 R2 evasion 응답의
    "y e o n w o o . y a n g 8 0 @ e x a m p l e . t e s t" 가 이메일로 복원되지 않았고,
    "0 1 0 - 9 0 0 0 - 5 0 1 4" 도 하이픈에서 런이 끊겨 미복원 → NER 이 이를 QT_IP 로
    오탐했다(RAG-2026-0810-001 실측: 응답 1건당 QT_IP 6건). 런 문자에 영문·구분자를
    포함시켜 둘 다 해소한다.
    """
    count = len(tokens)
    dropped: set[int] = set()
    index = 0

    while index < count:
      if tokens[index][0] not in _RUN_CHARS:
        index += 1
        continue
      # 극대 런 탐색: (글자 · 공백 1개 · 글자) 를 계속 이어 붙인다.
      run_length = 1
      cursor = index
      space_positions: list[int] = []
      while (
        cursor + 2 < count
        and tokens[cursor + 1][0] in _INTRA_DIGIT_WS
        and tokens[cursor + 2][0] in _RUN_CHARS
      ):
        space_positions.append(cursor + 1)
        run_length += 1
        cursor += 2
      if run_length >= self.digit_spacing_min_run:
        dropped.update(space_positions)
      index = cursor + 1

    if not dropped:
      return tokens, False
    output = [token for position, token in enumerate(tokens) if position not in dropped]
    return output, True
