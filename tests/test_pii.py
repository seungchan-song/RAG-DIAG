"""Tests for PII detection, masking, runtime status, and artifact safety."""

from __future__ import annotations

import json
import sys
import types

from rag.attack.base import AttackResult
from rag.pii.artifacts import sanitize_results_for_storage
from rag.pii.detector import PIIDetector
from rag.pii.step0_normalize import TextNormalizer
from rag.pii.step1_regex import PIIMatch, RegexDetector
from rag.pii.step2_checksum import ChecksumValidator
from rag.pii.step3_ner import NERDetector, NERMatch
from rag.pii.step4_sllm import SLLMVerifier


def _build_pii_config(
  *,
  enable_step3: bool = True,
  enable_step4: bool = True,
  model_path: str = "townboy/kpfbert-kdpii",
  revision: str = "",
) -> dict:
  return {
    "pii": {
      "runtime": {
        "enable_step3": enable_step3,
        "enable_step4": enable_step4,
      },
      "ner": {
        "model_path": model_path,
        "revision": revision,
        "confidence_threshold": 0.8,
      },
      "sllm": {
        "model": "gpt-4o-mini",
        "max_retries": 1,
        "retry_backoff": 1,
      },
    },
    "report": {
      "mask_raw_pii": True,
      "persist_raw_response": False,
    },
  }


# 조직별 ID 체계(사원번호·회원 ID·참가자 ID·계정 ID)는 회사마다 형식이 달라
# 국가 표준이 없다. 그래서 코드가 아니라 배포처 설정(`pii.custom_id_patterns`)에
# 둔다. 아래는 우리 합성 코퍼스가 쓰는 형식으로, 정규식 경로를 검증할 때 주입한다.
_DEMO_ID_PATTERNS: dict[str, str] = {
  "EMPLOYEE_ID": r"EMP-\d{4}-\d{4,6}",
  "MEMBER_ID": r"MBR\d{7}",
  "PARTICIPANT_ID": r"(?:PART|PTC|RES|SUB)-\d{4}",
  "USER_ID": r"(?:user|admin|staff|dev|mgr)_\d{4}",
}


def _config_with_demo_ids() -> dict:
  """우리 코퍼스 ID 형식을 선언한 최소 설정."""
  return {"pii": {"custom_id_patterns": dict(_DEMO_ID_PATTERNS)}}


class TestRegexDetector:
  def setup_method(self) -> None:
    self.detector = RegexDetector(_config_with_demo_ids())

  def test_mobile_with_hyphen(self) -> None:
    matches = self.detector.detect("전화번호는 010-1234-5678입니다.")
    assert "QT_MOBILE" in [match.tag for match in matches]

  def test_mobile_without_separator(self) -> None:
    matches = self.detector.detect("연락처 01012345678")
    assert "QT_MOBILE" in [match.tag for match in matches]

  def test_email(self) -> None:
    matches = self.detector.detect("이메일 hong@example.com")
    assert "TMI_EMAIL" in [match.tag for match in matches]

  def test_email_complex(self) -> None:
    matches = self.detector.detect("test.user+tag@company.co.kr")
    assert "TMI_EMAIL" in [match.tag for match in matches]

  def test_rrn_pattern(self) -> None:
    matches = self.detector.detect("주민번호: 901015-1234567")
    assert "QT_RRN" in [match.tag for match in matches]

  def test_rrn_needs_validation(self) -> None:
    matches = self.detector.detect("901015-1234567")
    rrn_matches = [match for match in matches if match.tag == "QT_RRN"]
    assert rrn_matches
    assert rrn_matches[0].needs_validation is True

  def test_card_with_hyphen(self) -> None:
    matches = self.detector.detect("카드: 4532-1234-5678-9012")
    assert "QT_CARD" in [match.tag for match in matches]

  def test_passport(self) -> None:
    matches = self.detector.detect("여권번호: M12345678")
    assert "QT_PASSPORT" in [match.tag for match in matches]

  def test_ip_address(self) -> None:
    matches = self.detector.detect("서버 IP: 192.168.0.1")
    assert "QT_IP" in [match.tag for match in matches]

  def test_address(self) -> None:
    matches = self.detector.detect("서울특별시 광진구 능동로 209")
    assert "QT_ADDR" in [match.tag for match in matches]

  def test_new_33_category_identifiers(self) -> None:
    """개인정보 33종 개편으로 코퍼스에 심긴 고정 포맷 식별자 5종을 잡는지 확인한다.

    이 패턴들이 빠지면 해당 PII 가 유출돼도 리포트에 0건으로 찍힌다(과소보고).
    """
    text = (
      "성명 홍길동 (사원번호 EMP-2024-13579), 회원 MBR1234567, "
      "참가번호 PART-4821, ID: admin_7391, 주소 서울 강남구 테헤란로 12 (우편번호 06234)"
    )
    tags = {match.tag for match in self.detector.detect(text)}
    assert {
      "EMPLOYEE_ID", "MEMBER_ID", "PARTICIPANT_ID", "USER_ID", "ZIPCODE",
    } <= tags

  def test_member_id_not_mistaken_for_passport(self) -> None:
    """MBR1234567 이 여권번호(영문+숫자)로 오분류되지 않아야 한다.

    오분류되면 '고유식별' 위험 등급 건수가 실제보다 부풀려진다.
    """
    from rag.pii.classifier import PIIClassifier

    matches = self.detector.detect("회원 MBR1234567 입니다.")
    confirmed = PIIClassifier().classify(matches, [], [])
    assert [item.tag for item in confirmed] == ["MEMBER_ID"]

  def test_bare_five_digit_number_is_not_zipcode(self) -> None:
    matches = self.detector.detect("이번 분기 예산은 45000 만원입니다.")
    assert "ZIPCODE" not in [match.tag for match in matches]

  def test_no_pii(self) -> None:
    matches = self.detector.detect("오늘 날씨가 좋습니다.")
    core_tags = {"QT_MOBILE", "TMI_EMAIL", "QT_RRN", "QT_CARD"}
    assert not (core_tags & {match.tag for match in matches})

  def test_multiple_pii(self) -> None:
    matches = self.detector.detect(
      "홍길동의 전화번호는 010-1234-5678이고 이메일은 hong@example.com입니다."
    )
    tags = {match.tag for match in matches}
    assert "QT_MOBILE" in tags
    assert "TMI_EMAIL" in tags

  def test_match_position(self) -> None:
    text = "메일: hong@example.com"
    matches = self.detector.detect(text)
    email_match = next(match for match in matches if match.tag == "TMI_EMAIL")
    assert text[email_match.start:email_match.end] == email_match.text


class TestChecksumValidator:
  def setup_method(self) -> None:
    self.validator = ChecksumValidator()

  def test_rrn_invalid(self) -> None:
    assert self.validator.validate_rrn("901015-1234567") is False

  def test_rrn_wrong_length(self) -> None:
    assert self.validator.validate_rrn("12345") is False

  def test_rrn_non_numeric(self) -> None:
    assert self.validator.validate_rrn("abcdef-ghijklm") is False

  def test_card_invalid(self) -> None:
    assert self.validator.validate_card("1234-5678-9012-3456") is False

  def test_card_wrong_length(self) -> None:
    assert self.validator.validate_card("1234") is False

  def test_filter_removes_invalid_rrn(self) -> None:
    matches = [
      PIIMatch(
        tag="QT_RRN",
        text="901015-1234567",
        start=0,
        end=14,
        needs_validation=True,
      ),
      PIIMatch(
        tag="TMI_EMAIL",
        text="test@example.com",
        start=20,
        end=36,
        needs_validation=False,
      ),
    ]
    valid = self.validator.filter_valid(matches)
    assert "TMI_EMAIL" in [match.tag for match in valid]
    assert "QT_RRN" not in [match.tag for match in valid]

  def test_filter_keeps_no_validation_items(self) -> None:
    valid = self.validator.filter_valid(
      [
        PIIMatch(
          tag="QT_MOBILE",
          text="010-1234-5678",
          start=0,
          end=13,
          needs_validation=False,
        ),
      ]
    )
    assert len(valid) == 1
    assert valid[0].tag == "QT_MOBILE"

  def test_partition_valid_captures_rejected_rrn(self) -> None:
    matches = [
      PIIMatch(
        tag="QT_RRN",
        text="901015-1234567",
        start=0,
        end=14,
        needs_validation=True,
      ),
      PIIMatch(
        tag="TMI_EMAIL",
        text="test@example.com",
        start=20,
        end=36,
        needs_validation=False,
      ),
    ]
    valid, rejected = self.validator.partition_valid(matches)

    # 유효 목록에는 이메일만 남고, 체크섬 탈락 주민번호는 rejected 로 분리된다.
    assert [match.tag for match in valid] == ["TMI_EMAIL"]
    assert len(rejected) == 1
    assert rejected[0].tag == "QT_RRN"
    assert rejected[0].reason == "checksum_failed"
    assert rejected[0].validator == "mod11"


class TestStep0Normalizer:
  def setup_method(self) -> None:
    self.normalizer = TextNormalizer(_build_pii_config())

  def test_clean_text_is_unchanged(self) -> None:
    result = self.normalizer.normalize("연락처는 010-1234-5678 입니다.")
    assert result.changed is False
    assert result.applied == []

  def test_fullwidth_digits_folded(self) -> None:
    result = self.normalizer.normalize("０１０－１２３４－５６７８")
    assert result.normalized_text == "010-1234-5678"
    assert "compat" in result.applied

  def test_zero_width_removed(self) -> None:
    result = self.normalizer.normalize("0​1​0​1234​5678")
    assert result.normalized_text == "01012345678"
    assert "invisible" in result.applied

  def test_jamo_composition(self) -> None:
    result = self.normalizer.normalize("ㅎㅗㅇㄱㅣㄹㄷㅗㅇ")
    assert result.normalized_text == "홍길동"
    assert "jamo" in result.applied
    # 음절 3개가 자모 9개에서 나왔으므로 원문 스팬으로 되돌리면 전체를 덮는다.
    assert result.to_original_span(0, 3) == (0, 9)

  def test_emoticon_consonants_are_preserved(self) -> None:
    # 모음이 없는 자음 나열은 결합되지 않아 흔한 이모티콘이 보존된다.
    result = self.normalizer.normalize("아 진짜 ㅋㅋㅋ")
    assert result.changed is False

  def test_spaced_digits_gated_and_stripped(self) -> None:
    # 규칙적 숫자 공백열(5자리 이상)이면 숫자 사이 공백을 제거한다.
    result = self.normalizer.normalize("0 1 0 1 2")
    assert result.normalized_text == "01012"
    assert "digit_sep" in result.applied

  def test_prose_spacing_not_stripped(self) -> None:
    # 산문의 우연한 숫자 공백(짧은 열)은 건드리지 않는다.
    result = self.normalizer.normalize("방 302 호실 5명")
    assert result.changed is False

  def test_disabled_returns_identity(self) -> None:
    config = _build_pii_config()
    config["pii"]["runtime"]["enable_step0"] = False
    normalizer = TextNormalizer(config)
    result = normalizer.normalize("０１０")
    assert result.normalized_text == "０１０"
    assert result.changed is False


class TestPIIMasker:
  def setup_method(self) -> None:
    from rag.pii.masker import PIIMasker

    self.masker = PIIMasker()

  def test_mask_rrn(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    masked = self.masker.mask_single(
      ConfirmedPII(
        tag="QT_RRN",
        text="901015-1234567",
        start=0,
        end=14,
        route="A-2",
        source="regex",
      )
    )
    assert "901015" in masked
    assert "1234567" not in masked

  def test_mask_mobile(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    masked = self.masker.mask_single(
      ConfirmedPII(
        tag="QT_MOBILE",
        text="010-1234-5678",
        start=0,
        end=13,
        route="A-1",
        source="regex",
      )
    )
    assert "5678" in masked

  def test_mask_email(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    masked = self.masker.mask_single(
      ConfirmedPII(
        tag="TMI_EMAIL",
        text="hong@example.com",
        start=0,
        end=16,
        route="A-1",
        source="regex",
      )
    )
    assert "h" in masked
    assert "example.com" in masked

  def test_placeholder_uses_korean_label_not_internal_tag(self) -> None:
    """자리표시자에 내부 태그명(QT_*/TMI_*)이 새면 안 된다.

    마스킹된 문서·응답은 그대로 리포트 화면에 실린다. 예전에는 "[TMI_OCCUPATION]",
    "[QT_IP]" 같은 우리 파이프라인 네임스페이스가 사용자에게 그대로 노출됐다.
    """
    from rag.pii.classifier import ConfirmedPII

    for tag, expected in (("QT_IP", "[IP 주소]"), ("TMI_OCCUPATION", "[직업·직장]"),
                          ("MEMBER_ID", "[회원 ID]"), ("QT_PASSPORT", "[여권번호]")):
      masked = self.masker.mask_single(
        ConfirmedPII(tag=tag, text="x", start=0, end=1, route="A-1", source="regex")
      )
      assert masked == expected
      assert "QT_" not in masked and "TMI_" not in masked

  def test_unknown_tag_falls_back_to_tag_name(self) -> None:
    """라벨이 없는 새 태그도 조용히 깨지지 않고 태그명 그대로 남는다."""
    from rag.pii.classifier import ConfirmedPII

    masked = self.masker.mask_single(
      ConfirmedPII(tag="BRAND_NEW_TAG", text="x", start=0, end=1, route="A-1", source="regex")
    )
    assert masked == "[BRAND_NEW_TAG]"

  def test_mask_text_replaces_pii(self) -> None:
    from rag.pii.classifier import ConfirmedPII

    original = "전화번호: 010-1234-5678"
    masked = self.masker.mask_text(
      original,
      [
        ConfirmedPII(
          tag="QT_MOBILE",
          text="010-1234-5678",
          start=6,
          end=19,
          route="A-1",
          source="regex",
        ),
      ],
    )
    assert "010-1234-5678" not in masked
    assert "5678" in masked


class TestKoreanParticleBoundary:
  """한국어 조사가 값에 붙어도 정규식이 탐지해야 한다.

  `\\b` 는 한글도 단어문자로 보기 때문에 "203.0.113.11를" 처럼 조사가 바로 붙으면
  경계가 생기지 않아 매칭이 통째로 실패했다(2026-08-03 실측: clean 코퍼스 IP
  331건 중 112건 미탐). 더 나쁜 건 "MBR1234567은" 에서 MEMBER_ID 가 실패해
  여권번호 오분류가 되살아나던 것 — 고유식별 등급 건수를 부풀린다.
  """

  def test_values_followed_by_particles_are_detected(self) -> None:
    detector = RegexDetector(_config_with_demo_ids())
    cases = {
      "허용 목록에 203.0.113.11를 등록했습니다": "QT_IP",
      "우편번호 06234가 표시됩니다": "ZIPCODE",
      "사번 EMP-2024-13579로 조회하세요": "EMPLOYEE_ID",
      "회원 MBR1234567은 탈퇴했습니다": "MEMBER_ID",
      "PART-4821에게 안내했습니다": "PARTICIPANT_ID",
      "admin_7391으로 접속했습니다": "USER_ID",
    }
    for text, expected_tag in cases.items():
      tags = {match.tag for match in detector.detect(text)}
      assert expected_tag in tags, f"{text!r} 에서 {expected_tag} 미탐: {tags}"

  def test_ascii_prefix_still_blocks_partial_match(self) -> None:
    """경계를 넓히되 ASCII 영숫자 안쪽의 부분 매칭은 계속 막아야 한다."""
    detector = RegexDetector()
    assert not [m for m in detector.detect("x203.0.113.11") if m.tag == "QT_IP"]
    assert not [m for m in detector.detect("1203.0.113.119") if m.tag == "QT_IP"]


class TestCustomIdPatterns:
  """조직별 ID 체계는 코드가 아니라 설정에서 온다.

  예전엔 우리 합성 코퍼스의 접두사(`EMP-`·`MBR`·`PART-`·`admin_`)가 정규식에
  하드코딩돼 있었다. 그러면 우리 데이터에서만 맞고 **남의 RAG 를 진단하면 조용히
  0건**이 나온다(2026-08-04 발견). 이 도구의 목적이 외부 RAG 진단이므로,
  선언하지 않은 대상에는 ID 정규식이 아예 붙지 않아야 한다.
  """

  def test_no_id_patterns_without_declaration(self) -> None:
    """선언이 없으면 ID 는 정규식으로 잡지 않는다(문맥을 보는 NER 담당)."""
    detector = RegexDetector()
    text = "사번 EMP-2024-13579, 회원 MBR1234567, 참가 PART-4821, 계정 admin_7391"
    assert [match.tag for match in detector.detect(text)] == []

  def test_declared_patterns_are_applied(self) -> None:
    """선언하면 그 형식으로 탐지한다."""
    detector = RegexDetector(_config_with_demo_ids())
    tags = {match.tag for match in detector.detect("계정 admin_7391 로 접속")}
    assert "USER_ID" in tags

  def test_other_org_format_is_supported(self) -> None:
    """다른 조직 형식을 선언하면 그쪽이 잡힌다 — 우리 형식에 묶이지 않는다."""
    detector = RegexDetector({"pii": {"custom_id_patterns": {"USER_ID": r"u-[0-9]{3}"}}})
    assert {m.tag for m in detector.detect("계정 u-106 로 접속")} == {"USER_ID"}
    assert [m.tag for m in detector.detect("계정 admin_7391 로 접속")] == []

  def test_invalid_pattern_is_skipped_without_crashing(self) -> None:
    """설정 오타 하나로 파이프라인 전체가 죽으면 안 된다."""
    detector = RegexDetector(
      {"pii": {"custom_id_patterns": {"BROKEN": r"([0-9", "USER_ID": r"u-[0-9]{3}"}}}
    )
    assert {m.tag for m in detector.detect("계정 u-106")} == {"USER_ID"}

  def test_standard_patterns_survive_without_config(self) -> None:
    """표준 형식(전화·이메일 등)은 설정과 무관하게 항상 동작한다."""
    detector = RegexDetector()
    tags = {m.tag for m in detector.detect("연락처 010-1234-5678, 메일 a@b.com")}
    assert {"QT_MOBILE", "TMI_EMAIL"} <= tags


class TestPassportPattern:
  """여권번호는 영문 1글자 + 숫자 8자리(구형)다.

  이전 `[A-Z]{1,2}\\d{7,8}` 은 근거 없이 넓어서 `MBR1234567` 의 뒤 9글자를
  `BR1234567` 여권번호로 집어갔고, 그걸 막으려고 MEMBER_ID 정규식이 방패 역할을
  하고 있었다. 조직별 ID 를 설정으로 뺀 뒤에는 방패가 없으므로 패턴 자체가
  안전해야 한다.
  """

  def test_old_format_is_detected(self) -> None:
    detector = RegexDetector()
    assert {m.tag for m in detector.detect("여권번호 S99585004 입니다")} == {"QT_PASSPORT"}

  def test_member_id_is_not_grabbed_as_passport(self) -> None:
    """ID 정규식 선언이 없어도 여권으로 오분류되면 안 된다."""
    detector = RegexDetector()
    assert [m.tag for m in detector.detect("회원 MBR1234567 입니다")] == []
    assert [m.tag for m in detector.detect("MBR1234567은 탈퇴")] == []


class TestNERStructureGate:
  """STEP 3 구조 게이트 — 모델이 쪼갠 조각이 고유식별정보로 확정되는 걸 막는다.

  실측 배경(2026-08-03): 라벨 단어가 없는 나열/표 형태 응답에서 NER 이 스팬을
  서브워드 조각까지 쪼개, 진짜 PII 6건짜리 문단이 엔티티 17개로 집계됐다
  (`'1'`→계좌번호, `'.'`→운전면허번호, `'김민수'`→계좌번호 등).
  """

  def _match(self, tag: str, text: str) -> NERMatch:
    return NERMatch(tag=tag, text=text, start=0, end=len(text), confidence=0.9)

  def test_fragments_are_rejected_not_confirmed(self) -> None:
    detector = NERDetector(_build_pii_config())
    fragments = [
      self._match("QT_ACCOUNT", "1"),      # 목록 번호
      self._match("QT_DRIVER", "."),       # 마침표
      self._match("QT_ACCOUNT", "김민수"),  # 사람 이름
      self._match("QT_RRN", "900"),        # 주민번호 앞 3자리
      self._match("QT_ARN", "101-"),       # 주민번호 가운데 조각
      self._match("QT_RRN", "06234"),      # 우편번호가 주민번호로 찍힌 경우
    ]
    kept, rejected = detector.partition_structural(fragments)

    assert kept == []
    assert len(rejected) == len(fragments)
    assert {item.reason for item in rejected} == {"ner_structure_mismatch"}

  def test_well_formed_values_pass(self) -> None:
    detector = NERDetector(_build_pii_config())
    valid = [
      self._match("QT_RRN", "900101-1234567"),
      self._match("QT_ARN", "900101-5234567"),
      self._match("QT_CARD", "4532-1234-5678-9012"),
      self._match("QT_PHONE", "010-1234-5678"),
      self._match("TMI_EMAIL", "hong@example.com"),
      self._match("ZIPCODE", "06234"),
      self._match("PER", "홍길동"),  # 비정형 태그는 자릿수 개념이 없어 그대로 통과
    ]
    kept, rejected = detector.partition_structural(valid)

    assert rejected == []
    assert len(kept) == len(valid)


class _FakeTokenizer:
  """NERDetector.warm_up 이 만지는 최소 토크나이저 더블.

  실제 코드는 KPF-BERT 토크나이저의 `model_max_length` 가 sentinel(~1e30) 인 것을
  512 로 강제해 자동 truncation 을 켠다(`step3_ner.py:warm_up`). 그 경로가 속성
  읽기/쓰기를 하므로 더블도 같은 속성을 가져야 한다.
  """

  def __init__(self) -> None:
    self.model_max_length = 10**30


class _FakeAutoTokenizer:
  @staticmethod
  def from_pretrained(_identifier: str, **_: object) -> _FakeTokenizer:
    return _FakeTokenizer()


class TestNERDetectorRuntime:
  def test_prefers_local_model_path_when_present(self, monkeypatch, tmp_path) -> None:
    local_model_dir = tmp_path / "local-kdpii"
    local_model_dir.mkdir()

    captured: dict[str, str] = {}
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(*, model: str, tokenizer: str, **_: object):  # type: ignore[override]
      captured["model"] = model
      captured["tokenizer"] = tokenizer
      return lambda text: []

    transformers_module.pipeline = lambda task, **kwargs: fake_pipeline(**kwargs)
    transformers_module.AutoTokenizer = _FakeAutoTokenizer
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)

    detector = NERDetector(
      _build_pii_config(model_path=str(local_model_dir))
    )
    detector.warm_up()
    status = detector.get_runtime_status()

    assert status["model_source"] == "local"
    assert status["load_status"] == "ready"
    assert status["resolved_model_identifier"] == str(local_model_dir)
    assert captured["model"] == str(local_model_dir)

  def test_hub_revision_is_pinned_and_reported(self, monkeypatch) -> None:
    """설정한 리비전이 실제 로드에 넘어가고 산출물에도 남는지 고정한다.

    핀이 안 넘어가면 허브의 main 이 바뀌는 순간 같은 config 가 다른 가중치로
    채점한다(2026-08-06 실측: e4c51df→7c0dd11 로 명단형 탐지 1건→8건).
    그러면 모델이 바뀐 것을 우리 코드 개선으로 오독하게 된다.
    """
    captured: dict[str, object] = {}
    transformers_module = types.ModuleType("transformers")

    class _RevisionCapturingTokenizer:
      @staticmethod
      def from_pretrained(_identifier: str, **kwargs: object) -> _FakeTokenizer:
        captured["tokenizer_revision"] = kwargs.get("revision")
        return _FakeTokenizer()

    def fake_pipeline(_task: str, **kwargs: object) -> object:
      captured["pipeline_revision"] = kwargs.get("revision")
      return lambda text: []

    transformers_module.pipeline = fake_pipeline
    transformers_module.AutoTokenizer = _RevisionCapturingTokenizer
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)

    detector = NERDetector(_build_pii_config(revision="e4c51df"))
    detector.warm_up()
    status = detector.get_runtime_status()

    assert captured["tokenizer_revision"] == "e4c51df"
    assert captured["pipeline_revision"] == "e4c51df"
    assert status["resolved_revision"] == "e4c51df"

  def test_local_model_path_ignores_revision(self, monkeypatch, tmp_path) -> None:
    """로컬 디렉토리에는 리비전 개념이 없으므로 넘기면 안 된다(넘기면 로드가 깨진다)."""
    local_model_dir = tmp_path / "local-ner"
    local_model_dir.mkdir()

    captured: dict[str, object] = {}
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(_task: str, **kwargs: object) -> object:
      captured["pipeline_revision"] = kwargs.get("revision")
      return lambda text: []

    transformers_module.pipeline = fake_pipeline
    transformers_module.AutoTokenizer = _FakeAutoTokenizer
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)

    detector = NERDetector(
      _build_pii_config(model_path=str(local_model_dir), revision="e4c51df")
    )
    detector.warm_up()

    assert captured["pipeline_revision"] is None

  def test_records_failed_status_when_model_load_fails(self, monkeypatch) -> None:
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(_: str, **__: object) -> object:
      raise RuntimeError("hf download failed")

    transformers_module.pipeline = fake_pipeline
    # AutoTokenizer 가 없으면 pipeline 에 닿기도 전에 ImportError 가 나서
    # "모델 로드 실패가 기록되는가" 라는 이 테스트의 의도가 검증되지 않는다.
    transformers_module.AutoTokenizer = _FakeAutoTokenizer
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)

    detector = NERDetector(_build_pii_config())
    detector.warm_up()
    status = detector.get_runtime_status()

    assert status["model_source"] == "hub"
    assert status["load_status"] == "failed"
    assert "hf download failed" in status["error"]


class TestSLLMVerifierRuntime:
  def test_mock_conservative_without_api_key(self, monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    verifier = SLLMVerifier(_build_pii_config())
    matches = [
      NERMatch(
        tag="PER",
        text="홍길동",
        start=0,
        end=3,
        confidence=0.91,
      )
    ]
    verified = verifier.verify_batch(matches, "홍길동이 방문했다.")
    status = verifier.get_runtime_status(
      candidate_count=len(matches),
      verified_count=len(verified),
      reason="mock_conservative",
    )

    assert len(verified) == 1
    assert status["mode"] == "mock_conservative"
    assert status["reason"] == "mock_conservative"


class TestSLLMLocalEndpoint:
  """STEP 4 를 로컬 sLLM(OpenAI 호환 엔드포인트)으로 돌리는 경로."""

  def _config(self, **sllm_overrides) -> dict:
    config = _build_pii_config()
    config["pii"]["sllm"].update(sllm_overrides)
    return config

  def test_base_url_disables_mock_and_reaches_client(self, monkeypatch) -> None:
    """base_url 이 있으면 API 키가 없어도 mock 으로 빠지지 않고 실제로 호출한다."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("PII_SLLM_BASE_URL", raising=False)

    verifier = SLLMVerifier(self._config(base_url="http://localhost:8000/v1"))

    assert verifier.mock_mode is False
    assert verifier.mode == "api"
    kwargs = verifier._client_kwargs()
    assert kwargs["base_url"] == "http://localhost:8000/v1"
    # 로컬 서버는 키를 안 보지만 SDK 가 빈 키를 거부하므로 자리채움이 들어가야 한다.
    assert kwargs["api_key"] == "EMPTY"

    status = verifier.get_runtime_status()
    assert status["is_closed_api"] is False
    assert status["endpoint"] == "http://localhost:8000/v1"

  def test_openai_default_is_flagged_as_closed_api(self, monkeypatch) -> None:
    """base_url 없이 OpenAI 로 붙으면 리포트가 Closed API 로 표시할 수 있어야 한다."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.delenv("PII_SLLM_BASE_URL", raising=False)

    status = SLLMVerifier(self._config()).get_runtime_status()

    assert status["is_closed_api"] is True
    assert status["endpoint"] == "openai-default"
    assert SLLMVerifier(self._config())._client_kwargs() == {}

  def test_plain_prompt_format_is_unchanged(self) -> None:
    """기본 형식은 기존 영문 평문 그대로여야 한다(무회귀)."""
    messages = SLLMVerifier(self._config())._build_messages(
      "홍길동", "PER", "직원 홍길동이 방문했다."
    )

    assert len(messages) == 2
    assert "personal information" in messages[0]["content"]
    assert 'Entity: "홍길동"' in messages[1]["content"]
    assert "NER tag: PER" in messages[1]["content"]

  def test_adapter_json_format_translates_tag_back(self) -> None:
    """어댑터 형식은 내부 태그를 33종 원본 라벨로 되돌려 JSON 으로 보낸다."""
    verifier = SLLMVerifier(self._config(prompt_format="adapter_json"))
    context = "직원 홍길동이 방문했다."
    messages = verifier._build_messages("홍길동", "PER", context)
    payload = json.loads(messages[1]["content"])

    assert messages[0]["content"] == verifier.ADAPTER_SYSTEM_PROMPT
    assert payload["answer"] == context
    # PER 은 어댑터가 학습한 NAME 으로 되돌아가야 한다.
    assert payload["candidate"]["tag"] == "NAME"
    assert payload["candidate"]["text"] == "홍길동"
    assert context[payload["candidate"]["start"] : payload["candidate"]["end"]] == "홍길동"

  def test_org_falls_back_to_trained_label(self) -> None:
    """ORG 는 DEPARTMENT/WORKPLACE/SCHOOL 합본이라 학습된 WORKPLACE 로 보낸다."""
    verifier = SLLMVerifier(self._config(prompt_format="adapter_json"))
    payload = json.loads(
      verifier._build_messages("보안관제팀", "ORG", "소속은 보안관제팀이다.")[1]["content"]
    )

    assert payload["candidate"]["tag"] == "WORKPLACE"


class TestPIIHardening:
  def test_detector_marks_step3_unavailable_without_crashing(self, monkeypatch) -> None:
    transformers_module = types.ModuleType("transformers")

    def fake_pipeline(_: str, **__: object) -> object:
      raise RuntimeError("model missing")

    transformers_module.pipeline = fake_pipeline
    monkeypatch.setitem(sys.modules, "transformers", transformers_module)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    detector = PIIDetector(_build_pii_config())
    detector.warm_up()
    result = detector.detect("홍길동은 example@example.com으로 연락했다.")

    assert result["runtime_status"]["step3"]["load_status"] == "failed"
    assert result["runtime_status"]["step4"]["reason"] == "step3_unavailable"
    assert result["summary"]["total"] >= 1

  def test_sanitize_results_masks_response_and_attaches_pii_metadata(self) -> None:
    raw_response = "연락처는 010-1234-5678이고 이메일은 hong@example.com입니다."
    results = [
      AttackResult(
        scenario="R2",
        query="테스트 질의",
        response=raw_response,
      )
    ]

    sanitized = sanitize_results_for_storage(
      results,
      _build_pii_config(enable_step3=False, enable_step4=False),
    )[0]

    assert sanitized.response == sanitized.response_masked
    assert sanitized.masking_applied is True
    assert "010-1234-5678" not in sanitized.response
    assert "hong@example.com" not in sanitized.response
    assert sanitized.pii_summary["total"] >= 2
    assert sanitized.pii_summary["has_high_risk"] is True
    assert sanitized.pii_runtime_status["step3"]["load_status"] == "skipped"
    assert sanitized.pii_runtime_status["step4"]["reason"] == "disabled"
    assert sanitized.metadata["response_storage_mode"] == "masked"
    assert all("text" not in finding for finding in sanitized.pii_findings)
    assert all("masked_text" in finding for finding in sanitized.pii_findings)

  def test_detector_reports_checksum_rejected_without_confirming(self) -> None:
    # step3/step4 를 꺼서 정규식+체크섬 경로만 남긴 뒤, 체크섬 미통과 주민번호가
    # 확정 목록이 아니라 rejected 트랙에 사유와 함께 보존되는지 검증한다.
    detector = PIIDetector(_build_pii_config(enable_step3=False, enable_step4=False))
    detector.warm_up()
    result = detector.detect("주민번호 901015-1234567, 이메일 hong@example.com")

    # 확정 목록에는 주민번호가 없어야 한다(체크섬 탈락 → 확정 제외).
    assert all(finding["tag"] != "QT_RRN" for finding in result["findings"])
    assert any(finding["tag"] == "TMI_EMAIL" for finding in result["findings"])
    # 클린 텍스트라 정규화가 손대지 않았으므로 복원 플래그는 False 여야 한다(오탐 방지).
    email = next(f for f in result["findings"] if f["tag"] == "TMI_EMAIL")
    assert email["recovered"] is False

    # rejected 트랙에 사유·검증기·마스킹과 함께 보존되어야 한다.
    assert len(result["rejected"]) == 1
    rejected = result["rejected"][0]
    assert rejected["tag"] == "QT_RRN"
    assert rejected["reason"] == "checksum_failed"
    assert rejected["validator"] == "mod11"
    assert rejected["status"] == "structurally_matched_unverified"
    assert "text" not in rejected  # 원문 키는 노출하지 않는다
    assert "1234567" not in rejected["masked_text"]  # 뒷자리 마스킹

    # 집계 왜곡 방지: rejected 는 확정 탐지 총계와 분리되어 카운트된다.
    assert result["runtime_status"]["step2"]["rejected_count"] == 1

  def test_sanitize_results_preserves_checksum_rejected(self) -> None:
    results = [
      AttackResult(
        scenario="R2",
        query="테스트 질의",
        response="주민번호 901015-1234567 참고 바랍니다.",
      )
    ]

    sanitized = sanitize_results_for_storage(
      results,
      _build_pii_config(enable_step3=False, enable_step4=False),
    )[0]

    assert len(sanitized.pii_rejected) == 1
    rejected = sanitized.pii_rejected[0]
    assert rejected["tag"] == "QT_RRN"
    assert rejected["reason"] == "checksum_failed"
    assert "text" not in rejected
    assert "1234567" not in rejected["masked_text"]

  def test_step0_recovers_fullwidth_phone(self) -> None:
    # 전각으로 변형된 휴대폰 번호가 STEP 0 정규화 후 정규식에 다시 잡히는지 검증한다.
    detector = PIIDetector(_build_pii_config(enable_step3=False, enable_step4=False))
    detector.warm_up()
    result = detector.detect_and_mask("연락처는 ０１０－１２３４－５６７８ 입니다.")

    tags = [finding["tag"] for finding in result["findings"]]
    assert "QT_MOBILE" in tags
    assert result["runtime_status"]["step0"]["changed"] is True
    # 전각 → 반각 복원으로 잡힌 항목이므로 recovered 플래그가 True 여야 한다(리포트 노출용).
    mobile = next(f for f in result["findings"] if f["tag"] == "QT_MOBILE")
    assert mobile["recovered"] is True
    # 원문(전각) 구간이 정규화된 마스킹 표현으로 치환되어 뒷자리가 그대로 남지 않는다.
    assert "１２３４" not in result["masked_text"]
    assert "010-****-5678" in result["masked_text"]

  def test_step0_fullwidth_invalid_rrn_flows_to_rejection(self) -> None:
    # STEP 0 가 구조를 복원했지만 체크섬이 실패하면 rejection 채널로 흘러가는지 검증한다.
    detector = PIIDetector(_build_pii_config(enable_step3=False, enable_step4=False))
    detector.warm_up()
    result = detector.detect("주민번호 ９０１０１５－１２３４５６７ 참고")

    rejected_tags = [item["tag"] for item in result["rejected"]]
    assert "QT_RRN" in rejected_tags
    assert all(finding["tag"] != "QT_RRN" for finding in result["findings"])
