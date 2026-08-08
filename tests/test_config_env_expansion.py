"""설정의 `${VAR}` 환경변수 치환 회귀 테스트.

왜 이 파일이 있나 — `config/default.yaml` 은 예전부터
`api_key: "${ANYTHINGLLM_API_KEY}"` 를 권장해 왔는데 **치환 로직이 아예 없었다**
(2026-08-06 확인: `expandvars` 전수 grep 0건). 그대로 쓰면 리터럴 문자열
`${ANYTHINGLLM_API_KEY}` 가 Bearer 토큰으로 전송돼 401 만 보고 원인을 못 찾는다 —
외부 RAG 실증(U9) 직전에 밟을 지뢰였다.

범위를 `${VAR}` 정확 일치로 좁힌 것도 의도다. `$` 를 무차별 확장하면
`generator.system_prompt` 같은 자유 텍스트가 조용히 깨질 수 있다.
"""

from __future__ import annotations

from rag.utils.config import expand_env_placeholders


def test_expands_known_environment_variable(monkeypatch):
  monkeypatch.setenv("RAGDIAG_TEST_TOKEN", "secret-value")
  config = {"adapter": {"api_key": "${RAGDIAG_TEST_TOKEN}"}}

  assert expand_env_placeholders(config)["adapter"]["api_key"] == "secret-value"


def test_expands_inside_nested_structures(monkeypatch):
  monkeypatch.setenv("RAGDIAG_TEST_HOST", "example.test")
  config = {
    "adapter": {"base_url": "https://${RAGDIAG_TEST_HOST}/api"},
    "targets": [{"url": "https://${RAGDIAG_TEST_HOST}"}],
  }

  expanded = expand_env_placeholders(config)
  assert expanded["adapter"]["base_url"] == "https://example.test/api"
  assert expanded["targets"][0]["url"] == "https://example.test"


def test_missing_variable_becomes_empty_not_literal(monkeypatch):
  """환경변수가 없으면 빈 값이 된다 — 자리표시자를 토큰으로 보내면 안 된다."""
  monkeypatch.delenv("RAGDIAG_TEST_ABSENT", raising=False)
  config = {"adapter": {"api_key": "${RAGDIAG_TEST_ABSENT}"}}

  api_key = expand_env_placeholders(config)["adapter"]["api_key"]
  assert api_key == ""
  assert "${" not in api_key


def test_plain_dollar_text_is_untouched():
  """`${VAR}` 형태가 아닌 `$` 는 건드리지 않는다(프롬프트 훼손 방지)."""
  config = {"generator": {"system_prompt": "비용은 $100 이며 $ 기호는 그대로 둔다."}}

  assert expand_env_placeholders(config) == config


def test_non_string_values_pass_through():
  config = {"top_k": 5, "enabled": True, "ratio": 0.5, "missing": None}

  assert expand_env_placeholders(config) == config


def test_input_is_not_mutated(monkeypatch):
  monkeypatch.setenv("RAGDIAG_TEST_TOKEN", "secret-value")
  config = {"adapter": {"api_key": "${RAGDIAG_TEST_TOKEN}"}}

  expand_env_placeholders(config)
  assert config["adapter"]["api_key"] == "${RAGDIAG_TEST_TOKEN}"


def test_load_config_applies_expansion(tmp_path, monkeypatch):
  """실제 load_config 경로가 치환을 통과시키는지 확인한다."""
  monkeypatch.setenv("RAGDIAG_TEST_TOKEN", "from-env")
  config_file = tmp_path / "cfg.yaml"
  config_file.write_text(
    'adapter:\n  api_key: "${RAGDIAG_TEST_TOKEN}"\n', encoding="utf-8"
  )

  from rag.utils.config import load_config

  loaded = load_config(str(config_file))
  assert loaded["adapter"]["api_key"] == "from-env"
