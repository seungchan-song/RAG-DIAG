"""Generator 컴포넌트 단위 테스트.

OpenAI/HyperCLOVA X/Mock 디스패치 동작과 ClovaXGenerator 의 응답 파싱을 검증합니다.
실제 API 호출은 하지 않으며, http_client 를 mock 으로 주입해 결정론적으로 테스트합니다.
"""

from __future__ import annotations

from typing import Any

import pytest

from rag.generator.generator import (
  ClovaXGenerator,
  MockGenerator,
  create_clova_generator,
  create_generator,
)


class _FakeResponse:
  """requests.Response 와 호환되는 최소 stub."""

  def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
    self._payload = payload
    self.status_code = status_code
    self.text = str(payload)

  def json(self) -> dict[str, Any]:
    return self._payload


class _FakeHttpClient:
  """ClovaXGenerator 의 http_client 슬롯에 주입되는 mock 클라이언트."""

  def __init__(self, response: _FakeResponse) -> None:
    self.response = response
    self.calls: list[tuple[str, dict[str, str], dict[str, Any]]] = []

  def post(
    self,
    url: str,
    *,
    headers: dict[str, str],
    json: dict[str, Any],
    timeout: float,
  ) -> _FakeResponse:
    self.calls.append((url, headers, json))
    assert timeout > 0
    return self.response


class TestClovaXGenerator:
  def test_run_extracts_assistant_content(self):
    payload = {
      "result": {
        "message": {"role": "assistant", "content": "안녕하세요, 클로바입니다."},
        "usage": {"promptTokens": 12, "completionTokens": 8},
      },
      "status": {"code": "20000"},
    }
    client = _FakeHttpClient(_FakeResponse(payload))
    gen = ClovaXGenerator(api_key="dummy", http_client=client)

    output = gen.run(prompt="질문에 답해주세요.")

    assert output["replies"] == ["안녕하세요, 클로바입니다."]
    assert output["meta"][0]["provider"] == "clova"
    assert output["meta"][0]["model"] == "HCX-DASH-002"
    assert output["meta"][0]["usage"] == {"promptTokens": 12, "completionTokens": 8}

    # 호출된 URL/헤더/바디 검증
    assert len(client.calls) == 1
    url, headers, body = client.calls[0]
    assert "chat-completions/HCX-DASH-002" in url
    assert headers["Authorization"] == "Bearer dummy"
    assert body["messages"][0] == {"role": "user", "content": "질문에 답해주세요."}
    assert body["temperature"] == 0.1
    assert body["maxTokens"] == 1024

  def test_run_handles_http_error(self):
    client = _FakeHttpClient(_FakeResponse({"error": "bad"}, status_code=500))
    gen = ClovaXGenerator(api_key="dummy", http_client=client)

    output = gen.run(prompt="질문")

    assert output["replies"] == [""]
    assert "error" in output["meta"][0]
    assert output["meta"][0]["provider"] == "clova"

  def test_run_handles_empty_payload(self):
    client = _FakeHttpClient(_FakeResponse({}))
    gen = ClovaXGenerator(api_key="dummy", http_client=client)

    output = gen.run(prompt="질문")

    assert output["replies"] == [""]
    assert output["meta"][0]["provider"] == "clova"


class TestCreateClovaGenerator:
  def test_raises_when_api_key_missing(self, monkeypatch):
    monkeypatch.delenv("NAVER_CLOVA_API_KEY", raising=False)
    with pytest.raises(ValueError, match="NAVER_CLOVA_API_KEY"):
      create_clova_generator({})

  def test_uses_config_overrides(self, monkeypatch):
    monkeypatch.setenv("NAVER_CLOVA_API_KEY", "secret")
    monkeypatch.setenv("NAVER_CLOVA_API_URL", "https://example.test")
    config = {
      "generator": {
        "clova": {
          "model": "HCX-DASH-002",
          "temperature": 0.05,
          "max_tokens": 256,
          "top_p": 0.7,
        }
      }
    }
    gen = create_clova_generator(config)

    assert isinstance(gen, ClovaXGenerator)
    assert gen.model == "HCX-DASH-002"
    assert gen.temperature == 0.05
    assert gen.max_tokens == 256
    assert gen.top_p == 0.7
    assert gen.api_url == "https://example.test"


class TestCreateGeneratorDispatch:
  def test_provider_clova_without_key_falls_back_to_mock(self, monkeypatch):
    monkeypatch.delenv("NAVER_CLOVA_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    config = {"generator": {"provider": "clova"}}
    assert isinstance(create_generator(config), MockGenerator)

  def test_provider_openai_without_key_falls_back_to_mock(self, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("NAVER_CLOVA_API_KEY", raising=False)
    config = {"generator": {"provider": "openai"}}
    assert isinstance(create_generator(config), MockGenerator)

  def test_auto_prefers_openai_when_both_keys_set(self, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("NAVER_CLOVA_API_KEY", "nv-test")
    # OpenAI 어댑터 자체 로드 비용을 줄이기 위해 외부 호출을 모킹할 수도 있지만
    # 여기서는 openai 클라이언트 import 만으로도 충분한 경량 테스트를 의도.
    # 결과 객체 타입을 직접 검사하지 않고, MockGenerator 가 아니라는 사실만 검증.
    gen = create_generator({})
    assert not isinstance(gen, MockGenerator)

  def test_auto_uses_clova_when_only_clova_key_set(self, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("NAVER_CLOVA_API_KEY", "nv-test")
    gen = create_generator({})
    assert isinstance(gen, ClovaXGenerator)
