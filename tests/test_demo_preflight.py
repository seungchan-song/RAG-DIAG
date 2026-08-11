"""`rag demo` 의 로컬 생성기 사전 점검 테스트.

`generator.provider` 를 "local" 로 고정하면서 생긴 함정을 고정한다 — 로컬 LLM 서버가
안 떠 있어도 생성기 **생성**은 성공하고, 실패는 질의 시점에야 드러난다. 그러면 심사위원이
`rag demo` 를 처음 치는 순간 **전 쿼리가 실패한 리포트**를 보게 된다. 사전 점검이 그 앞에서
막고 준비 명령을 보여주는지 검증한다. 실제 HTTP 는 monkeypatch 로 대체한다.
"""

from __future__ import annotations

from typing import Any

import pytest
import typer

from rag.cli.main import _preflight_local_generator


class _FakeResponse:
  """requests.Response 와 호환되는 최소 stub."""

  def __init__(self, payload: dict[str, Any]) -> None:
    self._payload = payload

  def raise_for_status(self) -> None:
    return None

  def json(self) -> dict[str, Any]:
    return self._payload


def _local_config(model: str = "qwen2.5:3b") -> dict[str, Any]:
  return {
    "generator": {
      "provider": "local",
      "local": {"base_url": "http://localhost:11434/v1", "model": model},
    }
  }


def _patch_models(monkeypatch: pytest.MonkeyPatch, ids: list[str]) -> None:
  """`/v1/models` 응답을 주어진 모델 목록으로 고정한다."""
  import requests

  monkeypatch.setattr(
    requests, "get", lambda url, timeout=None: _FakeResponse({"data": [{"id": i} for i in ids]})
  )


def test_passes_when_server_lists_the_model(monkeypatch):
  _patch_models(monkeypatch, ["qwen2.5:3b", "korean-pii:latest"])
  note = _preflight_local_generator(_local_config())
  assert "qwen2.5:3b" in note
  assert "Closed API" in note


def test_aborts_when_server_unreachable(monkeypatch):
  import requests

  def _boom(url, timeout=None):
    raise requests.exceptions.ConnectionError("Connection refused")

  monkeypatch.setattr(requests, "get", _boom)
  with pytest.raises(typer.Exit) as excinfo:
    _preflight_local_generator(_local_config())
  assert excinfo.value.exit_code == 1


def test_aborts_when_model_not_registered(monkeypatch):
  # 서버는 살아 있지만 다른 모델만 등록된 상태 — `ollama pull` 을 안 한 경우다.
  _patch_models(monkeypatch, ["korean-pii:latest"])
  with pytest.raises(typer.Exit) as excinfo:
    _preflight_local_generator(_local_config())
  assert excinfo.value.exit_code == 1


def test_non_local_provider_skips_the_check(monkeypatch):
  # provider 가 local 이 아니면 네트워크를 건드리지 않는다.
  import requests

  def _should_not_be_called(url, timeout=None):
    raise AssertionError("provider!=local 인데 서버를 확인했다")

  monkeypatch.setattr(requests, "get", _should_not_be_called)
  monkeypatch.delenv("OPENAI_API_KEY", raising=False)
  monkeypatch.delenv("NAVER_CLOVA_API_KEY", raising=False)
  note = _preflight_local_generator({"generator": {"provider": "auto"}})
  assert "mock" in note
