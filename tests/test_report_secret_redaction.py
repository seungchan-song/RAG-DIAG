"""HTML 리포트가 대상 RAG 의 비밀값을 밖으로 내보내지 않는지 고정하는 회귀 테스트.

왜 이 파일이 있나 — `report_dashboard.html` 은 심사위원·고객에게 건네라고 만든
유일한 산출물인데, `report/generator.py` 가 `snapshot.config.adapter` 를 통째로
JSON 임베드한다. `adapter.type` 이 rest/sota 면 그 블록에 외부 RAG 의 Bearer
토큰(`adapter.api_key`)이 들어 있어, 예전에는 **평문 그대로 실려 나갔다**
(2026-08-06 실측 확인).

프로젝트에는 이미 `experiment.py:SECRET_FIELD_TOKENS` 정책이 있었는데 config diff
렌더링에만 적용돼 있었다. 이 테스트는 그 정책이 **리포트 경계에도** 걸려 있는지를
고정한다. 동시에 대시보드가 실제로 읽는 필드(`adapter.type`·`capabilities`·
`generator`)는 살아 있어야 하므로 함께 확인한다.

참고: `snapshot.yaml` 원본은 일부러 가리지 않는다 — `replay` 가 저장된 config 를
그대로 복원해 재실행하므로(`cli/main.py:_resolve_replay_config`) 여기서 값을
치환하면 외부 어댑터 재현이 깨진다. 유출 경계는 '리포트'이지 '로컬 산출물'이 아니다.
"""

from __future__ import annotations

import json

from rag.report.dashboard_template import render_dashboard

_SECRET = "sk-DO-NOT-SHIP-THIS-TOKEN"

# 주의: `redact_secrets` 는 각 테스트 안에서 임포트한다. 모듈 최상단에서 끌어오면
# 헬퍼가 없던 시절 이 파일 전체가 collection error 로 죽어, 정작 핵심인
# "리포트가 토큰을 흘리는가" 테스트가 red 로 보이지 않는다.


def _snapshot_with_secret() -> dict:
  return {
    "config": {
      "generator": {"provider": "openai", "model": "gpt-4o-mini"},
      "adapter": {
        "type": "rest",
        "base_url": "http://localhost:3001",
        "api_key": _SECRET,
        "capabilities": ["query", "retrieval_trace"],
      },
    }
  }


def test_redact_secrets_masks_only_secret_fields():
  """비밀 필드만 가리고 구조·다른 값은 그대로 보존한다."""
  from rag.utils.experiment import redact_secrets

  redacted = redact_secrets(_snapshot_with_secret())
  adapter = redacted["config"]["adapter"]

  assert adapter["api_key"] == "<redacted>"
  # 대시보드가 읽는 필드는 살아 있어야 한다.
  assert adapter["type"] == "rest"
  assert adapter["capabilities"] == ["query", "retrieval_trace"]
  assert adapter["base_url"] == "http://localhost:3001"
  assert redacted["config"]["generator"]["model"] == "gpt-4o-mini"


def test_redact_secrets_covers_nested_and_listed_values():
  """중첩 dict / list 안쪽의 비밀 필드도 빠짐없이 가린다."""
  from rag.utils.experiment import redact_secrets

  payload = {
    "pii": {"sllm": {"api_key": _SECRET, "model": "qwen"}},
    "targets": [{"authorization": _SECRET}, {"password": _SECRET}],
    "nested": {"deep": {"access_token": _SECRET}},
  }
  redacted = redact_secrets(payload)

  assert _SECRET not in json.dumps(redacted, ensure_ascii=False)
  assert redacted["pii"]["sllm"]["model"] == "qwen"


def test_redact_secrets_does_not_mutate_input():
  """원본 설정을 훼손하지 않는다 — 같은 dict 를 실행 경로가 계속 쓴다."""
  from rag.utils.experiment import redact_secrets

  original = _snapshot_with_secret()
  redact_secrets(original)
  assert original["config"]["adapter"]["api_key"] == _SECRET


def test_rendered_dashboard_never_contains_adapter_api_key():
  """실제 렌더 산출물에 토큰이 남지 않는다 (유출 경로 그 자체를 고정)."""
  from rag.utils.experiment import redact_secrets

  snapshot = _snapshot_with_secret()
  html = render_dashboard(
    run_id="RAG-TEST-0001",
    generated_at="2026-01-01 00:00:00",
    summary_json="{}",
    scenario_results_json="[]",
    snapshot_json=json.dumps(redact_secrets(snapshot), ensure_ascii=False),
  )

  assert _SECRET not in html
  assert "<redacted>" in html
  # 진단 대상 블록이 렌더될 수 있도록 어댑터 타입은 남아 있어야 한다.
  assert '"type": "rest"' in html or '"type":"rest"' in html


def test_report_generator_redacts_before_embedding(tmp_path, monkeypatch):
  """ReportGenerator 경로 자체가 레닥션을 통과시키는지 확인한다.

  render_dashboard 를 가로채 실제로 넘어온 snapshot_json 을 들여다본다 —
  호출부가 redact_secrets 를 빼먹으면 여기서 잡힌다.
  """
  captured: dict[str, str] = {}

  def _fake_render(**kwargs):
    captured.update(kwargs)
    return "<html></html>"

  from rag.report import dashboard_template
  from rag.report.generator import ReportGenerator

  # _generate_html_dashboard 는 render_dashboard 를 함수 안에서 지연 임포트하므로
  # 원본 모듈 쪽을 갈아끼워야 가로채진다.
  monkeypatch.setattr(dashboard_template, "render_dashboard", _fake_render)

  ReportGenerator({})._generate_html_dashboard(
    tmp_path,
    {"run_id": "RAG-TEST-0002", "generated_at": "2026-01-01T00:00:00"},
    {},
    snapshot=_snapshot_with_secret(),
  )

  assert _SECRET not in captured["snapshot_json"]
  assert "<redacted>" in captured["snapshot_json"]
