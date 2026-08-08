"""탐지기가 빠진 채로 나온 수치가 조용히 통과하지 못하게 막습니다.

배경(RAG-2026-0806-001, 2026-08-06 실측):
  응답 1,468건 중 611건(41.6%)이 NER 없이 채점됐는데 **실행 실패는 0건**이었다.
  CLI 화면은 완벽한 런이었고, HTML 대시보드에는 step3 관련 표시가 아예 없었으며
  (문자열 0건), 신호는 `report_summary.json` 안쪽에만 있었다. 즉 "유출이 적었다"와
  "탐지기가 죽어서 못 봤다"가 사용자에게 똑같이 보였다.

  원인(HF fast 토크나이저 스레드 경쟁)은 락으로 닫았지만 탐지기가 죽는 길은 그것
  말고도 있다 — 모델 다운로드 실패 · 캐시 손상 · OOM · 마스킹 예외.
  그래서 원인마다 막는 대신 **결과를 항상 세어 노출**하고, 그 계약을 여기서 고정한다.
"""

from __future__ import annotations

import json

from rag.report.generator import ReportGenerator


def _profile(**scenarios) -> dict:
  """시나리오별 step3_load_status 만 담은 최소 pii_leakage_profile 을 만든다."""
  return {name: {"step3_load_status": status} for name, status in scenarios.items()}


def test_all_ready_is_reliable() -> None:
  quality = ReportGenerator({})._build_detection_quality(
    _profile(NORMAL={"ready": 100}, R2={"ready": 200})
  )

  assert quality["is_reliable"] is True
  assert quality["degraded_response_count"] == 0
  assert quality["degraded_ratio"] == 0.0


def test_degraded_responses_are_counted_and_attributed() -> None:
  """실측 런의 형태 그대로 — 사유·시나리오·비율이 다 남아야 원인을 추적한다."""
  quality = ReportGenerator({})._build_detection_quality(
    _profile(
      NORMAL={"ready": 201, "failed": 86, "masking_unavailable": 1},
      R2={"ready": 141, "failed": 398, "masking_unavailable": 1},
      R7={"ready": 120},
    )
  )

  assert quality["is_reliable"] is False
  assert quality["degraded_response_count"] == 486
  assert quality["response_count"] == 948
  assert round(quality["degraded_ratio"], 4) == round(486 / 948, 4)
  assert quality["degraded_reasons"] == {"failed": 484, "masking_unavailable": 2}
  # 정상인 시나리오는 목록에 끼지 않아야 어디를 봐야 할지가 분명해진다.
  assert set(quality["degraded_scenarios"]) == {"NORMAL", "R2"}
  assert quality["degraded_scenarios"]["R2"] == {"total": 540, "degraded": 399}


def test_summary_carries_detection_quality(tmp_path) -> None:
  """리포트 요약에 블록이 실제로 실려야 대시보드가 그릴 수 있다."""
  from rag.utils.experiment import ExperimentManager

  config = {"report": {"output_dir": str(tmp_path), "output_formats": ["json"]}}
  manager = ExperimentManager(config)
  run_id = manager.create_run()
  manager.save_snapshot(run_id, config)

  manager.save_result(
    run_id,
    {
      "scenario": "R2",
      "total": 1,
      "success_count": 0,
      "results": [
        {
          "scenario": "R2",
          "query": "q",
          "response": "r",
          "success": False,
          "pii_summary": {"total": 0},
          "pii_runtime_status": {"step3": {"load_status": "failed"}},
        }
      ],
    },
    "R2_result.json",
  )

  ReportGenerator(config).generate(run_id)
  with open(tmp_path / run_id / "report_summary.json", "r", encoding="utf-8") as file:
    quality = json.load(file)["detection_quality"]
  assert quality["is_reliable"] is False
  assert quality["degraded_response_count"] == 1


def test_cli_warns_when_detection_is_missing(capsys) -> None:
  """셀이 끝날 때 CLI 가 크게 경고해야 한다 — 실행 실패 0건이어도."""
  from rag.attack.base import AttackResult
  from rag.cli.main import _warn_if_detection_degraded

  results = [
    AttackResult(
      scenario="R2",
      query="q",
      response="r",
      pii_runtime_status={"step3": {"load_status": "failed"}},
    ),
    AttackResult(
      scenario="R2",
      query="q",
      response="r",
      pii_runtime_status={"step3": {"load_status": "ready"}},
    ),
  ]

  _warn_if_detection_degraded(results)

  output = capsys.readouterr().out
  assert "PII 탐지 누락" in output
  assert "1/2" in output


def test_cli_stays_quiet_on_healthy_run(capsys) -> None:
  """정상 런에서는 아무 말도 하지 않는다(경고 피로 방지)."""
  from rag.attack.base import AttackResult
  from rag.cli.main import _warn_if_detection_degraded

  _warn_if_detection_degraded(
    [
      AttackResult(
        scenario="R2",
        query="q",
        response="r",
        pii_runtime_status={"step3": {"load_status": "ready"}},
      )
    ]
  )

  assert capsys.readouterr().out == ""
