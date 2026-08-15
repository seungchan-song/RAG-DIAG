"""
대상 RAG 의 가드레일 판정이 리포트 문장까지 살아서 도착하는지 관통 검증합니다.

왜 이 테스트가 필요한가:
  이 프로젝트의 핵심 주장은 "방어 효과를 정량화한다" 이다. 그런데 대상 RAG(외부
  어댑터)가 공격을 막아서 유출이 0 인 경우와, 애초에 유출될 게 없어서 0 인
  경우는 리포트에서 완전히 똑같아 보인다 — 대상이 보고한 `is_blocked` 를 어딘가에서
  떨어뜨리면 그렇게 된다. 실제로 `RagTrace.to_engine_dict()` 가 외부 어댑터의
  metadata 를 통째로 버리고 있었고, 그래서 이 경로 전체를 테스트로 고정한다.

무엇을 검증하는가 (관통 경로):
  SOTA 응답(is_blocked=true)
    → SotaRagAdapter.query()          … RagTrace.metadata
    → RagTrace.to_engine_dict()       … trace["target_metadata"]
    → NormalBaselineAttack.execute()  … AttackResult.metadata["target_metadata"]
    → summarize_evaluated_results()   … summary["target_blocked_count"]
    → _scenario_evidence()            … 리포트에 렌더되는 한국어 문장

서버 없이 도는 이유:
  `SotaRagAdapter` 가 transport 주입식이라 가짜 SOTA 를 함수 하나로 세울 수 있다.
  RunPod pod·GPU·vLLM 없이 배선만 검증한다. 실제 가드레일이 진짜로 발동하는지는
  이 테스트의 범위가 아니다(그건 pod 에서 실측해야 한다).
"""

from typing import Any

from rag.adapters import SotaRagAdapter
from rag.attack.normal_baseline import NormalBaselineAttack
from rag.evaluator.normal_evaluator import NormalEvaluator
from rag.evaluator.summary import summarize_evaluated_results
from rag.report.narrative import _scenario_evidence


def _blocking_sota_transport(
  url: str, payload: dict[str, Any], headers: dict[str, str]
) -> dict[str, Any]:
  """가드레일이 질의를 차단한 SOTA_RAG 응답을 흉내 냅니다.

  차단 시 SOTA 는 답변 문자열 자체가 거부 메시지이고, is_blocked 와 guardrails 가
  함께 실려 온다(런북 §6.3 스모크 테스트가 확인하는 그 형태).
  """
  return {
    "answer": "요청하신 정보는 제공할 수 없습니다.",
    "sources": [],
    "is_blocked": True,
    "guardrails": [{"name": "PromptInjectionDetector", "verdict": "block"}],
    "metadata": {"model": "Qwen2.5-32B-Instruct-AWQ"},
  }


def _passthrough_sota_transport(
  url: str, payload: dict[str, Any], headers: dict[str, str]
) -> dict[str, Any]:
  """가드레일이 통과시킨(차단하지 않은) SOTA_RAG 응답을 흉내 냅니다."""
  return {
    "answer": "담당자 연락처는 문서에 있습니다.",
    "sources": [{"content": "본문", "source_file": "/root/rag-corpus/normal/n1.txt"}],
    "is_blocked": False,
    "guardrails": [{"name": "PromptInjectionDetector", "verdict": "pass"}],
  }


def _run_normal_against(transport, count: int) -> list:
  """가짜 SOTA 를 대상으로 NORMAL 시나리오를 count 건 실행해 평가까지 마칩니다."""
  target = SotaRagAdapter(
    base_url="http://x:8080",
    documents_root="/root/rag-corpus",
    transport=transport,
  )
  attack = NormalBaselineAttack({}, target=target)
  evaluator = NormalEvaluator({})

  queries = attack.generate_queries([])[:count]
  assert queries, "NORMAL 은 데이터셋 비의존이라 target_docs 가 비어도 쿼리가 나와야 한다"

  # rag_pipeline 은 target 이 주입되면 쓰이지 않으므로 None 을 넘긴다.
  return [evaluator.evaluate(attack.execute(q, None)) for q in queries]


def test_guardrail_block_survives_from_adapter_to_report_sentence():
  """차단된 응답이 요약 집계와 리포트 문장까지 도달해야 한다."""
  results = _run_normal_against(_blocking_sota_transport, count=3)

  # ① 어댑터 → 공격 결과
  assert results[0].metadata["target_metadata"]["is_blocked"] is True

  # ② 공격 결과 → 요약 집계
  summary = summarize_evaluated_results("NORMAL", {}, results)
  assert summary["target_reported_count"] == 3
  assert summary["target_blocked_count"] == 3

  # ③ 요약 → 리포트가 실제로 렌더하는 문장
  evidence = _scenario_evidence("NORMAL", summary)
  assert any("가드레일" in line and "3건을 차단" in line for line in evidence), evidence


def test_unblocked_target_reports_zero_blocks():
  """대상이 차단하지 않았으면 차단 수는 0 이고 문장도 나오지 않아야 한다.

  '보고는 받았지만 차단은 없었다'와 '아무 보고도 없었다'는 다른 상태이므로,
  reported 는 세되 blocked 는 0 이어야 한다.
  """
  results = _run_normal_against(_passthrough_sota_transport, count=2)

  summary = summarize_evaluated_results("NORMAL", {}, results)
  assert summary["target_reported_count"] == 2
  assert summary["target_blocked_count"] == 0
  assert not any("가드레일" in line for line in _scenario_evidence("NORMAL", summary))


def test_builtin_target_produces_no_guardrail_noise():
  """우리 builtin RAG 경로(대상 메타데이터 없음)에서는 빈 집계여야 한다.

  가드레일이 없는 대상에까지 '0건 차단' 같은 문장이 나가면 리포트에 의미 없는
  노이즈가 쌓인다. 대상이 아무것도 보고하지 않으면 조용해야 한다.
  """
  from rag.attack.base import AttackResult

  results = [AttackResult(scenario="NORMAL", query="q", response="a") for _ in range(2)]

  summary = summarize_evaluated_results("NORMAL", {}, results)
  assert summary["target_reported_count"] == 0
  assert summary["target_blocked_count"] == 0
  assert not any("가드레일" in line for line in _scenario_evidence("NORMAL", summary))
