"""PII 위험 등급(identifier/contact/context) 집계 회귀 테스트.

리포트 1장 '유출 규모'의 등급별 차분표가 이 집계를 그대로 렌더한다. 총량 차분만
맞고 등급 분해가 틀리면 "주민번호가 샜다"와 "이름이 샜다"가 리포트에서 같아진다.
"""

from __future__ import annotations

from rag.pii.classifier import count_by_risk_tier, risk_tier
from rag.report.generator import ReportGenerator


def _result(by_tag: dict[str, int]) -> dict:
  return {
    "response": "resp",
    "pii_summary": {"total": sum(by_tag.values()), "by_tag": by_tag},
    "metadata": {"env": "clean", "reranker_state": "off"},
  }


def test_risk_tier_mapping():
  assert risk_tier("QT_RRN") == "identifier"
  assert risk_tier("QT_MOBILE") == "contact"
  # 매핑에 없는 태그(NER 이름 등)는 전부 context 로 떨어져 집계가 새지 않는다.
  assert risk_tier("PER") == "context"
  assert count_by_risk_tier({"QT_RRN": 2, "QT_MOBILE": 1, "PER": 4}) == {
    "identifier": 2,
    "contact": 1,
    "context": 4,
  }


def test_summarize_pii_results_counts_by_tier(tmp_path):
  gen = ReportGenerator({"report": {"output_dir": str(tmp_path), "output_formats": []}})
  stats = gen._summarize_pii_results([
    _result({"QT_RRN": 1, "PER": 2}),
    _result({"QT_MOBILE": 3}),
  ])
  assert stats["total_pii_count"] == 6
  assert stats["pii_by_risk"] == {"identifier": 1, "contact": 3, "context": 2}


def test_delta_entry_splits_delta_by_tier(tmp_path):
  gen = ReportGenerator({"report": {"output_dir": str(tmp_path), "output_formats": []}})
  baseline = gen._summarize_pii_results([_result({"QT_RRN": 1, "PER": 10})])
  attack = gen._summarize_pii_results([_result({"QT_RRN": 5, "PER": 12})])
  entry = gen._build_pii_delta_entry(baseline, attack)

  # 총량은 6건 늘었을 뿐이지만, 고유식별정보는 5배로 뛰었다는 사실이 살아 있어야 한다.
  assert entry["pii_delta_total"] == 6
  ident = entry["pii_delta_by_risk"]["identifier"]
  assert (ident["baseline"], ident["attack"], ident["delta"]) == (1, 5, 4)
  assert ident["ratio"] == 5.0
  # 등급 키는 0 이어도 항상 3개 다 있어야 표의 칸이 어긋나지 않는다.
  assert set(entry["pii_delta_by_risk"]) == {"identifier", "contact", "context"}
  assert entry["pii_delta_by_risk"]["contact"]["ratio"] == 0.0
