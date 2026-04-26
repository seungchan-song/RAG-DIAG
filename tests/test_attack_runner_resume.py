"""Tests for AttackRunner resume-oriented skipping behavior."""

from __future__ import annotations

from haystack import Pipeline

import rag.attack.runner as runner_module
from rag.attack.base import AttackResult, BaseAttack
from rag.attack.runner import AttackRunner


class FakeAttack(BaseAttack):
  def generate_queries(self, target_docs):
    return [
      {"query": "q1", "query_id": "q1"},
      {"query": "q2", "query_id": "q2"},
    ]

  def execute(self, query_info, rag_pipeline: Pipeline) -> AttackResult:
    return AttackResult(
      scenario="R2",
      query=query_info["query"],
      response=f"answer:{query_info['query_id']}",
      query_id=query_info["query_id"],
    )


class DummyPipeline:
  pass


def test_attack_runner_skips_completed_query_ids(monkeypatch):
  monkeypatch.setitem(runner_module.SCENARIO_MAP, "R2", FakeAttack)
  runner = AttackRunner(
    {
      "profile_name": "default",
      "retrieval_config": {"reranker": {"enabled": False}},
    }
  )

  results = runner.run(
    scenario="R2",
    rag_pipeline=DummyPipeline(),
    target_docs=[{"doc_id": "doc-1"}],
    completed_query_ids={"q1"},
  )

  assert len(results) == 1
  assert results[0].query_id == "q2"
