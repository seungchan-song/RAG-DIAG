"""Tests for retrieval controls and trace capture in run_query()."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from rag.retriever.pipeline import NO_CONTEXT_RESPONSE, apply_similarity_threshold, run_query


@dataclass
class DummyDocument:
  id: str
  score: float
  content: str
  meta: dict[str, Any] = field(default_factory=dict)


class FakeQueryEmbedder:
  def run(self, text: str) -> dict[str, Any]:
    return {"embedding": [0.1, 0.2, 0.3], "text": text}


class FakeRetriever:
  def __init__(self, documents: list[DummyDocument]) -> None:
    self.documents = documents

  def run(self, query_embedding: list[float]) -> dict[str, Any]:
    assert query_embedding
    return {"documents": list(self.documents)}


class FakePromptBuilder:
  def __init__(self) -> None:
    self.calls: list[dict[str, Any]] = []

  def run(self, documents: list[DummyDocument], query: str) -> dict[str, Any]:
    self.calls.append({"documents": documents, "query": query})
    prompt = f"question={query}; docs={','.join(doc.id for doc in documents)}"
    return {"prompt": prompt}


class FakeGenerator:
  def __init__(self) -> None:
    self.prompts: list[str] = []

  def run(self, prompt: str) -> dict[str, Any]:
    self.prompts.append(prompt)
    return {"replies": [f"generated from {prompt}"], "meta": [{"model": "fake"}]}


class FakeReranker:
  def __init__(self) -> None:
    self.calls: list[dict[str, Any]] = []

  def rerank(
    self,
    query: str,
    documents: list[DummyDocument],
    top_k: int | None = None,
  ) -> list[DummyDocument]:
    self.calls.append({"query": query, "documents": documents, "top_k": top_k})
    reranked = [
      DummyDocument(
        id=doc.id,
        score=doc.score + 0.5,
        content=doc.content,
        meta={**doc.meta, "reranked": True},
      )
      for doc in reversed(documents)
    ]
    if top_k is None:
      return reranked
    return reranked[:top_k]


class FakePipeline:
  def __init__(
    self,
    *,
    documents: list[DummyDocument],
    retrieval_config: dict[str, Any],
    reranker: FakeReranker | None = None,
  ) -> None:
    self.components = {
      "query_embedder": FakeQueryEmbedder(),
      "retriever": FakeRetriever(documents),
      "prompt_builder": FakePromptBuilder(),
      "generator": FakeGenerator(),
    }
    self._rag_runtime = {
      "profile_name": "test-profile",
      "retrieval_config": retrieval_config,
      "reranker": reranker,
    }

  def get_component(self, name: str) -> Any:
    return self.components[name]


def test_apply_similarity_threshold_filters_low_scores():
  documents = [
    DummyDocument(id="a", score=0.9, content="a"),
    DummyDocument(id="b", score=0.4, content="b"),
    DummyDocument(id="c", score=0.7, content="c"),
  ]

  filtered = apply_similarity_threshold(documents, 0.5)
  assert [doc.id for doc in filtered] == ["a", "c"]


def test_run_query_records_raw_thresholded_and_reranked_documents():
  documents = [
    DummyDocument(id="a", score=0.9, content="doc-a", meta={"doc_id": "a"}),
    DummyDocument(id="b", score=0.6, content="doc-b", meta={"doc_id": "b"}),
    DummyDocument(id="c", score=0.2, content="doc-c", meta={"doc_id": "c"}),
  ]
  reranker = FakeReranker()
  pipeline = FakePipeline(
    documents=documents,
    retrieval_config={
      "top_k": 5,
      "similarity_threshold": 0.5,
      "reranker": {"enabled": True, "model_name": "fake-reranker", "top_k": 2},
    },
    reranker=reranker,
  )

  result = run_query(pipeline, "test question")

  assert result["profile_name"] == "test-profile"
  assert result["retrieval_config"]["reranker"]["enabled"] is True
  assert result["reranker_enabled"] is True
  assert len(result["raw_retrieved_documents"]) == 3
  assert len(result["thresholded_documents"]) == 2
  assert len(result["reranked_documents"]) == 2
  assert [doc["id"] for doc in result["retrieved_documents"]] == ["b", "a"]
  assert result["final_prompt"] == "question=test question; docs=b,a"
  assert reranker.calls[0]["top_k"] == 2


def test_run_query_returns_no_context_fallback_without_calling_generator():
  documents = [
    DummyDocument(id="a", score=0.2, content="doc-a", meta={"doc_id": "a"}),
  ]
  pipeline = FakePipeline(
    documents=documents,
    retrieval_config={
      "top_k": 5,
      "similarity_threshold": 0.9,
      "reranker": {"enabled": False, "model_name": "", "top_k": 5},
    },
  )

  result = run_query(pipeline, "empty context question")

  assert result["context_empty"] is True
  assert result["generator"]["replies"] == [NO_CONTEXT_RESPONSE]
  assert result["retrieved_documents"] == []
  assert pipeline.get_component("generator").prompts == []
