"""
리랭커 모듈

검색된 문서를 cross-encoder 기반으로 재정렬합니다.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from loguru import logger

_RERANKER_CACHE: dict[str, "SentenceTransformerReranker"] = {}


class SentenceTransformerReranker:
  """
  SentenceTransformers CrossEncoder 기반 리랭커 래퍼입니다.
  """

  def __init__(self, model_name: str) -> None:
    from sentence_transformers import CrossEncoder

    self.model_name = model_name
    self.model = CrossEncoder(model_name)
    logger.debug(f"리랭커 모델 로드 완료: {model_name}")

  def rerank(
    self,
    query: str,
    documents: list[Any],
    top_k: int | None = None,
  ) -> list[Any]:
    """
    질의-문서 쌍 점수를 계산해 문서를 재정렬합니다.
    """
    if not documents:
      return []

    pairs = [(query, getattr(document, "content", "") or "") for document in documents]
    scores = self.model.predict(pairs)

    ranked_documents: list[Any] = []
    for document, score in zip(documents, scores):
      cloned_document = deepcopy(document)
      cloned_document.meta = dict(getattr(cloned_document, "meta", {}) or {})
      cloned_document.meta["retriever_score"] = getattr(document, "score", None)
      cloned_document.meta["reranker_score"] = float(score)
      cloned_document.score = float(score)
      ranked_documents.append(cloned_document)

    ranked_documents.sort(
      key=lambda item: item.score if getattr(item, "score", None) is not None else float("-inf"),
      reverse=True,
    )

    if top_k is not None:
      return ranked_documents[:top_k]
    return ranked_documents


def create_reranker(config: dict[str, Any]) -> SentenceTransformerReranker | None:
  """
  설정에 따라 리랭커를 생성합니다.
  """
  reranker_config = config.get("reranker", {})
  if not reranker_config.get("enabled", False):
    return None

  model_name = reranker_config.get("model_name", "")
  if not model_name:
    raise ValueError("리랭커가 활성화되었지만 model_name이 비어 있습니다.")

  cached = _RERANKER_CACHE.get(model_name)
  if cached is not None:
    return cached

  try:
    reranker = SentenceTransformerReranker(model_name)
  except Exception as error:
    raise ValueError(
      f"리랭커 모델을 로드할 수 없습니다: {model_name}. "
      f"원인: {error}"
    ) from error

  _RERANKER_CACHE[model_name] = reranker
  return reranker
