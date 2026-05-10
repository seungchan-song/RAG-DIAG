"""
질의 임베딩 모듈

사용자의 질문(query)을 벡터로 변환합니다.
문서 임베딩과 동일한 모델을 사용하여 같은 벡터 공간에서 유사도를 비교합니다.

핵심 개념:
  - 질의 임베딩: 사용자 질문을 벡터로 변환
  - 문서 임베딩과 동일한 모델을 써야 유사도 비교가 의미 있음
  - 질의는 하나의 텍스트이므로 TextEmbedder를 사용 (DocumentEmbedder와 구분)

사용 예시:
  query_embedder = create_query_embedder(config)
  result = query_embedder.run(text="한국의 개인정보보호법에 대해 알려줘")
"""

from typing import Any

from haystack.components.embedders import SentenceTransformersTextEmbedder
from haystack.utils import ComponentDevice
from loguru import logger


def create_query_embedder(config: dict[str, Any]) -> SentenceTransformersTextEmbedder:
    """
    질의 텍스트를 벡터로 변환하는 임베딩 컴포넌트를 생성합니다.

    문서 임베딩(ingest/embedder.py)과 동일한 모델을 사용합니다.
    같은 모델을 사용해야 문서-질의 간 유사도 비교가 정확합니다.

    Args:
      config: YAML에서 로드한 설정 딕셔너리.
              config["embedding"]["model_name"]에서 모델명을 읽습니다.

    Returns:
      SentenceTransformersTextEmbedder: 질의 임베딩 컴포넌트
    """
    embedding_config = config.get("embedding", {})
    model_name = embedding_config.get("model_name", "dragonkue/BGE-m3-ko")
    device_str = embedding_config.get("device", "cpu")

    # Haystack v2에서는 ComponentDevice 객체를 사용해야 합니다
    device = ComponentDevice.from_str(device_str)

    embedder = SentenceTransformersTextEmbedder(
        model=model_name,
        device=device,
        progress_bar=False,
    )

    logger.debug(f"질의 임베딩기 생성 완료 (모델: {model_name})")
    return embedder
