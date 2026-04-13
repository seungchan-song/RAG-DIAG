"""
문서 임베딩 모듈

분할된 청크들을 벡터(숫자 배열)로 변환합니다.
이 벡터가 FAISS 인덱스에 저장되어 나중에 유사도 검색에 사용됩니다.

핵심 개념:
  - 임베딩(Embedding): 텍스트를 고차원 벡터로 변환하는 것
  - 유사한 의미의 텍스트는 벡터 공간에서 가까이 위치합니다
  - 모델: dragonkue/BGE-m3-ko (한국어 특화 임베딩 모델)

사용 예시:
  embedder = create_document_embedder(config)
  result = embedder.run(documents=documents)
"""

from typing import Any

from haystack.components.embedders import SentenceTransformersDocumentEmbedder
from haystack.utils import ComponentDevice
from loguru import logger


def create_document_embedder(config: dict[str, Any]) -> SentenceTransformersDocumentEmbedder:
  """
  문서 청크를 벡터로 변환하는 임베딩 컴포넌트를 생성합니다.

  SentenceTransformers 라이브러리를 사용하여 dragonkue/BGE-m3-ko 모델을 로드하고,
  각 Document의 content를 벡터로 변환합니다.

  Args:
    config: YAML에서 로드한 설정 딕셔너리.
            config["embedding"] 아래의 model_name, device를 사용합니다.

  Returns:
    SentenceTransformersDocumentEmbedder: 문서 임베딩 컴포넌트

  주의사항:
    - 최초 실행 시 모델 다운로드에 시간이 걸릴 수 있습니다 (~1GB)
    - GPU가 없으면 device="cpu"로 설정합니다 (느리지만 동작함)
  """
  # 설정값 읽기
  embedding_config = config.get("embedding", {})
  model_name = embedding_config.get("model_name", "dragonkue/BGE-m3-ko")
  device_str = embedding_config.get("device", "cpu")

  # Haystack v2에서는 ComponentDevice 객체를 사용해야 합니다
  device = ComponentDevice.from_str(device_str)

  embedder = SentenceTransformersDocumentEmbedder(
    model=model_name,  # 사용할 임베딩 모델
    device=device,     # 실행 장치 (cpu/cuda)
    # 메타데이터 필드도 임베딩에 포함할지 여부 (기본: content만)
    meta_fields_to_embed=[],
  )

  logger.debug(f"문서 임베딩기 생성 완료 (모델: {model_name}, 장치: {device})")
  return embedder
