"""
설정 관리 모듈

YAML 설정 파일과 .env 환경변수를 통합적으로 관리하는 모듈입니다.
코드를 수정하지 않고도 실험 조건(top_k, 모델 경로 등)을 변경할 수 있게 해줍니다.

사용 예시:
  config = load_config()                    # 기본 설정 로드
  config = load_config("config/custom.yaml") # 커스텀 설정 로드
  top_k = config["retriever"]["top_k"]      # 설정값 접근
"""

import copy
import os
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv
from loguru import logger


def load_env() -> None:
  """
  .env 파일에서 환경변수를 로드합니다.

  .env 파일에는 API 키 등 민감한 정보가 저장되어 있으며,
  이 함수를 호출하면 해당 값들이 os.environ에 등록됩니다.
  .env 파일이 없으면 경고 로그를 출력하고 계속 진행합니다.
  """
  # 프로젝트 루트 디렉토리에서 .env 파일을 찾습니다
  project_root = Path(__file__).parent.parent.parent.parent
  env_path = project_root / ".env"

  if env_path.exists():
    # .env 파일이 존재하면 환경변수로 로드합니다
    load_dotenv(env_path)
    logger.info(f".env 파일 로드 완료: {env_path}")
  else:
    # .env 파일이 없으면 경고만 출력합니다 (프로그램은 계속 실행)
    logger.warning(
      f".env 파일을 찾을 수 없습니다: {env_path}. "
      f".env.example을 복사하여 .env를 만들어주세요."
    )


def _deep_merge_dicts(
  base: dict[str, Any],
  override: dict[str, Any],
) -> dict[str, Any]:
  """
  중첩 딕셔너리를 재귀적으로 병합합니다.
  """
  merged = copy.deepcopy(base)
  for key, value in override.items():
    if isinstance(value, dict) and isinstance(merged.get(key), dict):
      merged[key] = _deep_merge_dicts(merged[key], value)
    else:
      merged[key] = copy.deepcopy(value)
  return merged


def build_retrieval_config(config: dict[str, Any]) -> dict[str, Any]:
  """
  현재 설정에서 retrieval 관련 런타임 스냅샷을 추출합니다.
  """
  retriever_config = copy.deepcopy(config.get("retriever", {}))
  reranker_config = copy.deepcopy(config.get("reranker", {}))

  return {
    "top_k": retriever_config.get("top_k", 5),
    "similarity_threshold": retriever_config.get("similarity_threshold", 0.0),
    "reranker": {
      "enabled": bool(reranker_config.get("enabled", False)),
      "model_name": reranker_config.get("model_name", ""),
      "top_k": reranker_config.get(
        "top_k",
        retriever_config.get("top_k", 5),
      ),
    },
  }


def load_config(
  config_path: str | None = None,
  profile: str = "default",
) -> dict[str, Any]:
  """
  YAML 설정 파일을 읽어서 딕셔너리로 반환합니다.

  Args:
    config_path: YAML 설정 파일 경로.
                 None이면 환경변수 RAG_CONFIG_PATH 또는 기본값(config/default.yaml) 사용.
    profile: 사용할 설정 프로파일명.

  Returns:
    설정값이 담긴 딕셔너리. 예: {"retriever": {"top_k": 5}, ...}

  Raises:
    FileNotFoundError: 설정 파일을 찾을 수 없을 때
    ValueError: 지정한 profile이 설정 파일에 없을 때
  """
  # 설정 파일 경로 결정 (우선순위: 인자 > 환경변수 > 기본값)
  if config_path is None:
    config_path = os.getenv("RAG_CONFIG_PATH", "config/default.yaml")

  config_file = Path(config_path)

  # 상대 경로인 경우 프로젝트 루트 기준으로 변환합니다
  if not config_file.is_absolute():
    project_root = Path(__file__).parent.parent.parent.parent
    config_file = project_root / config_file

  if not config_file.exists():
    raise FileNotFoundError(
      f"설정 파일을 찾을 수 없습니다: {config_file}. "
      f"config/default.yaml 파일이 존재하는지 확인해주세요."
    )

  # YAML 파일을 읽어서 딕셔너리로 파싱합니다
  with open(config_file, "r", encoding="utf-8") as f:
    raw_config = yaml.safe_load(f) or {}

  profiles = raw_config.pop("profiles", {})
  if profile != "default" and profile not in profiles:
    available_profiles = ", ".join(sorted(profiles.keys())) or "없음"
    raise ValueError(
      f"설정 프로파일을 찾을 수 없습니다: {profile}. "
      f"사용 가능: {available_profiles}"
    )

  profile_overrides = profiles.get(profile, {})
  config = _deep_merge_dicts(raw_config, profile_overrides)
  config["profile_name"] = profile
  config["retrieval_config"] = build_retrieval_config(config)

  logger.info(
    f"설정 파일 로드 완료: {config_file} "
    f"(profile={profile})"
  )
  return config


def get_env(key: str, default: str | None = None) -> str | None:
  """
  환경변수 값을 안전하게 가져옵니다.

  Args:
    key: 환경변수 이름 (예: "OPENAI_API_KEY")
    default: 환경변수가 없을 때 반환할 기본값

  Returns:
    환경변수 값 또는 기본값
  """
  value = os.getenv(key, default)
  if value is None:
    logger.warning(f"환경변수 '{key}'가 설정되지 않았습니다.")
  return value
