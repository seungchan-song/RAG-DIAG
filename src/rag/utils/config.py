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
import re
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
  project_root = Path(__file__).parent.parent.parent.parent
  env_path = project_root / ".env"

  if env_path.exists():
    load_dotenv(env_path)
    logger.info(f".env 파일 로드 완료: {env_path}")
  else:
    logger.warning(
      f".env 파일을 찾을 수 없습니다: {env_path}. "
      f".env.example을 복사하여 .env를 만들어주세요."
    )


# `${VAR}` 형태만 정확히 인식한다. `$` 를 무차별 확장하면 system_prompt 같은
# 자유 텍스트가 조용히 깨질 수 있어 범위를 좁게 잡는다.
_ENV_PLACEHOLDER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env_placeholders(value: Any) -> Any:
  """설정값 안의 `${VAR}` 를 환경변수 값으로 치환한 사본을 돌려준다.

  왜 필요한가 — `config/default.yaml` 은 예전부터
  `api_key: "${ANYTHINGLLM_API_KEY}"` 처럼 쓰라고 안내해 왔는데 치환 로직이 아예
  없었다. 그대로 두면 리터럴 문자열 `${ANYTHINGLLM_API_KEY}` 가 Bearer
  토큰으로 전송돼 401 만 보고 원인을 못 찾는다(외부 RAG 실증에서 바로 밟을 지뢰).
  동시에 비밀값을 yaml 에 적지 않아도 되는 정석 경로가 열린다.

  환경변수가 없으면 빈 문자열로 치환하고 경고한다. 자리표시자를 그대로 두면
  가짜 토큰을 실제로 보내게 되는데, 빈 값이면 호출부가 헤더를 아예 안 붙여
  (`adapters/rest.py`) 실패 원인이 로그에 남는다.

  Args:
    value: 설정 딕셔너리/리스트/문자열/스칼라. 원본은 변경하지 않는다.

  Returns:
    Any: 치환된 새 객체. 문자열이 아닌 값은 그대로 통과한다.
  """
  if isinstance(value, dict):
    return {key: expand_env_placeholders(item) for key, item in value.items()}
  if isinstance(value, list):
    return [expand_env_placeholders(item) for item in value]
  if not isinstance(value, str) or "${" not in value:
    return value

  def _replace(match: "re.Match[str]") -> str:
    name = match.group(1)
    resolved = os.getenv(name)
    if resolved is None:
      logger.warning(
        "설정의 ${{{}}} 를 채울 환경변수가 없습니다. 빈 값으로 둡니다 — "
        ".env 에 {}=... 을 추가하세요.",
        name,
        name,
      )
      return ""
    return resolved

  return _ENV_PLACEHOLDER.sub(_replace, value)


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

  if not config_file.is_absolute():
    project_root = Path(__file__).parent.parent.parent.parent
    config_file = project_root / config_file

  if not config_file.exists():
    raise FileNotFoundError(
      f"설정 파일을 찾을 수 없습니다: {config_file}. "
      f"config/default.yaml 파일이 존재하는지 확인해주세요."
    )

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
  # `${VAR}` 치환은 프로파일 병합 이후에 한다 — 프로파일이 덮어쓴 값에도
  # 동일하게 적용돼야 하기 때문. load_env() 가 CLI 진입점에서 먼저 돌아
  # .env 값이 os.environ 에 올라와 있는 상태를 전제한다.
  config = expand_env_placeholders(config)
  config["profile_name"] = profile
  config["retrieval_config"] = build_retrieval_config(config)

  logger.info(
    f"설정 파일 로드 완료: {config_file} "
    f"(profile={profile})"
  )
  return config
