"""
실험 관리 모듈

각 실험 실행에 고유한 run_id를 부여하고, 실험 시점의 설정 스냅샷을 저장합니다.
이를 통해 나중에 동일한 조건으로 실험을 재현할 수 있습니다.

사용 예시:
  manager = ExperimentManager(config)
  run_id = manager.create_run()           # 고유한 실험 ID 생성
  manager.save_snapshot(run_id, config)   # 설정 스냅샷 저장
  manager.save_result(run_id, result)     # 실험 결과 저장
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

import yaml
from loguru import logger


class ExperimentManager:
  """
  실험의 생성, 설정 저장, 결과 기록을 관리하는 클래스입니다.

  각 실험은 고유한 run_id를 가지며, 해당 실험의 모든 정보가
  results_dir/run_id/ 디렉토리에 저장됩니다.
  """

  def __init__(self, config: dict[str, Any]) -> None:
    """
    ExperimentManager를 초기화합니다.

    Args:
      config: YAML에서 로드한 설정 딕셔너리.
              config["report"]["output_dir"]에서 결과 저장 경로를 읽습니다.
    """
    # 결과 저장 경로 설정 (환경변수 > 설정파일 > 기본값)
    self.results_dir = Path(
      os.getenv(
        "RAG_RESULTS_PATH",
        config.get("report", {}).get("output_dir", "data/results")
      )
    )
    # 결과 저장 디렉토리가 없으면 자동 생성합니다
    self.results_dir.mkdir(parents=True, exist_ok=True)

  def create_run(self, prefix: str = "RAG") -> str:
    """
    고유한 실험 ID(run_id)를 생성합니다.

    형식: {prefix}-{날짜}-{순번}
    예시: RAG-2026-0413-001

    Args:
      prefix: run_id 앞에 붙는 접두사 (기본값: "RAG")

    Returns:
      생성된 run_id 문자열 (예: "RAG-2026-0413-001")
    """
    # 오늘 날짜를 YYYY-MMDD 형식으로 생성합니다
    today = datetime.now().strftime("%Y-%m%d")

    # 같은 날짜에 이미 만들어진 실험이 있으면 순번을 증가시킵니다
    existing_runs = list(self.results_dir.glob(f"{prefix}-{today}-*"))
    next_num = len(existing_runs) + 1

    # 최종 run_id 생성 (예: RAG-2026-0413-001)
    run_id = f"{prefix}-{today}-{next_num:03d}"

    # 해당 실험의 결과 저장 디렉토리를 생성합니다
    run_dir = self.results_dir / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"새 실험 생성: {run_id} (저장 경로: {run_dir})")
    return run_id

  def save_snapshot(self, run_id: str, config: dict[str, Any]) -> Path:
    """
    실험 시점의 설정 스냅샷을 YAML 파일로 저장합니다.

    나중에 동일한 설정으로 실험을 재현하기 위해 사용됩니다.

    Args:
      run_id: 실험 ID (예: "RAG-2026-0413-001")
      config: 저장할 설정 딕셔너리

    Returns:
      저장된 스냅샷 파일의 경로
    """
    # 스냅샷 파일 경로: results/run_id/snapshot.yaml
    snapshot_path = self.results_dir / run_id / "snapshot.yaml"

    # 설정에 메타정보를 추가합니다
    snapshot = {
      "run_id": run_id,
      "created_at": datetime.now().isoformat(),
      "config": config,
    }

    with open(snapshot_path, "w", encoding="utf-8") as f:
      yaml.dump(snapshot, f, allow_unicode=True, default_flow_style=False)

    logger.info(f"설정 스냅샷 저장 완료: {snapshot_path}")
    return snapshot_path

  def save_result(self, run_id: str, result: dict[str, Any], filename: str = "result.json") -> Path:
    """
    실험 결과를 JSON 파일로 저장합니다.

    Args:
      run_id: 실험 ID
      result: 저장할 결과 딕셔너리 (질의, 응답, 판정 결과 등)
      filename: 결과 파일명 (기본값: "result.json")

    Returns:
      저장된 결과 파일의 경로
    """
    result_path = self.results_dir / run_id / filename

    with open(result_path, "w", encoding="utf-8") as f:
      json.dump(result, f, ensure_ascii=False, indent=2)

    logger.info(f"실험 결과 저장 완료: {result_path}")
    return result_path

  def load_snapshot(self, run_id: str) -> dict[str, Any]:
    """
    저장된 설정 스냅샷을 불러옵니다.

    이전 실험과 동일한 조건으로 재실행할 때 사용합니다.

    Args:
      run_id: 불러올 실험의 ID

    Returns:
      스냅샷에 저장된 설정 딕셔너리

    Raises:
      FileNotFoundError: 스냅샷 파일이 없을 때
    """
    snapshot_path = self.results_dir / run_id / "snapshot.yaml"

    if not snapshot_path.exists():
      raise FileNotFoundError(
        f"스냅샷 파일을 찾을 수 없습니다: {snapshot_path}. "
        f"run_id '{run_id}'가 올바른지 확인해주세요."
      )

    with open(snapshot_path, "r", encoding="utf-8") as f:
      snapshot = yaml.safe_load(f)

    logger.info(f"설정 스냅샷 로드 완료: {snapshot_path}")
    return snapshot
