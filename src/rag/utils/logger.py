"""
로깅 설정 모듈

loguru 라이브러리를 사용하여 프로젝트 전체의 로그를 관리합니다.
콘솔에 색상이 적용된 로그를 출력하고, 필요시 파일에도 저장합니다.

사용 예시:
  from rag.utils.logger import setup_logger, get_logger

  setup_logger()                          # 로거 초기 설정 (프로그램 시작 시 1회)
  logger = get_logger()                   # 로거 인스턴스 가져오기
  logger.info("실험 시작")                # 정보 로그
  logger.warning("API 키 미설정")         # 경고 로그
  logger.error("파일을 찾을 수 없습니다")  # 에러 로그
"""

import os
import sys
from contextlib import contextmanager

from loguru import logger


def setup_logger(log_level: str | None = None) -> None:
  """
  loguru 로거를 프로젝트에 맞게 설정합니다.

  이 함수는 프로그램 시작 시 한 번만 호출하면 됩니다.
  기존 로거 설정을 제거하고 새로운 설정을 적용합니다.

  Args:
    log_level: 로그 레벨 문자열 ("DEBUG", "INFO", "WARNING", "ERROR").
               None이면 환경변수 LOG_LEVEL 또는 기본값 "INFO" 사용.
  """
  # 로그 레벨 결정 (우선순위: 인자 > 환경변수 > 기본값)
  if log_level is None:
    log_level = os.getenv("LOG_LEVEL", "INFO")

  # 기존 로거 설정을 모두 제거합니다 (중복 출력 방지)
  logger.remove()

  # 콘솔 출력 설정: 색상 + 시간 + 레벨 + 메시지 형식
  logger.add(
    sys.stderr,
    level=log_level,
    format=(
      "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
      "<level>{level: <8}</level> | "
      "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> - "
      "<level>{message}</level>"
    ),
    colorize=True,
  )

  logger.info(f"로거 설정 완료 (레벨: {log_level})")


def get_logger():
  """
  loguru 로거 인스턴스를 반환합니다.

  각 모듈에서 이 함수를 호출하여 로거를 사용합니다.
  loguru는 전역 싱글턴이므로 항상 동일한 로거가 반환됩니다.

  Returns:
    loguru.logger 인스턴스
  """
  return logger


@contextmanager
def quiet_execution():
  """
  공격 쿼리 실행 루프 중 rag 패키지의 모든 로그를 임시 비활성화하는 컨텍스트 관리자.

  Rich progress bar와 loguru 로그가 동시에 stderr로 출력될 때
  화면이 깨지는 문제를 방지합니다. 실행 블록이 끝나면 자동으로 복원됩니다.

  사용 예시:
    with quiet_execution(), progress:
        for query in queries:
            ...
  """
  logger.disable("rag")
  try:
    yield
  finally:
    logger.enable("rag")
