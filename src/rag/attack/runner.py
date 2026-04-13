"""
공격 실행기(AttackRunner) 모듈

설정 파일 기반으로 공격 시나리오를 자동 반복 실행합니다.
시나리오(R2/R4/R9) × 공격자 유형(A1~A4) × 환경(clean/poisoned)
조합에 따라 실험을 수행하고 결과를 수집합니다.

논문 기반:
  - 공격자 분류 (Figure 2):
    A_I (Unaware Observer) = A1: 블랙박스, 사전지식 없음
    A_II (Aware Observer) = A2: 블랙박스, 사전지식 보유
    A_III (Aware Insider) = A3: 화이트박스, 사전지식 보유
    A_IV (Unaware Insider) = A4: 화이트박스, 사전지식 없음

사용 예시:
  from rag.attack.runner import AttackRunner

  runner = AttackRunner(config)
  results = runner.run(
    scenario="R2",
    rag_pipeline=pipeline,
    target_docs=docs,
    attacker="A1",
    env="poisoned",
  )
"""

from typing import Any

from haystack import Pipeline
from loguru import logger

from rag.attack.base import AttackResult, BaseAttack
from rag.attack.r2_extraction import R2ExtractionAttack
from rag.attack.r4_membership import R4MembershipAttack
from rag.attack.r9_injection import R9InjectionAttack

# 시나리오 코드 → 공격 클래스 매핑
SCENARIO_MAP: dict[str, type[BaseAttack]] = {
  "R2": R2ExtractionAttack,
  "R4": R4MembershipAttack,
  "R9": R9InjectionAttack,
}


class AttackRunner:
  """
  공격 시나리오를 자동 실행하는 클래스입니다.

  설정에 따라 적절한 공격 클래스를 선택하고,
  쿼리 생성 → 실행 → 결과 수집을 자동으로 수행합니다.
  """

  def __init__(self, config: dict[str, Any]) -> None:
    """
    AttackRunner를 초기화합니다.

    Args:
      config: YAML에서 로드한 설정 딕셔너리
    """
    self.config = config
    logger.debug("AttackRunner 초기화 완료")

  def run(
    self,
    scenario: str,
    rag_pipeline: Pipeline,
    target_docs: list[dict[str, Any]],
    attacker: str = "A1",
    env: str = "poisoned",
  ) -> list[AttackResult]:
    """
    지정된 시나리오의 공격을 실행합니다.

    Args:
      scenario: 공격 시나리오 ("R2", "R4", "R9")
      rag_pipeline: 공격 대상 RAG 파이프라인
      target_docs: 공격 대상 문서 목록
        [{"content": "...", "keyword": "...", "doc_id": "..."}, ...]
      attacker: 공격자 유형 ("A1", "A2", "A3", "A4")
      env: 실행 환경 ("clean", "poisoned")

    Returns:
      list[AttackResult]: 모든 공격 시행의 결과 목록

    Raises:
      ValueError: 지원하지 않는 시나리오를 지정했을 때
    """
    # 시나리오 코드로 공격 클래스 선택
    attack_cls = SCENARIO_MAP.get(scenario.upper())
    if attack_cls is None:
      raise ValueError(
        f"지원하지 않는 시나리오입니다: {scenario}. "
        f"사용 가능: {list(SCENARIO_MAP.keys())}"
      )

    # 공격 인스턴스 생성
    attack = attack_cls(self.config)

    logger.info(
      f"공격 실행 시작: 시나리오={scenario}, "
      f"공격자={attacker}, 환경={env}, "
      f"대상 문서={len(target_docs)}개"
    )

    # 공격 쿼리 생성
    queries = attack.generate_queries(target_docs)
    logger.info(f"공격 쿼리 {len(queries)}개 생성 완료")

    # 각 쿼리를 순차 실행하고 결과를 수집합니다
    results: list[AttackResult] = []
    for i, query_info in enumerate(queries):
      logger.debug(f"공격 시행 {i + 1}/{len(queries)}")

      result = attack.execute(query_info, rag_pipeline)

      # 공통 메타데이터 추가
      result.metadata["attacker"] = attacker
      result.metadata["env"] = env
      result.metadata["trial_index"] = i

      results.append(result)

    logger.info(
      f"공격 실행 완료: {len(results)}개 시행, "
      f"성공 {sum(1 for r in results if r.success)}개"
    )
    return results

  def run_all_scenarios(
    self,
    rag_pipeline: Pipeline,
    target_docs: list[dict[str, Any]],
    scenarios: list[str] | None = None,
    attacker: str = "A1",
    env: str = "poisoned",
  ) -> dict[str, list[AttackResult]]:
    """
    여러 시나리오를 한 번에 실행합니다.

    Args:
      rag_pipeline: 공격 대상 RAG 파이프라인
      target_docs: 공격 대상 문서 목록
      scenarios: 실행할 시나리오 목록 (None이면 전체)
      attacker: 공격자 유형
      env: 실행 환경

    Returns:
      dict[str, list[AttackResult]]: 시나리오별 결과
        {"R2": [...], "R4": [...], "R9": [...]}
    """
    if scenarios is None:
      scenarios = list(SCENARIO_MAP.keys())

    all_results: dict[str, list[AttackResult]] = {}

    for scenario in scenarios:
      results = self.run(
        scenario=scenario,
        rag_pipeline=rag_pipeline,
        target_docs=target_docs,
        attacker=attacker,
        env=env,
      )
      all_results[scenario] = results

    return all_results
