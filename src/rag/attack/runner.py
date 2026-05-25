"""Attack execution orchestration."""

from __future__ import annotations

import time
from typing import Any

from haystack import Pipeline
from loguru import logger

from rag.attack.base import AttackResult, BaseAttack
from rag.attack.normal_baseline import NormalBaselineAttack
from rag.attack.r2_extraction import R2ExtractionAttack
from rag.attack.r4_membership import R4MembershipAttack
from rag.attack.r7_prompt_disclosure import R7PromptDisclosureAttack
from rag.attack.r9_injection import R9InjectionAttack

# NORMAL 은 공격이 아닌 baseline 시나리오이지만 동일 인터페이스(BaseAttack)를 따르므로
# 같은 매핑에 등록해 CLI/runner/저장 파이프라인을 그대로 재사용한다.
SCENARIO_MAP: dict[str, type[BaseAttack]] = {
  "NORMAL": NormalBaselineAttack,
  "R2": R2ExtractionAttack,
  "R4": R4MembershipAttack,
  "R7": R7PromptDisclosureAttack,
  "R9": R9InjectionAttack,
}


class AttackRunner:
  """Generate attack queries, execute them, and stamp shared metadata."""

  def __init__(self, config: dict[str, Any]) -> None:
    self.config = config
    logger.debug("AttackRunner initialized")

  def create_attack(
    self,
    scenario: str,
    attacker: str = "A2",
    env: str = "poisoned",
    probe_mode: str = "generic",
  ) -> BaseAttack:
    """Instantiate the concrete attack implementation for one scenario.

    attacker 는 시나리오별 query_generator 동작 분기에 사용됩니다
    (요구사항분석서 §2.4 [표 13] A1~A3 매트릭스 참조; A4 는 제거됨).
    env 는 R2에서 쿼리 타입을 결정합니다.
    probe_mode 는 R4 전용 옵션: "generic"(일반 키워드) / "sensitive"(PII 식별자).
    """
    attack_cls = SCENARIO_MAP.get(scenario.upper())
    if attack_cls is None:
      raise ValueError(
        f"Unsupported scenario: {scenario}. "
        f"Available scenarios: {list(SCENARIO_MAP.keys())}"
      )
    if scenario.upper() == "R4":
      return attack_cls(self.config, attacker=attacker, env=env, probe_mode=probe_mode)
    return attack_cls(self.config, attacker=attacker, env=env)

  def prepare_queries(
    self,
    scenario: str,
    target_docs: list[dict[str, Any]],
    attacker: str = "A2",
    env: str = "poisoned",
    probe_mode: str = "generic",
  ) -> tuple[BaseAttack, list[dict[str, Any]]]:
    """Instantiate the scenario attack and generate all queries."""
    attack = self.create_attack(scenario, attacker=attacker, env=env, probe_mode=probe_mode)
    queries = attack.generate_queries(target_docs)
    logger.debug(
      "Prepared {} attack queries for scenario {} (attacker={}, env={}, probe_mode={})",
      len(queries),
      scenario.upper(),
      attacker,
      env,
      probe_mode,
    )
    return attack, queries

  def execute_query(
    self,
    attack: BaseAttack,
    *,
    query_info: dict[str, Any],
    rag_pipeline: Pipeline,
    attacker: str,
    env: str,
    trial_index: int,
  ) -> AttackResult:
    """Execute one query and attach the shared metadata fields.

    개별 쿼리의 처리 시간을 perf_counter() 로 측정해 metadata.elapsed_seconds 에
    기록한다. 동시에 time.time() 기반 Unix 타임스탬프(started_at/finished_at) 도
    함께 저장해 두는데, 리포트 생성 시 시나리오별 wall-clock 시간(병렬 실행을
    반영한 실제 체감 경과 시간)을 max(finished_at) - min(started_at) 으로
    역산하기 위함이다. perf_counter 는 wall-clock 과 무관한 단조 시계라
    스레드 간 비교가 불가능하므로 time.time() 값을 별도로 기록한다.
    """
    started_at = time.time()
    start_time = time.perf_counter()
    result = attack.execute(query_info, rag_pipeline)
    elapsed_seconds = round(time.perf_counter() - start_time, 4)
    finished_at = time.time()

    result.query_id = result.query_id or query_info.get("query_id", "")
    result.environment_type = env
    result.profile_name = result.profile_name or self.config.get("profile_name", "default")
    if not result.retrieval_config:
      result.retrieval_config = self.config.get("retrieval_config", {})

    reranker_enabled = bool(
      result.retrieval_config.get("reranker", {}).get("enabled", False)
    )
    result.metadata["attacker"] = attacker
    result.metadata["env"] = env
    result.metadata["trial_index"] = trial_index
    result.metadata["query_id"] = result.query_id
    result.metadata["profile_name"] = result.profile_name
    result.metadata["reranker_enabled"] = reranker_enabled
    result.metadata["reranker_state"] = "on" if reranker_enabled else "off"
    result.metadata["elapsed_seconds"] = elapsed_seconds
    # wall-clock 측정용 Unix timestamp(초). 병렬 실행 시 시나리오 전체의
    # 실제 경과 시간을 산출하기 위해 사용된다.
    result.metadata["started_at"] = round(started_at, 4)
    result.metadata["finished_at"] = round(finished_at, 4)
    # query_info 에 probe_mode / identifier_category 가 있다면 결과 메타데이터에
    # 동기화해 둔다 (특히 R4 외 시나리오에서는 attack.execute 가 키를 모르므로
    # 여기서 한 번 더 안전망을 둔다). 이미 attack.execute 가 세팅했다면 덮어쓰지 않음.
    probe_mode = query_info.get("probe_mode")
    if probe_mode and "probe_mode" not in result.metadata:
      result.metadata["probe_mode"] = probe_mode
    identifier_category = query_info.get("identifier_category")
    if identifier_category and "identifier_category" not in result.metadata:
      result.metadata["identifier_category"] = identifier_category
    return result

  def run(
    self,
    scenario: str,
    rag_pipeline: Pipeline,
    target_docs: list[dict[str, Any]],
    attacker: str = "A1",
    env: str = "poisoned",
    probe_mode: str = "generic",
    completed_query_ids: set[str] | None = None,
    on_result: Any | None = None,
  ) -> list[AttackResult]:
    """Run one attack scenario across all generated queries."""
    attack, queries = self.prepare_queries(
      scenario, target_docs, attacker=attacker, env=env, probe_mode=probe_mode
    )
    skipped = completed_query_ids or set()

    logger.debug(
      "Starting attack run: scenario={}, attacker={}, env={}, target_docs={}",
      scenario,
      attacker,
      env,
      len(target_docs),
    )

    results: list[AttackResult] = []
    for index, query_info in enumerate(queries):
      query_id = str(query_info.get("query_id", ""))
      if query_id and query_id in skipped:
        logger.debug("Skipping completed query {}", query_id)
        continue

      result = self.execute_query(
        attack,
        query_info=query_info,
        rag_pipeline=rag_pipeline,
        attacker=attacker,
        env=env,
        trial_index=index,
      )
      results.append(result)
      if on_result is not None:
        on_result(result)

    logger.debug(
      "Attack run finished: executions={}, successes={}",
      len(results),
      sum(1 for item in results if item.success),
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
    """Run multiple scenarios and return the grouped results."""
    selected_scenarios = scenarios or list(SCENARIO_MAP.keys())
    return {
      scenario: self.run(
        scenario=scenario,
        rag_pipeline=rag_pipeline,
        target_docs=target_docs,
        attacker=attacker,
        env=env,
      )
      for scenario in selected_scenarios
    }
