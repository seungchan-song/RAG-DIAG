"""Attack execution orchestration."""

from __future__ import annotations

from typing import Any

from haystack import Pipeline
from loguru import logger

from rag.attack.base import AttackResult, BaseAttack
from rag.attack.r2_extraction import R2ExtractionAttack
from rag.attack.r4_membership import R4MembershipAttack
from rag.attack.r9_injection import R9InjectionAttack

SCENARIO_MAP: dict[str, type[BaseAttack]] = {
  "R2": R2ExtractionAttack,
  "R4": R4MembershipAttack,
  "R9": R9InjectionAttack,
}


class AttackRunner:
  """Generate attack queries, execute them, and stamp shared metadata."""

  def __init__(self, config: dict[str, Any]) -> None:
    self.config = config
    logger.debug("AttackRunner initialized")

  def create_attack(self, scenario: str) -> BaseAttack:
    """Instantiate the concrete attack implementation for one scenario."""
    attack_cls = SCENARIO_MAP.get(scenario.upper())
    if attack_cls is None:
      raise ValueError(
        f"Unsupported scenario: {scenario}. "
        f"Available scenarios: {list(SCENARIO_MAP.keys())}"
      )
    return attack_cls(self.config)

  def prepare_queries(
    self,
    scenario: str,
    target_docs: list[dict[str, Any]],
  ) -> tuple[BaseAttack, list[dict[str, Any]]]:
    """Instantiate the scenario attack and generate all queries."""
    attack = self.create_attack(scenario)
    queries = attack.generate_queries(target_docs)
    logger.info(
      "Prepared {} attack queries for scenario {}",
      len(queries),
      scenario.upper(),
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
    """Execute one query and attach the shared metadata fields."""
    result = attack.execute(query_info, rag_pipeline)
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
    return result

  def run(
    self,
    scenario: str,
    rag_pipeline: Pipeline,
    target_docs: list[dict[str, Any]],
    attacker: str = "A1",
    env: str = "poisoned",
    completed_query_ids: set[str] | None = None,
    on_result: Any | None = None,
  ) -> list[AttackResult]:
    """Run one attack scenario across all generated queries."""
    attack, queries = self.prepare_queries(scenario, target_docs)
    skipped = completed_query_ids or set()

    logger.info(
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

    logger.info(
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
