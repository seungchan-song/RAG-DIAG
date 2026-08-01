"""
BYO-RAG 어댑터 패키지 (A-2).

진단 대상 RAG 를 추상화하는 표준 계약과 참조 구현을 제공한다. 이 계층 덕분에 공격
엔진은 "우리 RAG" 뿐 아니라 남이 운영하는 RAG 에도 어댑터만 갈아 끼워 붙을 수 있다.

공개 심볼:
  - Capability            : 어댑터가 노출하는 능력 열거형.
  - RagTrace              : 한 질의 결과의 표준 자료구조(엔진 dict 와 상호 변환).
  - TargetRAG             : 어댑터가 구현할 프로토콜(계약).
  - has_capability        : 능력 노출 여부 확인 헬퍼.
  - BuiltinHaystackAdapter: 우리 Haystack RAG 를 감싸는 첫 참조 어댑터.
  - plan_scenario_execution / CapabilityPlan: 시나리오별 run/degrade/skip 결정.
  - SCENARIO_REQUIRED_CAPABILITIES / SCENARIO_RECOMMENDED_CAPABILITIES: 매핑 표.
"""

from rag.adapters.base import (
  CAPABILITY_LABELS,
  Capability,
  RagTrace,
  TargetRAG,
  has_capability,
)
from rag.adapters.builtin import BuiltinHaystackAdapter
from rag.adapters.capabilities import (
  DECISION_DEGRADE,
  DECISION_RUN,
  DECISION_SKIP,
  SCENARIO_RECOMMENDED_CAPABILITIES,
  SCENARIO_REQUIRED_CAPABILITIES,
  CapabilityPlan,
  plan_scenario_execution,
  resolve_capabilities,
)
from rag.adapters.gated import CapabilityGatedAdapter, UnsupportedCapabilityError
from rag.adapters.registry import (
  AdapterConfigError,
  available_adapters,
  create_target_adapter,
  register_adapter,
  resolve_target_capabilities,
)
from rag.adapters.rest import RestRagAdapter
from rag.adapters.sota import SotaRagAdapter

__all__ = [
  "CAPABILITY_LABELS",
  "Capability",
  "RagTrace",
  "TargetRAG",
  "has_capability",
  "BuiltinHaystackAdapter",
  "CapabilityGatedAdapter",
  "UnsupportedCapabilityError",
  "RestRagAdapter",
  "SotaRagAdapter",
  "AdapterConfigError",
  "available_adapters",
  "create_target_adapter",
  "register_adapter",
  "resolve_target_capabilities",
  "CapabilityPlan",
  "DECISION_DEGRADE",
  "DECISION_RUN",
  "DECISION_SKIP",
  "SCENARIO_RECOMMENDED_CAPABILITIES",
  "SCENARIO_REQUIRED_CAPABILITIES",
  "plan_scenario_execution",
  "resolve_capabilities",
]
