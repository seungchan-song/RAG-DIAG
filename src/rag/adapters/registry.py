"""
어댑터 레지스트리 — `config.adapter.type` 로 진단 대상 어댑터를 고르는 확장점.

지금까지는 대상이 우리 RAG(builtin) 뿐이었다. 레지스트리를 두면 이름으로 어댑터를
등록·선택할 수 있어, 남의 RAG(REST 기반 외부 RAG 등)를 config 한 줄(`adapter.type`)로
갈아 끼울 수 있다. 팀원이 새 어댑터를 붙이는 표준 진입점이다.

두 개의 공개 함수가 CLI 실행 루프와 맞물린다:
  - resolve_target_capabilities(config): 인덱스 로드 이전에 대상이 노출하는 능력을
    구해 시나리오 skip/degrade 계획을 세운다. (파이프라인 불필요)
  - create_target_adapter(config, pipeline): 실제 대상 어댑터 인스턴스를 만든다.
    builtin + 전 능력이면 None 을 돌려주어 기존 경로(각 시나리오가 파이프라인을 즉석
    래핑)를 그대로 타게 한다 → 완전 비파괴.

능력 모델(중요):
  레지스트리는 어댑터 타입별 native(최대) 능력을 정적으로 보관한다. 운영자는
  `config.adapter.capabilities` 로 그보다 좁게 선언할 수 있고(그 대상 RAG 가 실제로
  덜 노출하는 경우), 그러면 CapabilityGatedAdapter 로 감싸 좁힌 능력만 노출한다.
  선언이 없으면 native 를 그대로 쓴다.
"""

from __future__ import annotations

from typing import Any, Callable

from loguru import logger

from rag.adapters.base import Capability
from rag.adapters.builtin import BuiltinHaystackAdapter
from rag.adapters.gated import CapabilityGatedAdapter

# 어댑터 팩토리: (전체 config, 우리 파이프라인) -> TargetRAG 인스턴스.
# 외부 어댑터는 pipeline 을 무시하고 config["adapter"] 설정으로 스스로를 구성한다.
AdapterFactory = Callable[[dict[str, Any], Any], Any]

_FULL_CAPABILITIES = set(BuiltinHaystackAdapter.capabilities)


class AdapterConfigError(RuntimeError):
  """config.adapter 설정이 잘못되었을 때(미등록 type 등) 발생한다."""


class _RegistryEntry:
  """레지스트리 한 항목: 팩토리 + 그 어댑터 타입의 native(최대) 능력."""

  def __init__(self, factory: AdapterFactory, capabilities: set[Capability]) -> None:
    self.factory = factory
    self.capabilities = set(capabilities)


_REGISTRY: dict[str, _RegistryEntry] = {}


def register_adapter(
  name: str,
  factory: AdapterFactory,
  capabilities: set[Capability],
) -> None:
  """
  어댑터 타입을 이름으로 등록합니다.

  Args:
    name: `config.adapter.type` 에서 쓸 이름(대소문자 무관).
    factory: (config, pipeline) -> 어댑터 인스턴스.
    capabilities: 이 어댑터 타입이 노출할 수 있는 native(최대) 능력 집합.
  """
  _REGISTRY[name.strip().lower()] = _RegistryEntry(factory, capabilities)
  logger.debug("어댑터 등록: {} (native 능력 {})", name, sorted(c.value for c in capabilities))


def available_adapters() -> list[str]:
  """등록된 어댑터 타입 이름 목록(정렬)."""
  return sorted(_REGISTRY)


def _adapter_type(config: dict[str, Any]) -> str:
  """config.adapter.type 를 정규화해 반환(기본 'builtin')."""
  return str((config.get("adapter") or {}).get("type") or "builtin").strip().lower()


def _declared_capabilities(config: dict[str, Any]) -> set[Capability] | None:
  """
  config.adapter.capabilities 선언을 파싱합니다.

  선언이 없으면(빈 값) None 을 돌려준다(= native 사용). 알 수 없는 이름은 무시하고,
  QUERY 는 최소 필수라 항상 포함시킨다.
  """
  declared = (config.get("adapter") or {}).get("capabilities")
  if not declared:
    return None

  valid = {cap.value: cap for cap in Capability}
  resolved: set[Capability] = set()
  for name in declared:
    cap = valid.get(str(name).strip().lower())
    if cap is None:
      logger.warning("알 수 없는 adapter capability '{}' 무시(유효: {})", name, list(valid))
      continue
    resolved.add(cap)
  resolved.add(Capability.QUERY)
  return resolved


def _native_capabilities(atype: str) -> set[Capability]:
  """어댑터 타입의 native 능력(미등록/builtin 은 전 능력)."""
  entry = _REGISTRY.get(atype)
  if entry is None:
    return set(_FULL_CAPABILITIES)
  return set(entry.capabilities)


def resolve_target_capabilities(config: dict[str, Any]) -> set[Capability]:
  """
  대상 어댑터가 실제로 노출하는 능력 집합을 해석합니다(시나리오 계획용).

  선언(config.adapter.capabilities)이 있으면 그 집합을, 없으면 어댑터 타입의 native
  능력을 돌려준다. 인덱스·파이프라인이 필요 없어 실행 루프 초반(skip/degrade 판정)에
  호출할 수 있다.
  """
  atype = _adapter_type(config)
  native = _native_capabilities(atype)
  declared = _declared_capabilities(config)
  if declared is None:
    return native
  # 선언은 native 를 넘어설 수 없다(대상이 실제로 가진 능력 이상은 무의미) → 교집합.
  return declared & native if atype != "builtin" else declared


def create_target_adapter(config: dict[str, Any], pipeline: Any) -> Any | None:
  """
  config 에 맞는 진단 대상 어댑터 인스턴스를 만듭니다.

  Returns:
    - builtin + 전 능력: None (기존 경로 유지 → 완전 비파괴).
    - 그 외: 어댑터 인스턴스. 선언 능력이 native 보다 좁으면 CapabilityGatedAdapter 로 감싼다.

  Raises:
    AdapterConfigError: 등록되지 않은 adapter.type 인 경우.
  """
  atype = _adapter_type(config)
  entry = _REGISTRY.get(atype)
  if entry is None:
    raise AdapterConfigError(
      f"알 수 없는 adapter.type '{atype}'. 등록된 타입: {available_adapters()}"
    )

  effective = resolve_target_capabilities(config)
  native = entry.capabilities

  # builtin + 전 능력이면 래핑하지 않고 None → 각 시나리오가 파이프라인을 즉석 래핑.
  if atype == "builtin" and effective >= native:
    return None

  raw_adapter = entry.factory(config, pipeline)
  if effective < native:
    logger.info(
      "{} 어댑터를 제한 능력으로 게이팅(degrade 반영): {}",
      atype,
      sorted(cap.value for cap in effective),
    )
    return CapabilityGatedAdapter(raw_adapter, effective)
  return raw_adapter


def _builtin_factory(config: dict[str, Any], pipeline: Any) -> Any:
  """builtin 어댑터 팩토리 — 우리 Haystack 파이프라인을 감싼다."""
  return BuiltinHaystackAdapter(pipeline, config)


# 기본 제공 어댑터 등록. 외부 어댑터(rest 등)는 각 모듈이 import 시 자기 자신을 등록한다.
register_adapter("builtin", _builtin_factory, _FULL_CAPABILITIES)
