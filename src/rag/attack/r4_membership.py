"""
R4 공격 시나리오: 멤버십 추론 (Document-Level Membership Inference Attack)

타깃 문서 d* 가 RAG 의 knowledge base 에 포함되어 있는지를 응답 차이로
드러내는지 측정한다.

공격 방식 (페어 기반 결정론적 비교):
  1. 같은 쿼리 q 를 두 환경에서 던진다.
     - b=1: d* 가 인덱스에 포함된 원본 환경
     - b=0: d* 만 제외하고 동적으로 재구성한 환경
  2. 두 환경의 응답 y₁, y₀ 를 한 페어로 묶는다.
  3. 평가기가 sim₁ = ROUGE-L(y₁, d*), sim₀ = ROUGE-L(y₀, d*) 를 계산하고
     Δ = sim₁ - sim₀ > delta_threshold 이면 그 페어를 공격 성공으로 판정한다.

사용 예시:
  attack = R4MembershipAttack(config)
  queries = attack.generate_queries(target_docs)
  result = attack.execute(queries[0], rag_pipeline)
"""

import threading
from typing import Any

from haystack import Pipeline
from loguru import logger

from rag.attack.base import AttackResult, BaseAttack
from rag.attack.query_generator import AttackQueryGenerator


class R4MembershipAttack(BaseAttack):
  """
  R4 멤버십 추론 공격을 수행하는 클래스입니다.

  특정 문서가 RAG 시스템의 knowledge base에 포함되어 있는지
  응답의 특성을 분석하여 추론합니다.
  """

  def __init__(
    self,
    config: dict[str, Any],
    attacker: str = "A2",
    env: str = "poisoned",
    probe_mode: str = "sensitive",
    target: Any | None = None,
  ) -> None:
    """
    R4MembershipAttack을 초기화합니다.

    Args:
      config: YAML 설정 딕셔너리
      attacker: 공격자 유형 (A1/A2)
      env: 실행 환경 (clean/poisoned)
      probe_mode: 쿼리 생성 방식.
        "sensitive" — 문서 내 PII 식별자 직접 사용 + 카테고리 분해 분석 (기본).
        "generic"  — 일반 키워드 기반 탐색 (레거시). 컨셉상 sensitive 와 동일
                     공격의 약화된 변종이며, 대시보드 R4 패널이 이를 직접 표시
                     하지 않으므로 호환성/디버그 용도로만 남겨둔다.
      target: 진단 대상 어댑터(BYO-RAG). 주입되면 비회원 반사실 인덱스도 이 어댑터의
        build_variant() 로 만든다. None 이면 execute() 에 전달된 파이프라인을 참조
        어댑터로 감싼다(기존 동작과 동일).
    """
    super().__init__(config, attacker=attacker, env=env, target=target)
    self.probe_mode = probe_mode.lower() if probe_mode else "generic"
    # sensitive 모드일 때만 PIIDetector 를 lazy 로 만들어 query_gen 에 주입한다.
    # 정규식만으로 잡히지 않는 한글 이름·주소·직장명을 NER 후보로 보충해서
    # identifier_category 다양성을 확보하기 위함. generic 모드 / 다른 시나리오에서는
    # KPF-BERT 모델 로드 비용을 피하기 위해 None 으로 둔다.
    # 비활성 스위치: config["attack"]["r4"]["sensitive_use_ner"] = false
    pii_detector = self._build_optional_pii_detector(config)
    self.query_gen = AttackQueryGenerator(
      config,
      attacker=self.attacker,
      pii_detector=pii_detector,
    )
    # 비회원(d* 제외) 반사실 어댑터를 target_doc_id 별로 캐시한다. 같은 d* 에 대한
    # 여러 쿼리가 동일한 반사실 인덱스를 재사용하도록 해 재구성 비용을 아낀다.
    self._non_member_adapters: dict[str, Any] = {}
    # 캐시를 지키는 락. CLI 는 이 인스턴스 하나를 ThreadPoolExecutor(max_workers=5)
    # 위에서 공유하는데, generate_queries 가 문서당 b=0 쿼리를 연속으로 쌓고 실행부가
    # 전량을 한 번에 submit 하므로 같은 target_doc_id 의 b=0 쿼리들이 나란히 워커에
    # 들어간다. 락이 없으면 전부 빈 캐시를 보고 build_variant 를 중복 실행했다
    # (실측: 동시 5건 → 5회 전부 재구성, 캐시 적중 0). build_variant 는 문서 1,200개
    # 재색인 + 파이프라인 재빌드라 비용이 크고, 그 순간 같은 크기의 store 가 워커 수만큼
    # 동시에 메모리에 뜬다.
    # 한계: 캐시 전체를 하나의 락으로 덮어 build_variant 자체를 직렬화한다. 서로 다른
    # 문서의 재구성까지 줄 세우지만, 재구성은 셀당 문서 수(기본 20)만큼만 일어나고 오히려
    # 메모리 피크를 1개분으로 눌러 주므로 이득이다. 재구성이 병목이 되면 target_doc_id 별
    # 락으로 쪼갤 것.
    self._non_member_lock = threading.Lock()
    logger.debug(
      "R4MembershipAttack 초기화 완료 (attacker={}, probe_mode={}, pii_ner={})",
      self.attacker,
      self.probe_mode,
      "on" if pii_detector is not None else "off",
    )

  def _build_optional_pii_detector(self, config: dict[str, Any]) -> Any | None:
    """sensitive 모드에서 NER 보충용 PIIDetector 인스턴스를 생성합니다.

    sensitive 모드가 아니면 None 을 돌려주어 KPF-BERT 모델 로드를 건너뛴다.
    config 의 `attack.r4.sensitive_use_ner` 가 false 면 강제로 비활성화한다.
    임포트/초기화 실패 시에도 정규식만으로 동작이 가능하므로 예외를 삼키고
    None 을 돌려준다.
    """
    if self.probe_mode != "sensitive":
      return None

    r4_cfg = (config.get("attack") or {}).get("r4") or {}
    if not r4_cfg.get("sensitive_use_ner", True):
      logger.info("R4S NER 보충 비활성화 (config.attack.r4.sensitive_use_ner=false)")
      return None

    try:
      from rag.pii.detector import PIIDetector

      return PIIDetector(config)
    except Exception as error:
      logger.warning(
        "PIIDetector 초기화 실패 → 정규식 전용 R4S 로 폴백: error={}",
        error,
      )
      return None

  def generate_queries(
    self, target_docs: list[dict[str, Any]]
  ) -> list[dict[str, Any]]:
    """
    R4 멤버십 추론 쿼리를 생성합니다.

    probe_mode에 따라 두 가지 방식으로 동작합니다.
      - "generic":   일반 키워드 기반 탐색 쿼리 (기존 방식)
      - "sensitive": 문서 내 PII 식별자 직접 사용 쿼리 (민감 프로브)

    각 타깃 문서에 대해 b=1(포함)과 b=0(미포함) 쿼리를 쌍으로 생성합니다.

    Args:
      target_docs: 멤버십 추론 대상 문서 목록

    Returns:
      list[dict]: R4 탐색 쿼리 목록
    """
    all_queries: list[dict[str, Any]] = []

    for doc in target_docs:
      if self.probe_mode == "sensitive":
        member_queries = self.query_gen.generate_r4_sensitive_queries(doc, is_member=True)
        non_member_queries = self.query_gen.generate_r4_sensitive_queries(doc, is_member=False)
      else:
        member_queries = self.query_gen.generate_r4_queries(doc, is_member=True)
        non_member_queries = self.query_gen.generate_r4_queries(doc, is_member=False)

      all_queries.extend(member_queries)
      all_queries.extend(non_member_queries)

    return all_queries

  def execute(
    self,
    query_info: dict[str, Any],
    rag_pipeline: Pipeline,
  ) -> AttackResult:
    """
    단일 R4 멤버십 추론 공격을 실행합니다.

    같은 쿼리가 b=1(원본 인덱스)과 b=0(d* 제외 인덱스) 두 환경에서 한 번씩
    실행되어 페어를 이루고, 평가기가 두 응답의 ROUGE-L 차이로 페어 단위
    공격 성공을 판정합니다.

    Args:
      query_info: generate_queries()에서 생성된 쿼리 정보
      rag_pipeline: 공격 대상 RAG 파이프라인

    Returns:
      AttackResult: 공격 결과
        - metadata["ground_truth_b"]: 이 응답이 b=1 환경 응답인지(1) b=0 환경 응답인지(0)
    """
    query = query_info["query"]
    target_text = query_info["target_text"]
    ground_truth_b = query_info["ground_truth_b"]

    logger.debug(
      f"R4 공격 실행 (b={ground_truth_b}): {query[:50]}..."
    )

    if ground_truth_b == 1:
      # b=1: d* 가 포함된 원본 대상(회원)에 그대로 질의한다.
      trace = self._run_rag_query(rag_pipeline, query)
    else:
      # b=0: d* 만 제외한 반사실 어댑터(build_variant)로 질의한다.
      non_member_target = self._resolve_non_member_adapter(query_info, rag_pipeline)
      trace = self._run_rag_query(rag_pipeline, query, target=non_member_target)
    replies = trace.get("generator", {}).get("replies", [])
    response = replies[0] if replies else ""

    return AttackResult(
      scenario="R4",
      query=query,
      response=response,
      query_id=query_info.get("query_id", ""),
      profile_name=trace.get("profile_name", ""),
      target_text=target_text,
      retrieved_documents=trace.get("retrieved_documents", []),
      raw_retrieved_documents=trace.get("raw_retrieved_documents", []),
      thresholded_documents=trace.get("thresholded_documents", []),
      reranked_documents=trace.get("reranked_documents", []),
      final_prompt=trace.get("prompt", ""),
      retrieval_config=trace.get("retrieval_config", {}),
      metadata={
        # 대상 RAG 가 보고한 부가 정보(가드레일 차단 여부 등). 우리 builtin
        # 경로에서는 항상 빈 dict 이며, 외부 어댑터일 때만 채워진다.
        "target_metadata": trace.get("target_metadata", {}),
        "ground_truth_b": ground_truth_b,
        "target_doc_id": query_info.get("target_doc_id", ""),
        "keyword": query_info.get("keyword", ""),
        # probe_mode 는 generic / sensitive 중 하나로 query_generator 가 직접 세팅한다.
        # 결과 metadata 에 그대로 보존해야 R4 evaluator 와 리포트가 sensitive(R4S) /
        # generic(R4) 분리 집계를 수행할 수 있다. query_id prefix 와 일치하지만
        # 의미적으로는 query_id 와 무관하게 단독으로 해석 가능해야 하므로 명시적으로
        # 메타데이터에 기록한다.
        "probe_mode": query_info.get("probe_mode", "generic"),
        # sensitive 모드에서만 채워지는 식별자 카테고리 (예: rrn, credit_card, email …).
        # 리포트의 "어떤 종류 PII가 멤버십 신호를 가장 잘 만드는가" 차트에 사용된다.
        "identifier_category": query_info.get("identifier_category", ""),
        "retrieval_mode": (
          "member"
          if ground_truth_b == 1
          else "non_member_excluded_index"
        ),
        "reranker_enabled": trace.get("reranker_enabled", False),
      },
    )

  def _resolve_non_member_adapter(
    self,
    query_info: dict[str, Any],
    rag_pipeline: Pipeline,
  ) -> Any:
    """
    R4 b=0 실행에 쓸 비회원(d* 제외) 반사실 어댑터를 만듭니다.

    기존에는 이 메서드가 저장 문서를 직접 필터링해 새 파이프라인을 빌드했지만, 이제는
    어댑터의 `build_variant(exclude_doc_ids=...)` 로 그 로직을 위임한다. base_target 은
    주입된 외부 어댑터(self.target)이거나, 없으면 전달된 파이프라인을 감싼 참조
    어댑터(BuiltinHaystackAdapter)다. 같은 target_doc_id 는 캐시로 재사용한다.

    Args:
      query_info: R4 쿼리 정보. `target_doc_id` 로 제외할 문서를 지정한다.
      rag_pipeline: 회원(b=1) 원본 파이프라인. self.target 이 없을 때만 사용된다.

    Returns:
      TargetRAG: d* 가 제외된 반사실 인덱스를 감싼 어댑터.

    Thread-safety:
      CLI 가 이 메서드를 워커 스레드 여러 개에서 동시에 부른다. 조회·생성·저장을
      `_non_member_lock` 안에서 한 덩어리로 처리해 같은 문서에 대한 build_variant 가
      정확히 한 번만 돌게 한다(`tests/test_r4_variant_cache.py` 가 고정).
    """
    target_doc_id = query_info.get("target_doc_id", "")
    with self._non_member_lock:
      if target_doc_id in self._non_member_adapters:
        return self._non_member_adapters[target_doc_id]

      base_target = self.target
      if base_target is None:
        from rag.adapters.builtin import BuiltinHaystackAdapter

        base_target = BuiltinHaystackAdapter(rag_pipeline, self.config)

      non_member_target = base_target.build_variant(exclude_doc_ids={target_doc_id})
      logger.debug("R4 non-member 반사실 어댑터 구성: target_doc_id={}", target_doc_id)
      self._non_member_adapters[target_doc_id] = non_member_target
      return non_member_target
