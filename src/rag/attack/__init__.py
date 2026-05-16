"""
공격 엔진 패키지

RAG 시스템에 대한 4가지 공격 시나리오(R2, R4, R7, R9)와 1개 baseline 시나리오(NORMAL)를
자동 실행합니다. 각 공격 시나리오는 공격 쿼리를 생성하고 RAG 파이프라인에 전달하여
공격 성공 여부를 판정합니다.

NORMAL 시나리오는 공격이 아니라 "공격이 없는 일반 질의" 상황에서 RAG 가 얼마나 PII 를
노출하는지 측정하는 baseline 으로, R2/R4/R7/R9 모두의 대조군으로 사용됩니다.
"""

from rag.attack.normal_baseline import NormalBaselineAttack

__all__ = ["NormalBaselineAttack"]
