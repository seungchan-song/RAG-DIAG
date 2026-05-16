"""
공격 평가 엔진 패키지

각 공격 시나리오(R2, R4, R7, R9)의 성공 여부를 정량적으로 판정합니다.
NORMAL 시나리오는 공격이 아니므로 success/score 를 고정하고 baseline 메타데이터만
기록하는 NormalEvaluator 가 담당합니다.
"""

from rag.evaluator.normal_evaluator import NormalEvaluator

__all__ = ["NormalEvaluator"]
