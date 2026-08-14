"""공격 평가 엔진 패키지.

시나리오별 성공 여부를 정량 지표로 판정한다(R2 ROUGE-L · R4 페어 Δ · R7 코사인 ·
R9 마커 탐지). NORMAL 은 공격이 아니라 success/score 를 고정하고 baseline 메타데이터만
남기는 NormalEvaluator 가 맡는다.
"""

from rag.evaluator.normal_evaluator import NormalEvaluator

__all__ = ["NormalEvaluator"]
