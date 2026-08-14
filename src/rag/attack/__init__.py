"""공격 엔진 패키지.

공격 시나리오 4종(R2/R4/R7/R9)과 baseline 1종(NORMAL)을 실행한다. 각 시나리오는 공격
쿼리를 만들어 RAG 파이프라인에 보내고 성공 여부를 판정한다.

NORMAL 은 공격이 아니라 "공격 없는 일반 질의"에서 RAG 가 노출하는 PII 량을 재는
대조군이며, 나머지 네 시나리오가 이 값과의 차이로 해석된다.
"""

from rag.attack.normal_baseline import NormalBaselineAttack

__all__ = ["NormalBaselineAttack"]
