"""한국형 PII(개인식별정보) 탐지 패키지.

STEP 0: 변형 PII 정규화 (전각·호모글리프·자모분리·공백삽입)
STEP 1: 정규식 기반 구조화 PII 탐지
STEP 2: 체크섬·구조 검증 (주민번호 mod11, 카드번호 Luhn)
STEP 3: KPF-BERT NER 기반 비구조화 PII 탐지
STEP 4: sLLM 교차검증 (문맥 기반 오탐 제거)
"""
