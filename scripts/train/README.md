# 파인튜닝 모델 학습·추론 코드

이 저장소가 파인튜닝해 사용하는 모델의 **학습 코드와 추론 코드**를 모델별로 담습니다.
대회 규정 제9조②-2-다 및 [별표2] '산출물 라이선스 준수'가 직접 작성한 학습·추론 코드에
OSI 인증 오픈소스SW 라이선스 적용을 요구하므로, 모든 코드는 MIT License 로 공개합니다.

| 폴더 | 모델 | 기반 모델 | 용도 |
| --- | --- | --- | --- |
| `ner/` | `townboy/kpfbert-ner` | `KPF/KPF-bert-ner` | PII 4단계 STEP 3 개체명 인식 |
| `sllm/` | `bbanany/qwen25-3b-korean-pii-qlora3` | `Qwen/Qwen2.5-3B-Instruct` | PII 4단계 STEP 4 교차검증 |

각 폴더의 `README.md` 에 설치·실행 방법과 실제 학습 하이퍼파라미터가 있고, `LICENSE` 에
MIT 전문이, 각 `.py` 상단에 `SPDX-License-Identifier: MIT` 가 붙어 있습니다.

여기 담긴 코드는 모델을 만들 때 쓴 것이며, 진단 파이프라인이 런타임에 실행하는 코드가
아닙니다. 실행 경로는 `src/rag/` 에 있습니다. 모델 가중치와 라이선스 근거는 저장소 루트
`THIRD_PARTY_NOTICES.md` 를 참조하세요.
