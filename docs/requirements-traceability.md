# 요구사항 추적표

이 문서는 요구사항분석서의 기능 요구사항(FR), 비기능 요구사항(NFR), 제약/정책 요구사항(CR)을 현재 코드 구조와 연결한 추적표입니다.

상태 표기:

- `구현`: 현재 코드로 요구사항을 대부분 충족
- `부분`: 초기 구현 또는 일부만 충족
- `미구현`: 현재 코드에 직접 구현 근거가 부족

## 기능 요구사항

### 문서/데이터셋 관리

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-DM-001 | PDF/TXT/MD 업로드·등록 | `ingest/pipeline.py`, `ingest/router.py`, `ingest/converter.py` | `구현` | 실제 MD MIME 라우팅 확인 | `rag ingest --path ...` 수동 실행 |
| FR-DM-002 | `normal/sensitive/attack`, `clean/poisoned` 분류 | `attack/query_generator.py`, 문서 운영 규칙 | `부분` | ingest 단계 메타데이터 강제 필요 | 입력 문서셋과 결과 메타 점검 |
| FR-DM-003 | 메타데이터 저장·조회·수정 | `AttackResult.metadata`, 일부 R9 문서 meta | `부분` | `doc_id/source/version/file_hash` 일관 저장 필요 | 결과 JSON 및 ingest 후 문서 meta 확인 |
| FR-DM-004 | 중복 판별 및 중복 정책 적용 | `ingest/writer.py` | `부분` | `file_hash`, stable chunk ID 기반 중복 판별 추가 | 동일 문서 재등록 테스트 |

### 인덱싱/지식베이스 관리

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-KB-001 | 전처리·청킹·임베딩·저장 파이프라인 실행 | `ingest/pipeline.py` | `구현` | 저장소 영속화 검토 | `rag ingest` 실행 후 청크 수 확인 |
| FR-KB-002 | clean/poisoned 인덱스 분리 | 문서 운영 규칙, CLI `env` | `미구현` | 별도 인덱스/컬렉션 분리 구현 | clean/poisoned 결과 혼합 여부 확인 |
| FR-KB-003 | 전체 재색인/부분 갱신 | `run_ingest()` 전체 재실행 | `부분` | 부분 갱신 API 추가 | 문서 추가/수정 후 갱신 시나리오 테스트 |
| FR-KB-004 | 라우팅 규칙으로 인덱스 선택 | CLI `env`, 실행 메타 | `미구현` | 인덱스 선택 라우터 구현 | 환경별 다른 저장소 연결 테스트 |

### RAG 실행/질의 처리

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-RG-001 | QueryEmbedder/Retriever/Re-ranker/PromptBuilder/Generator 실행 | `retriever/pipeline.py`, `generator/generator.py` | `부분` | reranker 실제 연결 필요 | `rag query` 실행과 파이프라인 구성 확인 |
| FR-RG-002 | retriever/reranker/top_k/threshold/prompt profile 설정 제어 | `config/default.yaml`, `utils/config.py` | `부분` | threshold, profile, reranker 반영 강화 | 설정값 변경 후 동작 차이 확인 |
| FR-RG-003 | retrieved docs/score/reranked docs/final prompt/final reply 저장 | `AttackResult`, 결과 JSON, query 결과 | `부분` | 검색 결과와 프롬프트 저장 추가 | 결과 JSON 스키마 검토 |

### 실험 실행/재현 관리

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-EX-001 | 시나리오·공격자·환경·질의셋·프로파일 조합 배치 실행 | `cli/main.py`, `attack/runner.py` | `부분` | 질의셋/프로파일 실제 분기 강화 | 다양한 CLI 조합 실행 |
| FR-EX-002 | 동일 질의셋을 clean/poisoned 반복 적용 | CLI `env`, 공격 쿼리 생성기 | `부분` | 동일 `query_id` 비교 구조 추가 | 두 환경 동일 질의 수동 비교 |
| FR-EX-003 | run ID와 설정 스냅샷 저장 | `utils/experiment.py` | `구현` | 결과 연결 필드 보강 | `snapshot.yaml` 생성 확인 |
| FR-EX-004 | 저장된 설정으로 재실행 | `load_snapshot()` | `부분` | CLI 재실행 명령 추가 | snapshot 로드 후 수동 재실행 |

### 공격 시뮬레이션

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-AT-001 | R2 공격 구현 | `attack/r2_extraction.py` | `구현` | 표적 문서 메타 보강 | `tests/test_attack_eval.py`, CLI 실행 |
| FR-AT-002 | R4 공격 구현 | `attack/r4_membership.py` | `구현` | clean/poisoned 분리 기반 고도화 | 평가 요약 확인 |
| FR-AT-003 | R9 공격 구현 | `attack/r9_injection.py` | `구현` | poisoned 인덱스 주입 흐름 고도화 | 마커 기반 성공 테스트 |
| FR-AT-004 | 시나리오별 poisoned 환경 구성 | 문서 운영 규칙, R9 poison docs | `부분` | 시나리오별 데이터셋 조립 자동화 | 입력 데이터셋 구조 검토 |
| FR-AT-005 | R2/R4/R9 자동 실행 | `attack/runner.py`, `cli/main.py` | `구현` | 체크포인트/실패 복구 보강 | 배치 실행 후 결과 수 확인 |

### 정량적 평가

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-EV-001 | R2 평가 | `evaluator/r2_evaluator.py` | `구현` | 기준 문서-응답 trace 저장 보강 | ROUGE-L 평가 테스트 |
| FR-EV-002 | R4 평가 | `evaluator/r4_evaluator.py` | `구현` | 챌린저/데이터셋 분리 구조 고도화 | hit_rate 계산 테스트 |
| FR-EV-003 | R9 평가 | `evaluator/r9_evaluator.py` | `구현` | 악성 문서 retrieval 여부 trace 저장 | 마커 포함 여부 테스트 |

### 한국형 PII 탐지

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-PII-001 | 정규식 기반 탐지 | `pii/step1_regex.py` | `구현` | 태그 범위 문서화 보강 | `tests/test_pii.py` |
| FR-PII-002 | 체크섬/구조 검증 | `pii/step2_checksum.py` | `구현` | 대상 태그 확대 검토 | 체크섬 테스트 |
| FR-PII-003 | KPF-BERT 비구조화 PII 인식 | `pii/step3_ner.py` | `부분` | 모델 준비/평가 스크립트 보강 | warm_up 후 샘플 탐지 |
| FR-PII-004 | sLLM 문맥 검증 | `pii/step4_sllm.py` | `부분` | 실제 운영 기준 프롬프트/로그 다듬기 | mock/실API 검증 |
| FR-PII-005 | 경로별 확정 조건 적용 | `pii/detector.py`, `pii/classifier.py` | `구현` | 결과 저장 스키마 연결 | detect 결과 route 확인 |
| FR-PII-006 | KDPII 33종 Precision/Recall/F1 산출 | PII 평가 운영 문서 | `미구현` | 전용 평가 스크립트/리포트 추가 | KDPII 테스트셋 기반 평가 |

### 자동 리포트

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| FR-RP-001 | 공격 성공 여부 자동 정리 출력 | `report/generator.py` | `구현` | 시나리오별 상세 설명 강화 | `rag report` 실행 |
| FR-RP-002 | 성공률/민감정보 포함 여부 시각화 | `report/generator.py` PDF 요약 | `부분` | 비교 표/차트 수준 고도화 | 생성 PDF 확인 |
| FR-RP-003 | run ID와 설정 정보 기록 | `utils/experiment.py`, `report/generator.py` | `구현` | 인덱스 버전 등 추가 | snapshot와 summary 확인 |
| FR-RP-004 | 태그 유형별 마스킹 | `pii/masker.py` | `부분` | 리포트 경로 기본 적용 강화 | 마스킹 결과 확인 |
| FR-RP-005 | 시나리오별 주요 유출 PII Top 3, High 비율 | `report/generator.py` PII 요약 | `부분` | Top 3/위험도 계산 추가 | 요약 JSON 필드 확인 |
| FR-RP-006 | clean vs poisoned 비교 테이블 | 결과 운영 문서 | `미구현` | 동일 `query_id` 비교 구조 구현 | 두 run 비교 리포트 생성 |
| FR-RP-007 | reranker ON/OFF 교차 비교 | 설정 문서만 존재 | `미구현` | reranker 연결 후 비교 집계 구현 | ON/OFF 실험 비교 |
| FR-RP-008 | CSV/JSON/PDF 저장/내보내기 | `report/generator.py` | `구현` | PDF 폰트/배포 안정성 보강 | 파일 생성 확인 |
| FR-RP-009 | 질의/검색 결과/최종 응답/판정 결과 저장 | `AttackResult`, 결과 JSON | `부분` | 검색 결과·프롬프트 저장 추가 | 결과 JSON 내용 검토 |

## 비기능 요구사항

### 인터페이스

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| NFR-IF-001 | CLI에서 시나리오/공격자/환경/프로파일 선택 | `cli/main.py` | `구현` | profile 실제 동작 연결 | CLI 옵션 확인 |
| NFR-IF-002 | 문서 등록/수정 메타데이터 입력 | ingest 운영 규칙 | `미구현` | 메타데이터 입력 인터페이스 추가 | 문서 등록 흐름 점검 |

### 유지보수성

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| NFR-MA-001 | 시나리오/PII/리포트 모듈 분리 | `attack/*`, `pii/*`, `report/*` | `구현` | 신규 모듈 추가 가이드 보강 | 디렉토리 구조 검토 |
| NFR-MA-002 | 주요 설정 외부화 | `config/default.yaml`, `utils/config.py` | `부분` | 모든 설정값 런타임 반영 보강 | 설정 변경 후 동작 확인 |

### 추적성

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| NFR-TR-001 | run ID와 질의/설정/결과 저장 | `utils/experiment.py`, 결과 JSON | `부분` | 검색 결과·프롬프트 필드 추가 | run 디렉토리 확인 |
| NFR-TR-002 | clean/poisoned 비교 시 동일 질의/버전 연결 | 운영 문서, env 메타 | `미구현` | `query_id`, dataset/index version 구조 추가 | 비교 실험 결과 점검 |
| NFR-TR-003 | 설정 변경 이력 추적 | `snapshot.yaml` | `부분` | 변경 이력 누적 관리 추가 | snapshot diff 확인 |

### 신뢰성/안정성

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| NFR-RL-001 | 외부 API 실패 시 3회 재시도 | `pii/step4_sllm.py` | `부분` | generator 경로에도 재시도 적용 | API 실패 모의 테스트 |
| NFR-RL-002 | 일부 실패에도 완료 결과 보존 | `utils/experiment.py`, 개별 저장 | `부분` | 시나리오 루프 단위 에러 격리 강화 | 일부 실패 유도 테스트 |
| NFR-RL-003 | 체크포인트 저장/재개 | 관련 CLI 없음 | `미구현` | checkpoint 파일과 resume 옵션 추가 | 장시간 배치 재개 테스트 |

### 데이터 무결성/일관성

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| NFR-DI-001 | 동일 입력/프로파일/버전 재현 | `experiment.random_seed`, `snapshot.yaml` | `부분` | 랜덤 시드/모델 버전 전면 기록 강화 | 동일 조건 재실행 비교 |
| NFR-DI-002 | clean/poisoned 혼합 금지 | env 메타, 운영 문서 | `미구현` | 물리/논리 분리 저장소 구현 | 데이터셋 혼합 여부 점검 |
| NFR-DI-003 | 문서/청크 버전·해시 일관 관리 | 일부 `doc_id` 메타 | `부분` | `file_hash`, chunk version 도입 | 중복/버전 비교 테스트 |

### 보안

| ID | 요구사항 | 관련 모듈 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| NFR-SP-001 | API 키/인증정보를 env 또는 비밀관리로 저장 | `utils/config.py`, `.env.example` | `구현` | `.env.example` 변수명 정합성 수정 | `.env` 로드 확인 |
| NFR-SP-002 | 실험 결과 로컬 저장 기본 | `report.output_dir`, `ExperimentManager` | `구현` | 외부 업로드 차단 정책 문서화 | 결과 경로 확인 |
| NFR-SP-003 | 로그에는 raw PII 대신 태그/점수/라벨만 기록 | PII 문서 원칙, 일부 마스킹 | `부분` | 결과 JSON 기본 비식별화 적용 | 로그/리포트 샘플 점검 |

## 제약 및 정책 요구사항

| ID | 요구사항 | 관련 모듈/문서 | 현재 구현 흔적 | 남은 작업 | 검증 방법 |
| --- | --- | --- | --- | --- | --- |
| CR-001 | KDPII 연구 목적 사용, 외부 배포 금지 | 문서 정책, 모델 경로 운영 | `부분` | 배포 금지 절차와 저장소 정책 명문화 | 문서와 배포 흐름 점검 |
| CR-002 | 법령 기반 PII 분류 체계 준수 | `pii/*`, 정책 문서 | `부분` | 태그-법령 매핑표 보강 | PII 문서/태그표 검토 |
| CR-003 | synthetic data만 사용, 실험 종료 후 자동 삭제 | 운영 문서 | `부분` | 자동 삭제 스크립트 구현 | 데이터셋 감사 및 정리 테스트 |
## 2026-04-25 Status Overrides

Use this section as the current source of truth for items that were implemented after
the original table was written.

| ID | Updated status | Notes |
| --- | --- | --- |
| FR-KB-002 | `구현` | clean/poisoned indexes are physically separated |
| FR-KB-004 | `구현` | CLI env/scenario selection resolves deterministic indexes |
| FR-RG-001 | `구현` | retrieval path is `retriever -> threshold -> reranker -> prompt -> generator` |
| FR-RG-002 | `구현` | profile, threshold, and reranker settings affect runtime behavior |
| FR-RG-003 | `구현` | retrieval traces and final prompt are stored in result artifacts |
| FR-EX-001 | `구현` | suite orchestration supports env/profile/scenario matrix execution |
| FR-EX-002 | `구현` | clean/poisoned comparisons pair by shared `query_id` |
| FR-PII-003 | `구현` | Step 3 loads `townboy/kpfbert-kdpii` or a local override path |
| FR-PII-004 | `구현` | Step 4 records runtime mode, retry state, and fallback reason |
| FR-PII-006 | `구현` | `rag pii-eval` emits KDPII-style Precision/Recall/F1 artifacts |
| FR-RP-006 | `구현` | reports generate clean vs poisoned comparison sections |
| FR-RP-007 | `구현` | reports generate reranker ON/OFF comparison sections |
| NFR-TR-002 | `구현` | dataset scope and index manifest refs are stored for comparison pairing |
| NFR-RL-003 | `구현` | single-run and suite resume both use checkpoint artifacts |
| NFR-DI-002 | `구현` | clean/base and poisoned/<scenario> indexes prevent mixed input reuse |
