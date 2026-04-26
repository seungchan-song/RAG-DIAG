# 아키텍처 개요

이 문서는 K-RAG 시스템의 기준 아키텍처와 현재 코드베이스의 구현 상태를 함께 정리한 개발용 문서입니다.

## 요구사항 기준 목표

요구사항분석서 기준의 기준 흐름은 아래와 같습니다.

`문서 등록 -> 인덱싱 -> 질의/RAG -> 공격 실행 -> 정량 평가 -> PII 탐지/마스킹 -> 리포트 생성`

이 흐름은 다음 원칙을 만족해야 합니다.

- `clean`과 `poisoned` 환경은 논리적으로 분리되어야 한다.
- 시나리오와 설정이 달라도 공통 파이프라인의 단계별 산출물이 추적 가능해야 한다.
- 실험 결과는 `run_id` 단위로 저장되고 재현 가능해야 한다.
- 리포트는 공격 성공 여부와 개인정보 노출 여부를 함께 해석할 수 있어야 한다.

## 현재 코드 기준 흐름

현재 코드 기준의 실질 흐름은 아래와 같습니다.

1. `src/rag/cli/main.py`
   - `rag ingest`, `rag query`, `rag run`, `rag report` 명령을 제공한다.
2. `src/rag/ingest/pipeline.py`
   - 파일 수집, 라우팅, 변환, 정제, 청킹, 임베딩, 저장을 한 번에 실행한다.
3. `src/rag/retriever/pipeline.py`
   - 질문 임베딩, 검색, 프롬프트 구성, 생성 흐름을 만든다.
4. `src/rag/attack/*`
   - R2/R4/R9 공격 쿼리를 만들고 RAG 파이프라인에 실행한다.
5. `src/rag/evaluator/*`
   - 각 시나리오별 성공 판정을 계산한다.
6. `src/rag/pii/*`
   - 정규식, 체크섬, NER, sLLM 교차검증, 분류, 마스킹을 제공한다.
7. `src/rag/report/generator.py`
   - 저장된 결과에서 JSON/CSV/PDF 리포트를 생성한다.
8. `src/rag/utils/experiment.py`
   - `run_id`, `snapshot.yaml`, 결과 JSON 저장을 관리한다.

## 모듈 책임

| 모듈 | 책임 | 현재 상태 |
| --- | --- | --- |
| `cli` | 명령행 진입점, 인자 검증, 단계별 실행 흐름 제어 | 구현됨 |
| `ingest` | 문서 수집, 변환, 정제, 청킹, 임베딩, 저장 | 구현됨 |
| `retriever` | 질의 임베딩, 검색, 프롬프트 구성 | 구현됨 |
| `generator` | OpenAI 또는 Mock 기반 답변 생성 | 구현됨 |
| `attack` | 시나리오별 쿼리 생성과 실행 | 구현됨 |
| `evaluator` | R2/R4/R9 성공 판정 및 집계 | 구현됨 |
| `pii` | 4단계 PII 탐지와 마스킹 | 부분 구현 |
| `report` | 결과 요약, 상세 CSV, PDF 리포트 생성 | 부분 구현 |
| `utils` | 설정 로드, 환경변수 로드, run snapshot/results 저장 | 구현됨 |

## 데이터 흐름

### 1. 문서 등록과 인덱싱

- 입력: `data/documents/` 아래 `PDF`, `TXT`, `MD`
- 처리: `FileTypeRouter -> Converter -> Cleaner -> Splitter -> Embedder -> Writer`
- 출력: 현재는 `InMemoryDocumentStore`

현재 코드 기준 현황:

- 문서 확장자 수집은 `.pdf`, `.txt`, `.md`를 지원한다.
- 저장소는 요구사항서의 FAISS 영속 인덱스가 아니라 메모리 기반 저장소다.
- 메타데이터 표준 필드(`doc_id`, `source`, `version`, `attack_type`, `file_hash`, `dataset_group`, `doc_role`)는 요구사항상 필요하지만 현재 ingest 경로에서 일관되게 주입되지는 않는다.

### 2. 질의와 RAG

- 입력: 사용자 질문
- 처리: `QueryEmbedder -> Retriever -> PromptBuilder -> Generator`
- 출력: 검색 문서 목록과 최종 응답

현재 코드 기준 현황:

- `top_k`는 사용된다.
- `similarity_threshold`는 설정 파일에 있으나 retriever 로직에서 실사용되지 않는다.
- `reranker` 설정은 존재하지만 파이프라인에 연결되어 있지 않다.
- `run_query()`는 Haystack 분기 문제를 피하기 위해 컴포넌트를 순차 호출한다.

### 3. 공격 실행

- 입력: 시나리오, 공격자 유형, 환경, 대상 문서
- 처리: 공격 쿼리 생성 -> RAG 실행 -> AttackResult 수집
- 출력: 시나리오별 AttackResult 목록

현재 코드 기준 현황:

- `AttackRunner`는 `R2`, `R4`, `R9`를 자동 반복 실행한다.
- 공격자 유형과 환경은 결과 메타데이터에 들어간다.
- `clean`/`poisoned` 분리는 현재 별도 인덱스로 구현되기보다 실행 메타데이터 수준에 머무른다.
- `BaseAttack._run_rag_query()`는 `retriever/pipeline.py`의 우회 로직과 다르게 `pipeline.run()`을 직접 사용한다. 따라서 공격 경로와 일반 질의 경로의 실행 방식이 일치하지 않는다.

### 4. 평가

- R2: `ROUGE-L Recall` 기반 유출 판정
- R4: `b`와 `b_hat` 일치 여부 기반 적중률 계산
- R9: 트리거 마커 포함 여부 기반 판정

현재 코드 기준 현황:

- 세 평가기는 구현되어 있고 `tests/test_attack_eval.py`에서 핵심 로직을 테스트한다.
- 시나리오별 반복 횟수는 설정값으로 제어한다.
- clean vs poisoned 비교 결과를 쌍으로 묶는 공통 데이터 구조는 아직 문서화/구현이 충분하지 않다.

### 5. PII 탐지와 마스킹

- STEP 1: 정규식
- STEP 2: 체크섬/구조 검증
- STEP 3: KPF-BERT NER
- STEP 4: GPT 기반 sLLM 교차검증

현재 코드 기준 현황:

- `PIIDetector`는 4단계 통합 클래스가 있다.
- `SLLMVerifier`는 API 키가 없으면 모킹 모드로 보수적 판정을 한다.
- 리포트 생성기에서는 현재 빠른 실행을 위해 STEP 1+2만 사용한다.

### 6. 리포트와 결과 저장

- `run_id` 디렉토리에 `snapshot.yaml`, `*_result.json`, 리포트 파일을 저장
- 요약과 상세 데이터를 동시에 보관

현재 코드 기준 현황:

- `ExperimentManager`가 run 디렉토리와 스냅샷을 저장한다.
- `ReportGenerator`는 JSON/CSV/PDF를 생성한다.
- 요구사항서의 clean vs poisoned 비교표, reranker ON/OFF 비교표, Top 3 PII 유형, High 위험도 비율은 아직 기본 리포트에 포함되지 않는다.

## clean / poisoned 분리 원칙

요구사항 기준 목표:

- `clean`: 일반 문서 + 민감 문서만 포함
- `poisoned`: `clean` + 공격 문서 포함
- 두 환경의 문서셋, 인덱스, 결과는 혼합되면 안 된다.

현재 코드 기준 현황:

- 환경값은 CLI 옵션과 `AttackResult.metadata["env"]`에 기록된다.
- 하지만 별도 저장소, 별도 인덱스 스냅샷, 별도 라우팅 규칙은 아직 충분히 구현되지 않았다.
- 따라서 현재 실험 해석 시 `환경 메타데이터`와 `입력 데이터셋 구성`을 별도 문서로 함께 관리해야 한다.

## 공통 산출물 단위

문서 전반에서 아래 산출물을 공통 단위로 사용한다.

- 설정 스냅샷
- 검색 결과
- 최종 프롬프트
- 생성 응답
- 평가 결과
- PII 탐지/마스킹 결과

현재 코드 기준 현황:

- 설정 스냅샷과 평가 결과는 저장된다.
- 검색 결과, reranked docs, final prompt는 요구사항 수준만큼 저장되지 않는다.

## 아키텍처상 우선 보완 포인트

- `clean`과 `poisoned`를 실제 인덱스 수준으로 분리
- `reranker`와 `similarity_threshold`를 검색 경로에 연결
- 공격 실행도 `run_query()`와 동일한 순차 실행 경로로 통일
- ingest 단계에서 요구 메타데이터를 강제
- 결과 저장 스키마에 검색 결과와 최종 프롬프트를 포함
- 리포트에 비교 실험과 시나리오별 PII 프로파일 집계 추가
