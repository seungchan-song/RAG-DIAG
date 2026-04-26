# K-RAG 보안 검증 하네스

이 저장소는 한국어 RAG 시스템을 대상으로 다음 세 가지 공격 시나리오를 평가합니다.

- `R2`: 검색 기반 민감 정보 추출 공격
- `R4`: 멤버십 추론 공격
- `R9`: 간접 프롬프트 인젝션 공격

현재 구현에는 다음 기능도 포함되어 있습니다.

- `clean` 데이터셋과 `poisoned` 데이터셋 분리
- 표준 디렉터리 구조와 기존 레거시 구조를 모두 지원하는 시나리오별 데이터셋 선택
- `similarity_threshold`와 `reranker` 설정을 제어할 수 있는 검색 프로필
- 환경, 시나리오 범위, 프로필별 영속 FAISS 인덱스
- `rag query`와 `rag run`에서 공통으로 사용하는 질의 추적 정보
- 장시간 시나리오 배치를 위한 체크포인트 및 재개 기능
- PII 마스킹이 기본 적용되는 안전한 저장 아티팩트
- 마스킹 안전 정책을 지키는 KDPII 스타일 exact-match PII 벤치마크
- clean vs poisoned, reranker ON/OFF 비교를 포함한 리포트 생성

## 빠른 시작

### 1. 설치

```bash
pip install -e ".[dev]"
```

### 2. 환경 설정

```bash
copy .env.example .env
```

지원하는 환경 변수는 다음과 같습니다.

- `OPENAI_API_KEY`
- `RAG_CONFIG_PATH`
- `RAG_RESULTS_PATH`

### 3. 영속 인덱스 생성

```bash
rag ingest --path data/documents/ --env clean --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off --incremental
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off --incremental --sync-delete
```

권장 디렉터리 구조는 다음과 같습니다.

- `data/documents/clean/...`
- `data/documents/poisoned/...`
- 현재 저장소에는 두 디렉터리 아래에 표준 샘플 파일이 들어 있습니다.
- 기존 `general/sensitive/attack` 구조도 계속 지원하지만, 표준 디렉터리가 함께 있으면 표준 디렉터리를 우선 사용합니다.

영속 인덱스는 아래 경로에 저장됩니다.

- `data/indexes/clean/base/<profile>/`
- `data/indexes/poisoned/<scenario>/<profile>/`

ingest 생명주기 규칙은 다음과 같습니다.

- 기본 `rag ingest`는 보수적으로 동작하며, 현재 입력과 일치하는 인덱스가 이미 있으면 아무 작업도 하지 않고 재사용합니다.
- `--incremental`은 기존 일치 인덱스에 추가/수정된 파일만 반영합니다.
- `--incremental --sync-delete`는 데이터셋에서 사라진 파일도 인덱스에서 제거합니다.
- `--rebuild`는 해당 범위의 인덱스를 버리고 처음부터 다시 만듭니다.
- 수정된 파일은 `doc_id` 기준으로 교체됩니다. 즉, 재수집 전에 해당 파일의 기존 청크를 모두 삭제합니다.

### 4. 수동 질의 실행

```bash
rag query --question "Summarize the privacy policy requirements." --doc-path data/documents/ --env clean --profile default
rag query --question "What happens when the R9 trigger appears?" --doc-path data/documents/ --env poisoned --scenario R9 --profile reranker_on
```

`rag query`는 지정된 환경에 맞는 영속 인덱스를 불러옵니다. 인덱스가 없으면 한 번 자동으로 생성합니다.
`--env poisoned`를 사용할 때는 `--scenario R2|R4|R9`가 필요합니다. 이렇게 해야 질의 경로가 하나의 결정적인 poisoned 인덱스로 해석됩니다.
터미널에 출력되는 대화형 결과는 그대로 유지됩니다. 기본 안전 정책인 마스킹은 저장되는 실행 아티팩트와 리포트에 적용되며, 터미널 응답 자체에는 적용되지 않습니다.

### 5. 공격 시나리오 실행

```bash
rag run --scenario R2 --attacker A2 --env poisoned --profile reranker_off
rag run --scenario R4 --attacker A1 --env clean --profile default
rag run --scenario R9 --attacker A3 --env poisoned --profile reranker_on
rag run --scenario R2 --attacker A2 --env poisoned --profile reranker_off --resume RAG-2026-0425-001
```

`rag run` 실행 중에는 다음 파일이 기록됩니다.

- `snapshot.yaml`: 해석 완료된 설정과 인덱스 메타데이터
- `checkpoint.json`: 재개에 필요한 메타데이터
- `R*_partial.json`: 시나리오 범위별 부분 결과
- `*_result.json`: 완료된 부분 결과를 다시 합친 최종 결과

### 6. 리포트 생성

```bash
rag report --run-id RAG-2026-0425-001
```

### 7. `snapshot.yaml` 기반 저장 실행 재현

```bash
rag replay --run-id RAG-2026-0425-001
rag replay --run-id PII-EVAL-2026-0425-001
```

`rag replay`는 항상 새 실행 디렉터리를 만듭니다. 저장된 `snapshot.yaml`의 해석 완료 설정을 재사용하고,
`replay_audit.json`을 작성하며, 새 snapshot에 `replayed_from_run_id`, `compatibility_mode`,
정규화된 provenance 필드를 기록합니다.

### 8. KDPII 스타일 PII 벤치마크 실행

```bash
rag pii-eval --dataset-path C:\path\to\local-kdpii.jsonl --mode full
rag pii-eval --dataset-path C:\path\to\local-kdpii.jsonl --all-modes
```

`rag pii-eval`은 로컬 JSONL 파일을 입력으로 받으며, 각 줄은 다음 필드를 포함해야 합니다.

- `sample_id`
- `text`
- `entities`: `{start, end, label}` 객체의 리스트

저장소에는 아주 작은 합성 fixture만 `tests/fixtures/pii_eval_fixture.jsonl`에 들어 있습니다.
실제 KDPII 데이터는 저장소 밖에 보관해야 합니다.

## 검색 프로필

`config/default.yaml`은 기본 검색 설정과 프로필별 오버레이를 정의합니다.

- `default`
- `reranker_on`
- `reranker_off`

`load_config(profile=...)`는 선택한 프로필을 해석하고, `profile_name`과 최종 `retrieval_config`를 snapshot 및 결과 JSON 파일에 저장합니다.

## 영속 인덱스와 재개 기능

인덱스 manifest에는 다음 정보가 저장됩니다.

- `backend`
- `index_version`
- `environment_type`
- `scenario_scope`
- `dataset_scope`
- `dataset_selection_mode`
- `profile_name`
- `embedding_model`
- `dataset_manifest_hash`
- `doc_selection_summary`
- `file_hashes`
- `source_state`
- `last_ingest_delta`
- `last_ingest_mode`
- `doc_count`
- `created_at`

`rag query`와 `rag run`은 manifest가 현재 설정과 일치하면 기존 인덱스를 재사용합니다.
인덱스가 없으면 한 번 자동 생성합니다. manifest가 현재 입력과 맞지 않으면 인덱스를 조용히 덮어쓰지 않고, 명시적인 rebuild 안내와 함께 명령을 중단합니다.

재개 동작은 다음과 같습니다.

- `rag run --resume <run_id>`는 저장된 scenario, attacker, environment, profile이 현재 요청과 맞는지 검증합니다.
- 완료된 `query_id`는 건너뜁니다.
- 실패했거나 완료되지 않은 질의는 다시 시도합니다.
- 최종 요약은 저장된 partial result를 바탕으로 다시 만듭니다.

## PII 보호 강화

저장되는 실행 아티팩트에는 기본적으로 마스킹이 적용됩니다.

- 저장 결과 JSON의 `response`에는 마스킹된 응답이 들어갑니다.
- `response_masked`에는 같은 마스킹 텍스트가 명시적인 별칭으로 저장됩니다.
- 각 응답마다 `pii_summary`, `pii_findings`, `pii_runtime_status`가 저장됩니다.
- 원문 응답 텍스트는 평가 중 메모리에만 존재합니다.

기본 Step 3 NER 모델은 Hugging Face token-classification 모델입니다.

- [`townboy/kpfbert-kdpii`](https://huggingface.co/townboy/kpfbert-kdpii)

단계별 동작은 다음과 같습니다.

1. Step 1: 정규식 기반 탐지
2. Step 2: 체크섬 / 구조 검증
3. Step 3: Hugging Face NER 탐지
4. Step 4: sLLM 검증

fallback 동작은 다음과 같습니다.

- 로컬 모델 경로가 있으면 Step 3은 해당 로컬 경로를 먼저 사용합니다.
- Step 3 모델 로딩에 실패해도 실행은 중단되지 않고 Step 1과 Step 2만으로 계속 진행됩니다.
- `OPENAI_API_KEY`가 설정되어 있지 않으면 Step 4는 `mock_conservative` 모드로 실행되며, 해당 모드가 결과 아티팩트에 기록됩니다.

## 안전한 결과 아티팩트

저장되는 각 공격 결과에는 현재 다음 필드가 포함됩니다.

- `query_id`
- `environment_type`
- `scenario_scope`
- `dataset_scope`
- `profile_name`
- `index_manifest_ref`
- `retrieval_config`
- `raw_retrieved_documents`
- `thresholded_documents`
- `reranked_documents`
- `retrieved_documents`
- `final_prompt`
- `response`
- `response_masked`
- `masking_applied`
- `pii_summary`
- `pii_findings`
- `pii_runtime_status`

각 실행 디렉터리에는 다음 파일도 함께 저장됩니다.

- `snapshot.yaml`
- `checkpoint.json`
- `R2_partial.json` 같은 시나리오 범위별 partial result 파일
- 저장된 snapshot/result 아티팩트 안의 `index_manifest_ref` 및 dataset scope 메타데이터

## 리포트

`rag report`는 실행 디렉터리 아래에 `JSON`, `CSV`, `PDF` 아티팩트를 생성합니다.

리포트 입력은 기본적으로 안전한 형태를 사용합니다.

- 마스킹된 응답만 사용
- 원문 응답을 다시 읽지 않고 저장된 `pii_summary`와 `pii_runtime_status` 재사용
- clean vs poisoned 비교
- reranker ON/OFF 비교
- 상위 PII 태그와 high-risk 응답 비율

## 주요 명령

- `rag ingest`
- `rag query`
- `rag run`
- `rag report`
- `rag replay`
- `rag pii-eval`

## 검증 명령

```bash
python -m compileall src tests
pytest tests -q
ruff check src tests
```

## 참고 문서

- [docs/pii-detection-and-masking.md](./docs/pii-detection-and-masking.md)
- [docs/testing-and-acceptance.md](./docs/testing-and-acceptance.md)
