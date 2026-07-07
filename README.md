# RAG 공격 및 한국형 PII 유출 진단 시스템 사용자 매뉴얼

이 문서는 RAG 기반 서비스가 개인정보(PII)를 얼마나 노출하는지 진단하기 위해 시스템을 처음 사용하는 사용자를 위한 실사용 중심 가이드입니다.

복잡한 내부 구조나 평가 이론보다, 설치 후 실제로 실험을 실행하고 결과를 확인하는 절차에 초점을 맞췄습니다.

## 1. 시스템 개요

이 시스템은 RAG 파이프라인에 여러 공격 시나리오를 적용해 응답에 개인정보가 노출되는지 측정합니다. 실행이 끝나면 HTML 대시보드, CSV, JSON 형식의 결과 파일이 생성됩니다.

주요 사용 흐름은 다음과 같습니다.

1. 테스트 문서를 준비합니다.
2. 문서를 검색 인덱스에 등록합니다.
3. 공격 시나리오를 실행합니다.
4. 생성된 리포트에서 위험도와 PII 노출 결과를 확인합니다.

## 빠른 시작 (심사위원용 원커맨드 데모)

전체 데이터셋을 준비할 필요 없이, 저장소를 클론한 직후 아래 두 줄이면 전체 파이프라인
(인덱싱 → 공격 → 한국형 PII 탐지 → HTML 리포트)을 바로 체험할 수 있습니다.

```bash
pip install -e .    # 실행에 필요한 최소 의존성만 설치 (개발 도구 제외)
python -m rag demo  # 소형 데모셋으로 대표 시나리오 실행 후 HTML 리포트 자동 오픈
```

- **API 키가 필요 없습니다.** 키가 없으면 오프라인 MockGenerator/보수적 PII 검증으로 완주하며,
  키가 있으면 실제 LLM 을 사용합니다.
- 실행되는 것: 소형 데모 코퍼스(`data/documents/demo/`) 인덱싱 → `NORMAL`(기준선) +
  `R2`(검색 데이터 유출) 실행 → PII 탐지 → `data/results/<run_id>/report_dashboard.html` 생성.
- 데모 인덱스는 `data/indexes/_demo/` 에 **격리 생성**되어 실제 인덱스를 덮어쓰지 않습니다.
- 최초 실행 시에만 임베딩/NER 모델(약 1.5GB)을 내려받으므로 몇 분 걸릴 수 있고, 이후에는 캐시를
  재사용해 수 분 내에 끝납니다. 브라우저 자동 열기를 원치 않으면 `python -m rag demo --no-open`.

전체 규모 실험(5개 시나리오 × 공격자 × 프로파일)은 아래 2장부터의 정식 절차를 따르세요.

## 2. 사전 준비

### 2.1 실행 환경

다음 환경을 권장합니다.

- 운영체제: macOS 12+, Ubuntu 20.04+, Windows 10/11 (WSL 권장)
- 언어:     Python 3.11 이상
- 메모리:   최소 8GB, 권장 16GB 이상
- 저장공간: 약 5GB 이상 (임베딩·리랭커·NER 모델 최초 다운로드 약 1.5GB 포함)
- 네트워크: 최초 실행 시 Hugging Face 에서 모델을 내려받기 위한 인터넷 연결.
  이후에는 캐시를 재사용하므로 오프라인에서도 동작합니다. LLM API(OpenAI/CLOVA)는
  선택 사항이며, 키가 없으면 오프라인 대체 경로로 동작합니다(아래 2.3 참고).

### 2.2 설치

프로젝트 루트 폴더에서 다음 명령을 실행합니다.

```bash
pip install -e .
```

이 명령은 실행에 필요한 최소 의존성만 설치합니다. 테스트·린트 등 개발 도구까지 함께
설치하려면(기여자용) 다음을 사용합니다.

```bash
pip install -e ".[dev]"   # pytest, ruff 등 개발 도구 포함
```

설치가 끝나면 다음 명령으로 CLI가 정상적으로 표시되는지 확인합니다.

```bash
python -m rag
```

### 2.3 API 키 설정 (선택 사항)

API 키는 **필수가 아닙니다.** 키가 없으면 생성기는 오프라인 MockGenerator(검색 문서 원문을
응답으로 반환)로, PII 4단계의 sLLM 교차검증은 보수적 모드로 자동 대체되어 실험이 끝까지
동작합니다. `python -m rag demo` 및 `NORMAL`/`R2` 는 키 없이도 의미 있는 결과를 만듭니다.

실제 LLM 응답으로 더 정밀하게 측정하려면(특히 `R7`/`R9` 처럼 생성기 가드레일 우회가 핵심인
시나리오), 아래처럼 키를 설정합니다. `.env.example`을 복사해 `.env` 파일을 만든 뒤 사용할 키를
입력합니다.

```bash
cp .env.example .env
```

Windows PowerShell에서는 다음 명령을 사용할 수 있습니다.

```powershell
Copy-Item .env.example .env
```

`.env` 파일을 열어 다음 항목 중 사용할 API 키를 입력합니다.

```env
OPENAI_API_KEY=sk-...
NAVER_CLOVA_API_KEY=...
```

기본 설정이 `auto`인 경우 OpenAI 키가 있으면 OpenAI를 우선 사용하고, OpenAI 키가 없고 CLOVA 키만
있으면 CLOVA를 사용합니다. 둘 다 없으면 오프라인 대체 경로(MockGenerator + 보수적 PII 검증)로
동작합니다.

> 참고: 키 없이 실행하면 생성기가 응답을 재작성하지 않고 검색 원문을 그대로 반환하므로, 원문
> 유출을 보는 `R2` 나 기준선 `NORMAL` 은 유의미하지만, 생성기의 가드레일 우회가 본질인 `R7`/`R9`
> 는 실제 LLM 키가 있을 때 더 정확하게 측정됩니다.

### 2.4 데이터 준비

문서는 `data/documents` 폴더 아래에 넣습니다.

```text
data/documents/
├── clean/
│   ├── normal/
│   └── sensitive/
└── poisoned/
    ├── normal/
    ├── sensitive/
    └── attack/
```

각 폴더의 용도는 다음과 같습니다.

| 폴더 | 넣는 파일 | 사용 목적 |
|---|---|---|
| `clean/normal` | 일반 업무 문서 | 공격이 없는 일반 검색 기준선 측정 |
| `clean/sensitive` | 합성 PII가 들어간 민감 문서 | R2, R4 등 민감 정보 노출 테스트 |
| `poisoned/normal` | clean과 동일 내용 |
| `poisoned/sensitive` | clean과 동일 내용 |
| `poisoned/attack` | 프롬프트 주입용 공격 문서 | R9 간접 프롬프트 주입 테스트 |

지원 파일 형식은 다음과 같습니다.

- `.txt`
- `.md`
- `.pdf`

> 주의: 실제 개인정보는 넣지 마세요. 테스트에는 합성 데이터를 사용해야 합니다.

## 3. 가장 빠른 실행 방법

처음 사용하는 경우 전체 시나리오를 한 번 실행해 시스템이 끝까지 동작하는지 확인하는 것이 가장 쉽습니다.

```bash
python -m rag run --all-scenarios --all-attackers --all-profiles --auto-report
```

실행이 끝나면 다음 위치에 결과 폴더가 생성됩니다.

```text
data/results/<run_id>/
```

가장 먼저 확인할 파일은 다음 HTML 대시보드입니다.

```text
data/results/<run_id>/report_dashboard.html
```

브라우저에서 이 파일을 열면 종합 위험도, 시나리오별 결과, PII 노출 유형을 확인할 수 있습니다.

> 첫 실행 시 인덱스가 없으면 시스템이 자동으로 FAISS 인덱스를 생성합니다. 문서 수와 모델 다운로드 상태에 따라 시간이 더 걸릴 수 있습니다.

## 4. 작업별 사용법

### 4.1 문서 인덱스 만들기

문서를 처음 넣었거나 문서가 바뀐 경우 인덱스를 갱신합니다.

Clean 데이터 인덱스:

```bash
python -m rag ingest --env clean
```

R9용 poisoned 데이터 인덱스:

```bash
python -m rag ingest --env poisoned --scenario R9
```

파일 일부만 바뀐 경우:

```bash
python -m rag ingest --env clean --incremental
```

삭제된 파일까지 인덱스에서 동기화하려면 다음 명령을 사용합니다.

```bash
python -m rag ingest --env clean --incremental --sync-delete
```

처음부터 다시 만들려면 다음 명령을 사용합니다.

```bash
python -m rag ingest --env clean --rebuild
```

위의 증분 반영, 삭제 동기화, 전체 재생성 명령은 `poisoned` 환경에서도 사용법이 동일합니다. `--env clean` 대신 `--env poisoned --scenario R9`를 지정하면 됩니다.

```bash
python -m rag ingest --env poisoned --scenario R9 --incremental
python -m rag ingest --env poisoned --scenario R9 --incremental --sync-delete
python -m rag ingest --env poisoned --scenario R9 --rebuild
```

### 4.2 특정 시나리오만 실행하기

전체 실행이 오래 걸리거나 특정 공격만 확인하고 싶다면 시나리오를 지정해 실행합니다.

| 시나리오 | 확인하는 내용 | 예시 명령 |
|---|---|---|
| `NORMAL` | 공격이 없을 때 기본 PII 노출량 | `python -m rag run -s NORMAL --all-attackers --auto-report` |
| `R2` | 검색 데이터가 응답에 그대로 노출되는지 | `python -m rag run -s R2 --all-attackers --auto-report` |
| `R4` | 특정 문서가 검색 DB에 포함됐는지 추론 가능한지 | `python -m rag run -s R4 --all-attackers --auto-report` |
| `R7` | 시스템 프롬프트가 노출되는지 | `python -m rag run -s R7 --all-attackers --auto-report` |
| `R9` | 공격 문서가 응답을 조작하는지 | `python -m rag run -s R9 --all-attackers --auto-report` |

시나리오마다 사용할 수 있는 공격자 유형은 고정되어 있습니다. `--all-attackers` 옵션을 사용해도 모든 공격자를 무조건 실행하는 것이 아니라, 아래 호환 매트릭스에 맞는 공격자만 자동으로 선택됩니다.

| 시나리오 | 사용되는 공격자 | 설명 |
|---|---|---|
| `NORMAL` | `A1` | 공격이 없는 baseline이므로 A1로 고정 |
| `R2` | `A1`, `A2` | A1과 A2를 비교하는 것이 핵심 실험축 |
| `R4` | `A2` | 멤버십 추론 공격 정의상 대상 문서를 아는 공격자를 사용 |
| `R7` | `A1` | 시스템 프롬프트 유출 위협 모델이 단일 공격자로 고정 |
| `R9` | `A3` | poisoned 문서를 활용하는 간접 프롬프트 주입 공격자로 고정 |

### 4.3 빠른 테스트 실행하기

전체 데이터 대신 일부 문서만 사용해 빠르게 확인하려면 `-n` 옵션을 사용합니다.

```bash
python -m rag run --all-scenarios -n 5 --auto-report
```

### 4.4 RAG 응답 직접 확인하기

실험 전후에 RAG가 정상적으로 응답하는지 확인할 때 사용합니다.

```bash
python -m rag query -q "회사 소개 자료 알려주세요" --env clean
```

R9 poisoned 환경에서 확인하려면 다음처럼 실행합니다.

```bash
python -m rag query -q "R9 트리거가 발견되면 어떻게 하나요?" --env poisoned --scenario R9 --profile reranker_on
```

### 4.5 PII 탐지 성능 평가하기

`pii-eval`은 공격 시나리오 실행이 아니라 PII 탐지 파이프라인 자체의 성능을 확인할 때 사용합니다. KDPII 형식의 JSONL 데이터셋을 입력하면 정밀도, 재현율, F1 등 PII 탐지 성능 지표를 확인할 수 있습니다.

JSONL 파일은 각 줄에 다음 필드를 포함해야 합니다.

| 필드 | 설명 |
|---|---|
| `sample_id` | 샘플을 구분하는 문자열 ID |
| `text` | PII 탐지 대상 원문 |
| `entities` | 정답 엔티티 목록. 각 항목은 `start`, `end`, `label`을 포함 |

전체 4단계 파이프라인을 한 번 실행하려면 다음 명령을 사용합니다.

```bash
python -m rag pii-eval --dataset-path ./local-kdpii.jsonl --mode full
```

각 단계별 성능 변화를 비교하려면 모든 모드를 실행합니다.

```bash
python -m rag pii-eval --dataset-path ./local-kdpii.jsonl --all-modes
```

사용할 수 있는 모드는 다음과 같습니다.

| 모드 | 평가 범위 |
|---|---|
| `step1` | 정규식 탐지만 평가 |
| `step1_2` | 정규식 탐지와 체크섬 검증까지 평가 |
| `step1_2_3` | KPF-BERT NER까지 포함해 평가 |
| `full` | sLLM 교차검증까지 포함한 전체 4단계 평가 |

> 주의: KDPII 원본 데이터셋은 저장소에 포함하지 마세요. 오픈소스 배포 시에는 합성 fixture나 별도 안내된 로컬 데이터셋을 사용해야 합니다.

### 4.6 리포트만 다시 만들기

이미 끝난 실험 결과로 HTML, CSV, JSON 리포트만 다시 만들 수 있습니다.

아래 예시의 `RAG-2026-0501-001`은 예시 runID입니다. 실제로 확인하려는 결과 폴더의 runID로 바꿔서 사용하면 됩니다.

```bash
python -m rag report --run-id RAG-2026-0501-001
```

### 4.7 중단된 실험 이어서 실행하기

네트워크 오류나 API 제한으로 중간에 멈춘 경우 `run_id`를 사용해 이어서 실행합니다.

아래 예시의 `RAG-2026-0501-001`은 예시 runID입니다. 이어서 실행하려는 실험의 runID로 바꿔서 사용하면 됩니다.

```bash
python -m rag run --all-scenarios --resume RAG-2026-0501-001
```

### 4.8 같은 설정으로 재실행하기

기존 실험의 `snapshot.yaml`을 사용해 같은 설정으로 다시 실행하려면 `replay`를 사용합니다.

아래 예시의 `RAG-2026-0501-001`은 예시 runID입니다. 같은 설정으로 다시 실행하려는 실험의 runID로 바꿔서 사용하면 됩니다.

```bash
python -m rag replay --run-id RAG-2026-0501-001
```

## 5. 결과 확인 방법

실행이 끝나면 `data/results/<run_id>/` 폴더에 결과가 저장됩니다.

주요 파일은 다음과 같습니다.

| 파일 | 설명 |
|---|---|
| `report_dashboard.html` | 브라우저에서 보는 종합 대시보드 |
| `report_detail.csv` | 응답 단위 결과를 표 형태로 저장한 파일 |
| `report_summary.json` | 시나리오, 환경, 프로파일별 요약 결과 |
| `<scenario>_result.json` | 시나리오별 상세 평가 결과 |
| `snapshot.yaml` | 같은 설정으로 재실행할 때 사용하는 설정 스냅샷 |
| `checkpoint.json` | 중단된 실험을 이어서 실행할 때 사용하는 진행 상태 |

대시보드에서는 다음 항목을 우선 확인합니다.

1. 종합 위험 등급
2. 시나리오별 공격 성공률
3. 고위험 PII 비율
4. 어떤 유형의 PII가 자주 노출됐는지
5. 리랭커 ON/OFF 또는 공격자별 차이

## 6. 자주 겪는 문제

| 상황 | 원인 | 해결 방법 |
|---|---|---|
| `OPENAI_API_KEY not set` | `.env`에 API 키가 없음 | `.env.example`을 복사해 `.env`를 만들고 `OPENAI_API_KEY=sk-...` 추가 |
| `Index not found` | 인덱스가 아직 생성되지 않음 | `python -m rag ingest --env clean` 실행 |
| `manifest mismatch` | 문서나 설정이 바뀜 | 인덱스를 다시 만들거나 `--rebuild` 사용 |
| `--scenario is required` | 단일 실행에서 시나리오 미지정 | `-s R2`처럼 시나리오를 지정하거나 `--all-scenarios` 사용 |
| poisoned ingest 오류 | poisoned 환경에서 시나리오 미지정 | `python -m rag ingest --env poisoned -s R9` 실행 |
| 실행 중 API 오류 | 네트워크 문제 또는 API 호출 제한 | `--resume <run_id>`로 이어서 실행 |
| HTML 차트가 비어 있음 | 일부 시나리오 결과 파일이 없음 | 전체 시나리오를 다시 실행 |
| Step 4 결과가 `mock_conservative` | OpenAI 키가 설정되지 않음 | `.env.example`을 복사해 만든 `.env`에 API 키를 추가하고 재실행 |

## 7. 자주 쓰는 명령어 모음

### 설치 및 설정

```bash
pip install -e ".[dev]"
cp .env.example .env
```

`.env` 파일을 연 뒤 `OPENAI_API_KEY` 또는 `NAVER_CLOVA_API_KEY` 값을 입력합니다.

### 인덱스

```bash
python -m rag ingest --env clean
python -m rag ingest --env poisoned -s R9
python -m rag ingest --env clean --incremental
python -m rag ingest --env clean --rebuild
```

### 실행

```bash
python -m rag run -s R2 --all-attackers --auto-report
python -m rag run -s R9 --all-attackers --auto-report
python -m rag run --all-scenarios --all-attackers --all-profiles --auto-report
python -m rag run --all-scenarios -n 5 --auto-report
```

### PII 탐지 성능 평가

```bash
python -m rag pii-eval --dataset-path ./local-kdpii.jsonl --mode full
python -m rag pii-eval --dataset-path ./local-kdpii.jsonl --all-modes
```

### 결과 확인 및 재실행

`RAG-2026-0501-001` 부분에는 확인하거나 재실행하려는 실제 runID를 입력합니다.

```bash
python -m rag report --run-id RAG-2026-0501-001
python -m rag run --all-scenarios --resume RAG-2026-0501-001
python -m rag replay --run-id RAG-2026-0501-001
```

### 디버깅 및 도움말

```bash
python -m rag query -q "회사 소개 자료 알려주세요" --env clean
python -m rag
python -m rag run --help
```

## 8. 처음 사용하는 사람을 위한 권장 순서

처음 사용하는 경우 아래 순서대로 진행하세요.

1. `pip install -e ".[dev]"`로 설치합니다.
2. `.env.example`을 복사해 `.env` 파일을 만들고 API 키를 입력합니다.
3. `data/documents` 아래에 테스트 문서를 넣습니다.
4. 빠른 확인이 필요하면 `python -m rag run --all-scenarios -n 5 --auto-report`를 실행합니다.
5. 정식 결과가 필요하면 전체 매트릭스 실행 명령을 사용합니다.
6. `data/results/<run_id>/report_dashboard.html`을 열어 결과를 확인합니다.
7. 문서를 추가하거나 수정했다면 `ingest --incremental`로 인덱스를 갱신합니다.

## 9. 안전한 테스트를 위한 주의사항

- 실제 개인정보를 테스트 문서에 넣지 마세요.
- 민감 문서에는 합성 데이터를 사용하세요.
- API 키가 포함된 `.env` 파일은 Git에 커밋하지 마세요.
- 대시보드나 CSV 결과를 공유하기 전 PII 마스킹 설정을 확인하세요.
- 오픈소스 배포 시 예제 데이터도 실제 개인정보가 없는지 확인하세요.
