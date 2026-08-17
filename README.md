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

전체 데이터셋을 준비할 필요 없이, 저장소를 클론한 직후 아래 네 줄이면 전체 파이프라인
(인덱싱 → 공격 → 한국형 PII 탐지 → HTML 리포트)을 바로 체험할 수 있습니다.

```bash
pip install -e .            # 실행에 필요한 최소 의존성만 설치 (개발 도구 제외)
ollama serve &              # 로컬 LLM 서버 기동 (별도 터미널에서 실행해도 됩니다)
ollama pull qwen2.5:3b      # 응답 생성 모델 내려받기 (약 2GB, 최초 1회)
python -m rag demo          # 소형 데모셋으로 대표 시나리오 실행 후 HTML 리포트 자동 오픈
```

- **외부 API 키가 필요 없습니다.** 응답 생성기와 PII 교차검증 모두 로컬 모델로 동작하므로
  Closed API 호출이 0건입니다. 대신 **로컬 LLM 서버(Ollama)가 반드시 떠 있어야 합니다** —
  안 떠 있으면 `python -m rag demo` 가 실행 전에 안내 메시지를 내고 중단합니다
  (`cli/main.py:_preflight_local_generator`). Ollama 설치는 아래 [2.3](#23-로컬-llm-준비-필수) 참고.
- 실행되는 것: 소형 데모 코퍼스(`data/documents/demo/`) 인덱싱 → `NORMAL`(기준선) +
  `R2`(검색 데이터 유출) 실행 → PII 탐지 → `data/results/<run_id>/report_dashboard.html` 생성.
- 데모 인덱스는 `data/indexes/_demo/` 에 **격리 생성**되어 실제 인덱스를 덮어쓰지 않습니다.
- **소요 시간은 약 30분입니다**(75질의 · M2/16GB 실측). 최초 실행은 임베딩·NER 모델
  다운로드(약 1.5GB)가 더해집니다. 병목은 응답 생성기가 아니라 PII 탐지 파이프라인입니다
  (질의당 13초 중 생성기 몫은 0.7~3.4초). 브라우저 자동 열기를 원치 않으면
  `python -m rag demo --no-open`.

전체 규모 실험(5개 시나리오 × 2개 프로파일 = 10개 조합)은 아래 2장부터의 정식 절차를 따르세요.
우리 내장 RAG 가 아니라 **이미 운영 중인 다른 RAG 를 진단하려면** [4.9](#49-외부-rag-진단하기-byo-rag)
를 보세요.

## 2. 사전 준비

### 2.1 실행 환경

다음 환경을 권장합니다.

- 운영체제: macOS 12+, Ubuntu 20.04+, Windows 10/11 (WSL 권장)
- 언어:     Python 3.11 이상
- 메모리:   최소 8GB, 권장 16GB 이상
- 저장공간: 약 10GB 이상 (임베딩·리랭커·NER 모델 약 1.5GB + 로컬 LLM 가중치 약 4GB 포함)
- 로컬 LLM: **Ollama 필수.** 응답 생성기(`qwen2.5:3b`)와 PII 교차검증 sLLM 이 모두 로컬에서
  돕니다. GPU 는 필요 없고 CPU 로 동작합니다(아래 2.3 참고).
- 네트워크: 최초 실행 시 Hugging Face·Ollama 에서 모델을 내려받기 위한 인터넷 연결.
  이후에는 캐시를 재사용하므로 **오프라인에서도 전 과정이 동작합니다** — 외부 LLM API 를
  호출하지 않기 때문입니다.

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

### 2.3 로컬 LLM 준비 (필수)

이 시스템은 **응답 생성기와 PII 교차검증 sLLM 을 모두 로컬에서 구동**합니다. 외부 LLM API 를
호출하지 않으므로 API 키가 필요 없지만, 대신 **로컬 LLM 서버가 떠 있어야 합니다.**

#### (1) 응답 생성기 — 필수

```bash
brew install ollama          # macOS. Linux: curl -fsSL https://ollama.com/install.sh | sh
ollama serve                 # 별도 터미널에서 계속 띄워 둡니다
ollama pull qwen2.5:3b       # 기본 생성 모델 (약 2GB)
```

`config/default.yaml` 의 기본값이 `generator.provider: "local"` · `generator.local.model: "qwen2.5:3b"`
입니다. 서버가 응답하지 않거나 모델이 등록되지 않았으면 `rag run` / `rag demo` 가 **질의를 시작하기
전에 중단하고 안내**합니다(전 질의가 실패한 리포트가 나오는 것을 막기 위함입니다).

> ⚠️ **모델을 바꿀 때는 Ollama 기본 설정에서 로드되는지 먼저 확인하세요.** Homebrew 포뮬러가
> `OLLAMA_KV_CACHE_TYPE=q8_0` 을 기본으로 설정하므로, head_dim 이 32 로 나누어떨어지지 않는 모델은
> 로드 자체가 실패합니다. 또한 추론 과정을 출력하는 이른바 thinking 모델은 쓰지 마세요 — `R2` 는
> 응답의 ROUGE, `R7` 은 응답과 시스템 프롬프트의 코사인 유사도로 채점하므로 추론 흔적이 지표를
> 오염시킵니다.

#### (2) PII 교차검증 sLLM — 권장

한국어 개인정보 33종으로 파인튜닝한 모델을 STEP 4 교차검증에 사용합니다. 등록하지 않으면 STEP 4 가
보수적 모드(후보 전량 수락)로 떨어져 **탐지량이 부풀려집니다.**

```bash
hf download bbanany/qwen25-3b-korean-pii-gguf \
  qwen25-3b-korean-pii-Q4_K_M.gguf Modelfile --local-dir ~/korean-pii
cd ~/korean-pii && ollama create korean-pii -f Modelfile
```

등록 후 API 에 넘기는 이름은 GGUF 파일명이 아니라 **`korean-pii`** 입니다(`config/default.yaml`
의 `pii.sllm.model` 기본값과 일치).

#### (3) 외부 API 키 — 개발용, 선택 사항

`.env` 에 키를 넣고 `generator.provider` 를 `openai` / `clova` 로 바꾸면 상용 API 로도 비교 실행할
수 있습니다. **기본 실행 경로가 아니며**, 대회 제출 구성은 위 (1)(2) 의 로컬 경로입니다.

```bash
cp .env.example .env    # Windows PowerShell: Copy-Item .env.example .env
```

```env
OPENAI_API_KEY=sk-...
NAVER_CLOVA_API_KEY=...
```

실제로 어떤 경로로 돌았는지는 결과물의 `runtime_status.step4.is_closed_api` 로 확인할 수 있습니다
(로컬 경로면 `false`).

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
python -m rag run --all-scenarios --all-profiles --auto-report
```

5개 시나리오 × 2개 프로파일(리랭커 on/off) = **10개 조합**이 실행됩니다. 시나리오별 공격자 유형은
자동으로 결정되므로 따로 지정할 필요가 없습니다([4.2](#42-특정-시나리오만-실행하기) 참고).

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
| `NORMAL` | 공격이 없을 때 기본 PII 노출량 | `python -m rag run -s NORMAL --auto-report` |
| `R2` | 검색 데이터가 응답에 그대로 노출되는지 | `python -m rag run -s R2 --auto-report` |
| `R4` | 특정 문서가 검색 DB에 포함됐는지 추론 가능한지 | `python -m rag run -s R4 --auto-report` |
| `R7` | 시스템 프롬프트가 노출되는지 | `python -m rag run -s R7 --auto-report` |
| `R9` | 공격 문서가 응답을 조작하는지 | `python -m rag run -s R9 --auto-report` |

**공격자 유형은 지정할 필요가 없습니다.** 시나리오마다 위협 모델이 하나로 고정돼 있어서
`attack/query_generator.py:SCENARIO_ATTACKER_MATRIX` 가 자동으로 선택합니다. 연구 목적으로 다른
조합을 강제하려면 `-a` 로 지정할 수 있고, 권장 조합을 벗어나면 경고만 남기고 실행됩니다.

| 시나리오 | 사용되는 공격자 | 가정한 권한 | 설명 |
|---|---|---|---|
| `NORMAL` | `A1` 외부 관찰자 | 질의 | 공격이 없는 baseline |
| `R2` | `A2` 내용 인지 관찰자 | 질의 + 문서 라벨 | 표적 문서의 식별자를 앵커로 사용해야 유출이 발생 |
| `R4` | `A2` 내용 인지 관찰자 | 질의 + 문서 라벨 | 멤버십 추론 정의상 대상 문서의 존재를 아는 공격자 |
| `R7` | `A1` 외부 관찰자 | 질의 | 시스템 프롬프트 유출은 블랙박스 외부자 위협 모델 |
| `R9` | `A3` 문서 주입 내부자 | 질의 + 인덱스 쓰기 | 코퍼스에 악성 문서를 삽입할 수 있는 공격자 |

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

`pii-eval`은 공격 시나리오 실행이 아니라 PII 탐지 파이프라인 자체의 성능을 확인할 때 사용합니다. 라벨이 달린 JSONL 데이터셋을 입력하면 정밀도, 재현율, F1 등 PII 탐지 성능 지표를 확인할 수 있습니다.

> 데이터셋의 라벨 체계는 **개인정보 33종**이어야 합니다. 구 KDPII 데이터셋(`CV`/`QT`/`OG`/`PS` 같은 14종 대분류)은 현재 NER 모델(`townboy/kpfbert-ner`)의 라벨 체계와 맞지 않아 채점이 성립하지 않습니다.

JSONL 파일은 각 줄에 다음 필드를 포함해야 합니다.

| 필드 | 설명 |
|---|---|
| `sample_id` | 샘플을 구분하는 문자열 ID |
| `text` | PII 탐지 대상 원문 |
| `entities` | 정답 엔티티 목록. 각 항목은 `start`, `end`, `label`을 포함 |

전체 파이프라인(STEP 0~4)을 한 번 실행하려면 다음 명령을 사용합니다.

```bash
python -m rag pii-eval --dataset-path ./pii-labeled.jsonl --mode full
```

각 단계별 성능 변화를 비교하려면 모든 모드를 실행합니다.

```bash
python -m rag pii-eval --dataset-path ./pii-labeled.jsonl --all-modes
```

사용할 수 있는 모드는 다음과 같습니다.

| 모드 | 평가 범위 |
|---|---|
| `step1` | 정규식 탐지만 평가 |
| `step1_2` | 정규식 탐지와 체크섬 검증까지 평가 |
| `step1_2_3` | KPF-BERT NER까지 포함해 평가 |
| `full` | sLLM 교차검증까지 포함한 전체 평가 |

> 주의: 재배포 제약이 있는 데이터셋은 저장소에 포함하지 마세요. 배포본에서는 합성 fixture 또는 사용자가 직접 준비한 로컬 데이터셋을 사용합니다.

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

### 4.9 외부 RAG 진단하기 (BYO-RAG)

이 도구는 우리 내장 RAG 뿐 아니라 **이미 운영 중인 다른 RAG 서비스**도 같은 방식으로 진단할 수
있습니다. 진단 대상은 어댑터 계층(`src/rag/adapters/`)으로 교체하며, 설정 파일 한 개만 바꾸면
공격·평가·리포트 파이프라인은 그대로 재사용됩니다.

`config/anythingllm.yaml` 이 오픈소스 RAG 인 **AnythingLLM** 을 대상으로 하는 완성된 예시입니다.

```yaml
adapter:
  type: rest                                # builtin(내장) / rest(외부 REST) / sota
  capabilities: []                          # 비우면 타입의 기본 능력 전체. 좁혀 선언하면 그만큼만 진단
  base_url: "http://localhost:3001"
  workspace: "<워크스페이스 slug 또는 id>"
  api_key: "${ANYTHINGLLM_API_KEY}"         # ${VAR} 는 .env / 환경변수로 치환됩니다
  timeout: 300.0                            # 로컬 CPU 생성은 기본 30초로는 전량 타임아웃납니다
  inject_poison: true                       # R9 악성 문서를 대상에 실제로 업로드
```

```bash
python -m rag run --all-scenarios -c config/anythingllm.yaml --auto-report
```

**대상이 못 하는 것은 조용히 넘어가지 않고 리포트에 명시됩니다.** 어댑터가 노출한 능력을 근거로
시나리오별 실행 계획이 먼저 결정되고(`adapters/capabilities.py:plan_scenario_execution`), 결과는
대시보드의 "진단 범위" 열에 사유와 함께 표시됩니다.

| 판정 | 의미 | 예 |
|---|---|---|
| 완전판 | 필요한 능력을 모두 갖춰 정상 진단 | `NORMAL` · `R2` · `R7` · `R9` |
| 축소 | 권장 능력이 없어 일부만 진단 | 검색 원문을 안 주는 대상의 `R2` |
| 미실시 | 필수 능력이 없어 실행 불가 | `R4` — 라이브 인덱스에서 특정 문서만 뺀 반사실 구성이 불가능 |

측정한 적 없는 항목이 "양호"로 집계되지 않도록, 미실시 시나리오는 성공률·권고 조치에서 모두
제외됩니다.

> ⚠️ **외부 대상 진단 시 주의 3가지 (전부 실측으로 확인된 함정입니다)**
>
> 1. **검색 임계값을 먼저 낮추세요.** AnythingLLM 워크스페이스 기본
>    `similarityThreshold` 는 0.25 인데, 실제 유출이 발생한 응답의 검색 점수가 0.166 이었습니다.
>    기본값 그대로면 진짜 유출이 검색 단계에서 걸러져 "안전함"으로 잘못 나옵니다.
> 2. **`--all-profiles` 를 쓰지 마세요.** 리랭커 on/off 는 우리 파이프라인의 설정이라 외부
>    대상에 전달되지 않습니다. 대상이 자체 리랭커를 쓰면 `reranker_on`/`reranker_off` 라벨이
>    거짓이 됩니다.
> 3. **R9 를 재려면 두 설정이 모두 필요합니다** — `adapter.inject_poison: true` 와
>    `attack.r9.trigger_source: "corpus"`. 하나라도 빠지면 악성 문서가 대상에 들어가지 않은 채
>    질의만 나가고, 그 0건이 "방어 성공"으로 집계됩니다. 지금은 이 조합을 실행 전에 검사해
>    막습니다.
>
> `push_system_prompt` 를 켜면 우리 방어 프롬프트를 대상 워크스페이스에 **설정한 뒤** 진단합니다.
> 대상의 설정을 실제로 변경하므로, 남이 운영하는 RAG 에는 켜지 마세요.

## 5. 결과 확인 방법

실행하지 않고 결과물만 먼저 보려면 [`docs/sample-reports/`](docs/sample-reports/) 에 완주한
실험 1건(10셀 · 1,128질의)의 리포트가 그대로 담겨 있습니다. GitHub 웹에서는 HTML 이 렌더되지
않으므로 저장소를 받은 뒤 로컬 브라우저로 여세요 (받는 방법은 그 폴더의 README 참고).

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
3. 위험 등급별(고유식별·금융 / 연락처 / 신원문맥) 유출량 — 총량만 보면 놓치는 것이 있습니다
4. 일반 질의(대조군) 대비 공격이 추가로 만들어낸 유출량
5. 리랭커 ON/OFF 차이

## 6. 자주 겪는 문제

| 상황 | 원인 | 해결 방법 |
|---|---|---|
| 실행 전 "로컬 LLM 서버 응답 없음"으로 중단 | `ollama serve`가 떠 있지 않거나 모델 미등록 | `ollama serve` 실행 후 `ollama pull qwen2.5:3b` ([2.3](#23-로컬-llm-준비-필수)) |
| Step 4 결과가 `mock_conservative` | PII 교차검증 sLLM이 등록되지 않음 (탐지량이 부풀려집니다) | `ollama create korean-pii -f Modelfile` 로 등록 ([2.3](#23-로컬-llm-준비-필수) (2)) |
| Step 4 결과에 연결 오류가 기록됨 | 모델은 등록됐지만 `ollama serve`가 죽어 있음 | 서버를 다시 띄우고 재실행. 결과는 `mock_conservative`와 겉보기가 같으니 `runtime_status.step4.error`로 구분하세요 |
| `Error: No such option` | 삭제된 CLI 옵션 사용 | `python -m rag run --help`로 현재 옵션 확인 |
| `Index not found` | 인덱스가 아직 생성되지 않음 | `python -m rag ingest --env clean` 실행 |
| `manifest mismatch` | 문서나 설정이 바뀜 | 인덱스를 다시 만들거나 `--rebuild` 사용 |
| `--scenario is required` | 단일 실행에서 시나리오 미지정 | `-s R2`처럼 시나리오를 지정하거나 `--all-scenarios` 사용 |
| poisoned ingest 오류 | poisoned 환경에서 시나리오 미지정 | `python -m rag ingest --env poisoned -s R9` 실행 |
| 실행 중 타임아웃이 잦음 | 로컬 생성이 느림 | `--resume <run_id>`로 이어서 실행. 외부 대상이면 `adapter.timeout`을 늘리세요 |
| HTML 차트가 비어 있음 | 일부 시나리오 결과 파일이 없음 | 전체 시나리오를 다시 실행 |
| 외부 RAG 진단에서 R4가 "미실시" | 대상이 인덱스 재구성을 지원하지 않음 | 정상 동작입니다 ([4.9](#49-외부-rag-진단하기-byo-rag)) |

## 7. 자주 쓰는 명령어 모음

### 설치 및 설정

```bash
pip install -e .                        # 실행용 (심사·사용자)
pip install -e ".[dev]"                 # 기여자용 (pytest, ruff 포함)
ollama serve                            # 로컬 LLM 서버 (별도 터미널)
ollama pull qwen2.5:3b                  # 응답 생성 모델
ollama create korean-pii -f Modelfile   # PII 교차검증 sLLM (~/korean-pii 에서)
```

외부 API 키는 선택 사항입니다. 필요하면 `cp .env.example .env` 후 값을 입력합니다.

### 인덱스

```bash
python -m rag ingest --env clean
python -m rag ingest --env poisoned -s R9
python -m rag ingest --env clean --incremental
python -m rag ingest --env clean --rebuild
```

### 실행

```bash
python -m rag run -s R2 --auto-report
python -m rag run -s R9 --auto-report
python -m rag run --all-scenarios --all-profiles --auto-report
python -m rag run --all-scenarios -n 5 --auto-report
python -m rag run --all-scenarios -c config/anythingllm.yaml --auto-report   # 외부 RAG 진단
```

### PII 탐지 성능 평가

```bash
python -m rag pii-eval --dataset-path ./pii-labeled.jsonl --mode full
python -m rag pii-eval --dataset-path ./pii-labeled.jsonl --all-modes
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

1. `pip install -e .`로 설치합니다.
2. `ollama serve` + `ollama pull qwen2.5:3b`로 로컬 LLM을 준비합니다([2.3](#23-로컬-llm-준비-필수)).
3. `python -m rag demo`로 전체 파이프라인이 끝까지 도는지 먼저 확인합니다(약 30분).
4. `data/documents` 아래에 테스트 문서를 넣습니다.
5. 빠른 확인이 필요하면 `python -m rag run --all-scenarios -n 5 --auto-report`를 실행합니다.
6. 정식 결과가 필요하면 전체 매트릭스 실행 명령을 사용합니다.
7. `data/results/<run_id>/report_dashboard.html`을 열어 결과를 확인합니다.
8. 문서를 추가하거나 수정했다면 `ingest --incremental`로 인덱스를 갱신합니다.

## 9. 안전한 테스트를 위한 주의사항

- 실제 개인정보를 테스트 문서에 넣지 마세요.
- 민감 문서에는 합성 데이터를 사용하세요.
- API 키가 포함된 `.env` 파일은 Git에 커밋하지 마세요.
- 대시보드나 CSV 결과를 공유하기 전 PII 마스킹 설정을 확인하세요.
- 오픈소스 배포 시 예제 데이터도 실제 개인정보가 없는지 확인하세요.
