# Third-Party Notices

이 파일은 `python scripts/license_scan.py` 로 생성됩니다. **직접 고치지 마세요** —
의존성을 바꿨으면 설치 후 스크립트를 다시 돌리면 됩니다.

본 프로젝트(RAG-DIAG)는 MIT 라이선스입니다(`LICENSE`). 아래는 함께 쓰이는 제3자
구성요소의 라이선스 목록입니다.

## 요약

- 파이썬 의존 폐포: **87개**(설치 기준)
- copyleft 계열: **2개** — certifi, tqdm
- 라이선스 미상: **0개** — 없음

## 확인 필요 (재배포 전에 판단할 것)

| 대상 | 사안 |
| --- | --- |
| `certifi`, `tqdm` (MPL-2.0) | MPL 은 **파일 단위** copyleft다. 우리는 두 패키지를 수정하지 않고 pip 로 설치해 쓰기만 하므로 소스 공개 의무가 발생하지 않는다. 벤더링(저장소에 복사)하는 순간 조건이 달라지니 하지 말 것. |
| `KPF/KPF-bert-ner` (HF 카드 메타데이터만 미선언) | **재배포 조건 자체는 확인됐다(2026-08-09).** HuggingFace 카드에 `license:` 필드가 없을 뿐이고, 이 모델을 배포하는 상류 프로젝트 저장소 두 곳이 모두 MIT 다 — [KPFBERT/kpfbert](https://github.com/KPFBERT/kpfbert)(base KPF-BERT, © 2021 KPFBERT) · [KPF-bigkinds/BIGKINDS-LAB](https://github.com/KPF-bigkinds/BIGKINDS-LAB)(`KPF-BERT-NER/` 하위, © 2022 빅카인즈랩). MIT 는 재배포·서브라이선스를 허용하므로 파생 가중치를 MIT 로 공개할 근거가 있으며, 조건인 **저작권 고지 유지**는 `townboy/kpfbert-ner` 의 `NOTICE` 가 두 건 다 담고 있다. 남은 것은 상류 HF 카드의 메타데이터 공백뿐이라 우리 쪽 조치 사항은 없다. |
| `Qwen/Qwen2.5-3B-Instruct` (STEP 4 sLLM 의 base) | **라이선스 원문 전수 확인함(2026-08-10).** `license: other` → 저장소 `LICENSE` 가 Qwen RESEARCH LICENSE AGREEMENT 다. Qwen2.5 계열에서 **0.5B·1.5B·7B·14B·32B 는 Apache-2.0**, **3B 와 72B 만** 이 라이선스다. 오해하기 쉬운 세 가지를 원문 기준으로 정리한다. **① 재배포는 금지가 아니다** — §3 이 파생물 배포를 명시적으로 허용한다(조건: §3.a 계약서 사본 동봉 · §3.b 수정 파일 명시 · §3.c NOTICE 저작권 문구 · §4.b 'Improved using Qwen' 표기). **② 우리 사용도 위반이 아니다** — §1.i 가 Non-Commercial 을 'research or evaluation purposes only' 로 정의하므로 연구·대회 평가 용도는 §2.a 의 허여 범위 안이다(상업적 이용은 §2.b 로 별도 계약 필요). **③ 대회 규정과도 충돌하지 않는다(규정집 원문 확인 2026-08-10)** — 제9조① 은 '최소한 가중치가 공개된 **오픈웨이트 모델 이상**의 공개 수준'만 요구하고 오픈소스 AI(OSAID)는 '권장하나 의무로 강제하지 않는다'고 못박는다. [별표2] 의 오픈웨이트 대표 모델 목록에 **Qwen 이 이름으로 올라 있다**(LLaMA·Mistral·Qwen·Gemma·SOLAR). 가중치에 대한 의무는 제9조②-2-나 '기반 모델의 라이선스 정책을 **최우선으로 준수하여 공개**' 이지 OSI 인증이 아니다 — **OSI 의무는 참가팀이 직접 작성한 코드에만** 붙는다(제8조① · 제9조②-2-다). [별표2] 가 경계하라는 것도 '**재배포 및 수정본 공개 금지**' 인데 §3 은 그 반대다. **→ 재학습 불필요.** **④ GGUF 저장소 표기 결함 2건은 2026-08-12 에 해소됐다(2026-08-17 HF 저장소 직접 조회로 재확인).** 한동안 `bbanany/qwen25-3b-korean-pii-gguf` 는 (ㄱ) 카드에 `license: apache-2.0` 을 선언해 **우리가 갖지 않은 상업적 이용 권리를 넘기고**(§3.d 는 수정분에 다른 조건을 붙이는 것을 '전체가 이 계약을 계속 준수하는 한'으로만 허용한다), (ㄴ) `LICENSE`·`NOTICE`·'Improved using Qwen' 이 없어 §3.a·§3.c·§4.b 를 못 채웠다 — 제9조②-2-나·제8조⑤⑥ 에 걸리는 상태였다. **현재 갱신본은 셋 다 갖췄다**: `license: other`+`license_name: qwen-research-license`+`license_link` · `LICENSE` 7,442B · `NOTICE` 378B · 카드 본문 'Improved using Qwen.'. 상류 `-qlora3` 도 동일하다. **→ 이 항목에 남은 우리 쪽 조치는 없다.** 이력을 지우지 않고 남기는 이유는 이 파일이 규정 증빙 원자료라 '언제 무엇을 확인했는가'가 근거이기 때문이다. |
| 대회 규정 제9조④ (**미이행**) | 'AI 모델을 탑재하거나 적용한 경우, 참가자는 **모델 정보를 포함하여 지정된 서식에 따라** 관련 내용을 작성하여 출품작과 함께 제출해야 한다.' 우리는 NER(`townboy/kpfbert-ner`)·sLLM(`bbanany/qwen25-3b-korean-pii-gguf`)·임베딩·리랭커 4종을 탑재하고 있다. 서식은 해당 연도 모집 공고에 붙으므로 **공고에서 서식을 받아 채워야 한다** — 이 파일이 그 원자료다. |
| KDPII 데이터셋 | 재배포 제약이 있어 저장소에 포함하지 않는다. 자체 합성 데이터셋으로 대체하는 작업이 진행 중이다. |

## 모델 가중치

| 모델 | 출처 | 라이선스 | 비고 |
| --- | --- | --- | --- |
| `dragonkue/BGE-m3-ko` | HuggingFace | Apache-2.0 | 문서/질의 임베딩. 재배포 제약 없음 |
| `dragonkue/bge-reranker-v2-m3-ko` | HuggingFace | Apache-2.0 | reranker_on 프로파일. 재배포 제약 없음 |
| `townboy/kpfbert-ner` | HuggingFace | MIT | STEP 3 한국어 PII NER (개인정보 33종). 저장소에 `LICENSE`(MIT) + `NOTICE`(상류 저작권 고지 2건) 포함. 상류가 MIT 라 이 선언에 근거가 있다 — 위 '확인 필요' 참조 |
| `KPF/KPF-bert-ner` | HuggingFace | MIT (상류 저장소 기준) | 위 모델의 base. HF 카드에는 `license:` 필드가 없으나 배포 주체의 GitHub 저장소가 MIT — 위 '확인 필요' 참조 |
| `bbanany/qwen25-3b-korean-pii-gguf` | HuggingFace | Qwen Research License (정확히 표기됨) | STEP 4 교차검증용 로컬 sLLM(Ollama `korean-pii`). 모델 자체는 대회 제9조① '오픈웨이트 이상' 요건을 충족한다. base 인 `Qwen/Qwen2.5-3B-Instruct` 의 조건이 함께 적용되며, `LICENSE`+`NOTICE`+'Improved using Qwen' 표기를 모두 갖춰 재배포 조건(§3·§4.b)을 충족한다 — 2026-08-12 갱신본 기준, 위 '확인 필요' 참조 |
| `bbanany/qwen25-3b-korean-pii-qlora3` | HuggingFace | Qwen Research License (정확히 표기됨) | 위 GGUF 의 상류 어댑터(FP16 병합본). `LICENSE`+`NOTICE`+'Improved using Qwen' 표기를 모두 갖춰 재배포 조건(§3·§4.b)을 충족한다 — GGUF 저장소가 따라야 할 기준 |
| `Qwen/Qwen2.5-3B-Instruct` | HuggingFace | Qwen Research License (비OSI · 비상업 — 대회는 허용) | 위 sLLM 의 base. Qwen2.5 계열에서 0.5B·1.5B·7B·14B·32B 는 Apache-2.0 이고 **3B 와 72B 만** 이 라이선스다(2026-08-10 카드 전수 확인). 대회 [별표2] 가 Qwen 을 오픈웨이트 대표 모델로 명시하므로 비OSI 라도 제9조① 은 충족 |

## 데이터셋

| 데이터셋 | 출처 | 라이선스 | 비고 |
| --- | --- | --- | --- |
| `townboy/korean-pii-dataset` | HuggingFace | CC-BY-4.0 | STEP 3 NER 학습셋(전량 합성, 11,732문서·33종). 저장소에 `LICENSE` 포함. 출처 표기만 하면 상업적 이용까지 허용 |
| `bbanany/korean-pii-candidate-classification` | HuggingFace | other / all-rights-reserved (저장소 `LICENSE` 원문 기준) | STEP 4 sLLM(`-qlora3` → GGUF) 파인튜닝셋. 전량 합성, 19,842건(train 15,875 / valid 1,984 / test 1,983 · 후보 태그 23종 · PII/NOT_PII 이진). 비OSI 지만 **제8조⑤⑥ 은 데이터셋 공개를 의무화하지 않고 출처·라이선스 명시만 요구**하므로 이 표기로 요건을 충족한다(가중치 의무는 제9조②-2-나 로 별개). 재배포·상업적 이용에는 저작권자 서면 허가가 필요하다 |
| `KDPII` | 외부 제공 | 재배포 제약 | 연구 목적 한정·외부 배포 금지. 저장소에 포함하지 않으며 벤치마크(`rag pii-eval`) 실행 시 사용자가 직접 준비한다. 자체 데이터셋으로 대체 예정 |
| `data/documents/**` | 본 저장소 | MIT (본 저장소와 동일) | `scripts/generate_dataset.py` 로 생성한 전량 합성 데이터. 실제 개인정보 0건 |

## 파이썬 의존성

`pyproject.toml` 의 직접 의존성에서 출발한 의존 폐포입니다(선택적 extra 제외).

| 패키지 | 버전 | 라이선스 |
| --- | --- | --- |
| `absl-py` | 2.4.0 | Apache-2.0 |
| `annotated-doc` | 0.0.4 | MIT |
| `annotated-types` | 0.7.0 | MIT License |
| `anyio` | 4.13.0 | MIT |
| `attrs` | 26.1.0 | MIT |
| `backoff` | 2.2.1 | MIT |
| `certifi` | 2026.1.4 | MPL-2.0 |
| `charset-normalizer` | 3.4.4 | MIT |
| `click` | 8.3.2 | BSD-3-Clause |
| `defusedxml` | 0.7.1 | PSFL |
| `distro` | 1.9.0 | Apache License, Version 2.0 |
| `docling` | 2.95.0 | MIT |
| `docling-core` | 2.77.0 | MIT |
| `docling-haystack` | 1.0.0 | Apache-2.0 |
| `docling-slim` | 2.95.0 | MIT |
| `docstring_parser` | 0.17.0 | MIT |
| `faiss-cpu` | 1.13.2 | MIT AND BSD-3-Clause |
| `filelock` | 3.25.2 | MIT |
| `filetype` | 1.2.0 | MIT |
| `fsspec` | 2026.3.0 | BSD-3-Clause |
| `h11` | 0.16.0 | MIT |
| `haystack-ai` | 2.27.0 | Apache-2.0 |
| `haystack-experimental` | 0.19.0 | Apache-2.0 |
| `hf-xet` | 1.4.3 | Apache-2.0 |
| `httpcore` | 1.0.9 | BSD-3-Clause |
| `httpx` | 0.28.1 | BSD-3-Clause |
| `huggingface_hub` | 1.10.1 | Apache-2.0 |
| `idna` | 3.11 | BSD-3-Clause |
| `Jinja2` | 3.1.6 | BSD License |
| `jiter` | 0.14.0 | MIT |
| `joblib` | 1.5.3 | BSD-3-Clause |
| `jsonref` | 1.1.0 | MIT |
| `jsonschema` | 4.26.0 | MIT |
| `jsonschema-specifications` | 2025.9.1 | MIT |
| `latex2mathml` | 3.81.0 | MIT |
| `lazy_imports` | 1.2.0 | Apache-2.0 |
| `loguru` | 0.7.3 | MIT License |
| `lxml` | 6.1.1 | BSD-3-Clause |
| `markdown-it-py` | 4.0.0 | MIT License |
| `MarkupSafe` | 3.0.3 | BSD-3-Clause |
| `mdurl` | 0.1.2 | MIT License |
| `more-itertools` | 11.0.2 | MIT |
| `mpmath` | 1.3.0 | BSD |
| `networkx` | 3.6.1 | BSD-3-Clause |
| `nltk` | 3.9.4 | Apache License, Version 2.0 |
| `numpy` | 2.4.4 | BSD-3-Clause AND 0BSD AND MIT AND Zlib AND CC0-1.0 |
| `openai` | 2.31.0 | Apache-2.0 |
| `packaging` | 26.0 | Apache-2.0 OR BSD-2-Clause |
| `pandas` | 3.0.3 | BSD License |
| `pillow` | 12.2.0 | MIT-CMU |
| `pluggy` | 1.6.0 | MIT |
| `posthog` | 7.11.0 | MIT |
| `pydantic` | 2.13.0 | MIT |
| `pydantic-settings` | 2.14.1 | MIT |
| `pydantic_core` | 2.46.0 | MIT |
| `Pygments` | 2.20.0 | BSD-2-Clause |
| `pypdf` | 6.10.0 | BSD-3-Clause |
| `python-dateutil` | 2.9.0.post0 | Dual License |
| `python-dotenv` | 1.2.2 | BSD-3-Clause |
| `PyYAML` | 6.0.3 | MIT |
| `referencing` | 0.37.0 | MIT |
| `regex` | 2026.4.4 | Apache-2.0 AND CNRI-Python |
| `reportlab` | 4.5.1 | BSD license (see license.txt for details), Copyright (c) 2000-2025, ReportLab Inc. |
| `requests` | 2.32.5 | Apache-2.0 |
| `rich` | 15.0.0 | MIT |
| `rouge_score` | 0.1.2 | Apache Software License |
| `rpds-py` | 0.30.0 | MIT |
| `safetensors` | 0.7.0 | Apache Software License |
| `scikit-learn` | 1.8.0 | BSD-3-Clause |
| `scipy` | 1.17.1 | BSD License |
| `sentence-transformers` | 5.4.0 | Apache 2.0 |
| `setuptools` | 81.0.0 | MIT |
| `shellingham` | 1.5.4 | ISC License |
| `six` | 1.17.0 | MIT |
| `sniffio` | 1.3.1 | MIT OR Apache-2.0 |
| `sympy` | 1.14.0 | BSD |
| `tabulate` | 0.10.0 | MIT |
| `tenacity` | 9.1.4 | Apache 2.0 |
| `threadpoolctl` | 3.6.0 | BSD-3-Clause |
| `tokenizers` | 0.22.2 | Apache Software License |
| `torch` | 2.12.0 | BSD-3-Clause |
| `tqdm` | 4.67.3 | MPL-2.0 AND MIT |
| `transformers` | 5.5.3 | Apache 2.0 License |
| `typer` | 0.21.2 | MIT |
| `typing-inspection` | 0.4.2 | MIT |
| `typing_extensions` | 4.15.0 | PSF-2.0 |
| `urllib3` | 2.6.3 | MIT |

### 이 환경에 설치되지 않아 확인하지 못한 항목

플랫폼 조건부 의존성(Windows 전용·CUDA 전용 등)이라 macOS/CPU 환경에서는 설치되지
않습니다. 해당 플랫폼에서 다시 돌리면 표에 채워집니다.

`aiocontextvars`, `colorama`, `cuda-bindings`, `cuda-toolkit`, `exceptiongroup`, `importlib-metadata`, `nvidia-cublas`, `nvidia-cudnn-cu13`, `nvidia-cusparselt-cu13`, `nvidia-nccl-cu13`, `nvidia-nvshmem-cu13`, `triton`, `tzdata`, `win32-setctime`
