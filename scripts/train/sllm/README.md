# bbanany/qwen25-3b-korean-pii-qlora3 학습·추론 코드

이 폴더는 `Qwen/Qwen2.5-3B-Instruct`를 한국어 PII 이진 분류기(`PII`,
`NOT_PII`)로 QLoRA 미세조정할 때 사용한 실제 학습 코드와 데이터 정제
코드, 그리고 결과 모델의 추론 코드를 제출용으로 정리한 것입니다. 코드에는
Hugging Face Hub 업로드나 `push_to_hub` 동작이 없으며, 학습 결과는 지정한
로컬 경로에만 저장됩니다.

## 포함 파일

- `train_qlora.py`: 실제 QLoRA 학습 스크립트. assistant 응답 토큰만 loss에
  포함하며, 4-bit NF4 양자화와 LoRA를 사용합니다.
- `prepare_dataset.py`: 원본 JSONL 검증, SHA-256 기준 완전 중복 제거,
  `(candidate tag, label)` 층화 train/valid/test 재분할 스크립트입니다.
- `requirements.txt`: 원 학습 패키지의 Python 의존성 범위입니다.
- `RUN_COMMAND.txt`: 학습 실행 명령 한 줄입니다.
- `training_summary.json`: 실제 학습 환경·하이퍼파라미터·평가 손실 기록입니다.
- `dataset_report.json`: 실제 정제 결과와 split별 SHA-256 기록입니다.
- `SOURCE_SHA256SUMS.txt`: 라이선스 표기를 추가하기 전 원본 코드의 해시입니다.
- `inference.py`: 병합 가중치로 추론하는 스크립트입니다. CUDA / Apple MPS /
  CPU 에서 모두 동작하며, 학습과 달리 `bitsandbytes` 나 PEFT 가 필요 없습니다.
- `requirements-inference.txt`: 추론 전용 의존성입니다.
- `LICENSE`: OSI 인증 MIT License 전문입니다.

## 데이터 형식과 전처리

원본 `train.jsonl`, `valid.jsonl`, `test.jsonl`을 이 폴더에 둔 후 다음을
실행하면 `*.clean.jsonl`과 `dataset_report.json`이 생성됩니다.

```bash
python prepare_dataset.py --input-dir . --output-dir . --overwrite
```

각 JSONL 행은 아래 구조입니다. 별도의 자동 라벨 생성기는 보관된 학습
패키지에 없으며, 이 스크립트는 기존 `PII`/`NOT_PII` 라벨을 검증하고
중복 누수 없이 다시 분할합니다.

```json
{"messages":[{"role":"system","content":"..."},{"role":"user","content":"{\"answer\":\"...\",\"candidate\":{\"text\":\"...\",\"tag\":\"NAME\",\"start\":0,\"end\":3}}"},{"role":"assistant","content":"PII"}]}
```

## 설치 및 실행

NVIDIA CUDA GPU 환경에서 설치합니다. PyTorch는 사용할 CUDA 버전에 맞는
공식 wheel을 먼저 설치한 뒤 나머지 패키지를 설치하면 됩니다.

```bash
python -m pip install -r requirements.txt
```

실제 설정과 같은 학습 실행 한 줄:

```bash
python train_qlora.py --train-file ./train.clean.jsonl --valid-file ./valid.clean.jsonl --output-dir ./outputs/final-mode-adapter
```

기본 주요 설정은 2 epochs, learning rate `1e-4`, max length 512,
micro-batch 8, gradient accumulation 2, LoRA r 16/alpha 32/dropout 0.05,
seed 20260810입니다. 실제 실행 기록상 NVIDIA A40, bfloat16 환경에서
학습되었으며 best checkpoint는 step 200이었습니다.

## 라이선스

학습 코드와 전처리 코드는 [MIT License](LICENSE)로 제공됩니다.
