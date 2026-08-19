# KPF-BERT Korean PII NER training package

이 디렉터리는 `KPF/KPF-bert-ner`를 한국어 PII BIO 토큰 분류 모델로 파인튜닝하기 위한 재현 가능한 코드입니다. 코드에는 실제 개인정보, API 키, Hugging Face 토큰, 사용자 PC의 절대경로를 포함하지 않습니다.

## 구성

- `prepare_dataset.py`: 원문 JSONL의 문자 span을 KPF-BERT 토큰 BIO 라벨로 변환합니다.
- `train.py`: 고정된 `train/validation/test` split을 읽어 CUDA GPU에서 파인튜닝합니다.
- `requirements.txt`: Python 의존성
- `RUN_COMMAND.txt`: 설치·전처리·학습 명령
- `LICENSE`: 이 디렉터리의 직접 작성 코드에 적용하는 MIT 전문

## 입력 원문 형식

입력은 합성 데이터셋의 `corpus_all.jsonl`과 같은 형식이어야 합니다.

```json
{
  "id": 100,
  "source_text": "회원 이름은 합성예시이고 이메일은 example@example.com입니다.",
  "privacy_mask": [
    {"label": "NAME", "value": "합성예시", "start": 7, "end": 11},
    {"label": "EMAIL", "value": "example@example.com", "start": 21, "end": 40}
  ],
  "split": "train"
}
```

`start`는 0부터 시작하는 문자 위치이고 `end`는 exclusive입니다. 전처리기는 `source_text[start:end] == value`를 먼저 검증하며, 틀린 span이나 겹치는 span은 즉시 중단합니다.

## 학습 흐름

1. `prepare_dataset.py`로 원문·문자 span을 BIO JSONL로 변환합니다. 입력 길이는 기본 512 토큰이며, 길이를 넘는 행은 조용히 자르지 않고 오류로 알립니다.
2. `train.py`가 `train`으로만 가중치를 업데이트하고 `validation`의 micro-F1로 최고 체크포인트와 early stopping을 결정합니다.
3. `test` split은 학습 중 사용하지 않습니다. 최종 성능 평가는 별도의 독립 holdout에서 수행해야 합니다.
4. 출력 디렉터리에는 `model.safetensors`, tokenizer 파일, `label_map.json`, `training_config.json`, `training_history.json`, `best_validation_metrics.json`이 저장됩니다.

## 최종 모델 재현 설정

이 프로젝트의 최종 KPF-BERT 모델은 다음 원칙을 사용했습니다.

- 기반 모델: `KPF/KPF-bert-ner`
- PII 유형 33개, BIO 라벨 67개(`O` 포함)
- 최대 입력 길이 512
- effective batch size 32 (`batch_size=4`, `gradient_accumulation=8`)
- 일반 학습 후 한국 주민등록번호·외국인등록번호 counterfactual 보강 1 epoch(`5e-6`), 일반 라벨 안정화 1 epoch(`1e-6`)
- 최종 refinement는 표준 cross-entropy이며 class-weighted loss가 필수는 아닙니다.

실행 예시는 `RUN_COMMAND.txt`에 있습니다. 경로는 `<raw-corpus>`, `<work>` 같은 자리표시자로만 적어 운영체제에 맞게 바꿔야 합니다.

## 주의사항

- 학습 데이터가 합성 데이터라도 모델과 데이터셋의 실제 공개 라이선스·출처를 각각 확인해야 합니다.
- 이 디렉터리의 코드 라이선스는 MIT입니다. 기반 모델의 권리와 데이터셋 라이선스는 이 코드 라이선스와 별개입니다.
- 모델 가중치의 배포에는 `LICENSE`, `NOTICE`, 기반 모델의 저작권·라이선스 고지를 함께 유지해야 합니다.
- 512 토큰보다 긴 운영 응답은 겹치는 window로 나눠 추론한 뒤 원문 span을 병합해야 합니다.
- 주민등록번호·외국인등록번호·카드·계좌 등 구조적 PII는 NER만으로 확정하지 말고 정규식·체크섬 검증을 병행해야 합니다.
