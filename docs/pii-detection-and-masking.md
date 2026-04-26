# PII Detection and Masking

This document describes the current Step 1 to Step 4 PII pipeline and the storage policy used by `rag run` and `rag report`.

## Goals

- detect Korean PII with layered precision controls
- keep evaluation behavior intact during runtime
- persist masked-only artifacts by default
- make Step 3 and Step 4 runtime state visible in saved artifacts

## Pipeline

### Step 1: Regex detection

`src/rag/pii/step1_regex.py`

Used for structured PII such as:

- mobile numbers
- email addresses
- resident registration numbers
- card numbers
- passport numbers
- IP addresses
- addresses

### Step 2: Checksum and structural validation

`src/rag/pii/step2_checksum.py`

Used to reduce false positives for structured identifiers such as:

- resident registration numbers
- card numbers

### Step 3: Hugging Face NER

`src/rag/pii/step3_ner.py`

Default model:

- `townboy/kpfbert-kdpii`

Runtime policy:

- Hugging Face Hub is the default source
- if `pii.ner.model_path` points to an existing local path, that local path wins
- Step 3 writes `model_source`, `load_status`, `resolved_model_identifier`, and any load error into `pii_runtime_status.step3`

Possible `load_status` values:

- `ready`
- `failed`
- `skipped`
- `not_loaded`

### Step 4: sLLM verification

`src/rag/pii/step4_sllm.py`

Step 4 only reviews low-confidence Step 3 candidates.

Runtime policy:

- if `OPENAI_API_KEY` is present, Step 4 uses the configured OpenAI model
- if `OPENAI_API_KEY` is missing, Step 4 switches to `mock_conservative`
- if Step 3 is unavailable, Step 4 is skipped and records `step3_unavailable`

Saved fields under `pii_runtime_status.step4` include:

- `mode`
- `status`
- `reason`
- `candidate_count`
- `verified_count`
- `error`

## Confirmed PII Output

`src/rag/pii/detector.py` produces:

- `pii_summary`
- `pii_findings`
- `response_masked`
- `pii_runtime_status`

### `pii_summary`

Per response summary includes:

- `total`
- `by_tag`
- `by_route`
- `top3_tags`
- `high_risk_count`
- `high_risk_tags`
- `has_high_risk`

### `pii_findings`

Per finding output is storage-safe and does not include the raw matched text.

Each finding stores:

- `tag`
- `route`
- `source`
- `masked_text`
- `start`
- `end`
- `confidence`
- `high_risk`

## Masking Policy

`src/rag/pii/masker.py`

Masking is applied before saving run artifacts.

Examples:

- `QT_RRN` -> `900101-*******`
- `QT_CARD` -> `****-****-****-9012`
- `QT_MOBILE` -> `010-****-5678`
- `TMI_EMAIL` -> `h***@example.com`
- `PER` -> first character only, rest replaced

## Persisted Artifact Policy

`rag run` now sanitizes results after evaluation and before `save_result()`.

Default behavior from `config/default.yaml`:

- `report.persist_raw_response: false`
- `report.mask_raw_pii: true`

Saved result JSON behavior:

- `response` is the masked response
- `response_masked` is the masked response alias
- `masking_applied` is set
- raw response text is not written to disk by default

## Report Policy

`rag report` prefers stored `pii_summary`, `pii_findings`, and `pii_runtime_status`.

This matters because saved `response` text is already masked, so report generation should not depend on re-detecting PII from the saved response body.

Report outputs use:

- masked responses only
- tag counts and top tags from stored summaries
- high-risk response ratio
- Step 3 and Step 4 runtime usage status

## Expected Fallback Behavior

- Step 3 load failure does not terminate the run
- Step 4 disabled or unavailable does not terminate the run
- `mock_conservative` Step 4 remains explicit in stored runtime metadata
- legacy result artifacts without `pii_summary` still have limited fallback support in report generation

## KDPII Benchmark

The repository now includes a dedicated benchmark entrypoint:

```bash
rag pii-eval --dataset-path C:\path\to\local-kdpii.jsonl --mode full
rag pii-eval --dataset-path C:\path\to\local-kdpii.jsonl --all-modes
```

Expected JSONL schema:

- `sample_id`
- `text`
- `entities`
  - `start`
  - `end`
  - `label`

Benchmark policy:

- metric: exact span + normalized label exact match
- label schema: `kdpii-33-v1`
- modes:
  - `step1`
  - `step1_2`
  - `step1_2_3`
  - `full`
- artifacts:
  - `pii_eval_summary.json`
  - `pii_eval_by_tag.csv`
  - `pii_eval_errors.csv`
  - `snapshot.yaml`

Benchmark artifacts stay safe by default:

- raw dataset text is not copied into saved artifacts
- `pii_eval_errors.csv` stores masked snippets only
- unsupported labels fail fast with `label_normalization_error`
- Step 3 load failure and Step 4 fallback state are stored in the benchmark runtime status
