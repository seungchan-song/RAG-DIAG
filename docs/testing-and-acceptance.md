# Testing and Acceptance

This document tracks the acceptance checks for the current retrieval, dataset-scope,
PII-hardening implementation, and KDPII-style benchmark workflow.

## Core Test Commands

```bash
python -m compileall src tests
pytest tests -q
ruff check src tests
```

## Acceptance Scope

### Configuration and profiles

Must verify:

- `load_config(profile=...)` resolves `profiles` overlays
- `rag query --profile ...` and `rag run --profile ...` both use the resolved retrieval config
- snapshot and result artifacts store `profile_name` and `retrieval_config`

### Dataset scopes and indexes

Must verify:

- canonical `clean/` and `poisoned/` directories win over legacy layout when both exist
- legacy `general/`, `sensitive/`, and `attack/` remain compatible when canonical directories are absent
- `rag ingest --env poisoned` requires `--scenario R2|R4|R9`
- default `rag ingest` reuses a matching scoped index as a no-op
- `rag ingest --incremental` applies add/update changes without forcing a rebuild
- `rag ingest --incremental --sync-delete` removes deleted files from the index
- `rag ingest --rebuild` and `rag ingest --incremental` are mutually exclusive
- `rag query --env poisoned` requires `--scenario R2|R4|R9`
- clean indexes resolve to `clean/base/<profile>`
- poisoned indexes resolve to `poisoned/<scenario>/<profile>`
- index manifests store `source_state`, `last_ingest_delta`, and `last_ingest_mode`
- snapshot and result artifacts store `scenario_scope`, `dataset_scope`, and `index_manifest_ref`

### Retrieval controls

Must verify:

- retrieval flow is `retriever -> threshold -> reranker -> prompt`
- `similarity_threshold` can remove all documents without crashing the query path
- reranker ON/OFF runs can be paired by `scenario + environment_type + query_id`

### PII hardening

Must verify:

- persisted result JSON does not store raw response by default
- saved `response` and `response_masked` are masked values
- `pii_summary`, `pii_findings`, and `pii_runtime_status` are present
- Step 3 load failures do not abort a run
- missing `OPENAI_API_KEY` produces Step 4 `mock_conservative` runtime status

### PII benchmark

Must verify:

- `rag pii-eval --dataset-path ...` accepts a local KDPII-style JSONL file
- `rag pii-eval --all-modes` runs `step1`, `step1_2`, `step1_2_3`, and `full`
- exact span + normalized label exact match is used for Precision/Recall/F1
- unsupported gold or predicted labels fail with `label_normalization_error`
- `pii_eval_summary.json`, `pii_eval_by_tag.csv`, `pii_eval_errors.csv`, and `snapshot.yaml` are created
- benchmark artifacts are masked-safe and never store raw PII spans or full raw text
- Step 3 load failure is recorded in benchmark runtime status without aborting the run
- missing `OPENAI_API_KEY` records Step 4 `mock_conservative` in benchmark runtime status

### Reporting

Must verify:

- `rag report` uses stored PII summaries when available
- `report_summary.json`, `report_detail.csv`, and `report.pdf` use masked-only content
- clean vs poisoned comparison works on matched `query_id`
- reranker ON/OFF comparison works on matched `query_id`
- PII sections include:
  - top 3 tags
  - total tag counts
  - high-risk response ratio
  - Step 3 / Step 4 runtime usage status

## Current Automated Coverage

### `tests/test_pii.py`

Covers:

- Step 1 regex detection
- Step 2 checksum filtering
- masking rules
- Step 3 local-path preference
- Step 3 load failure status
- Step 4 `mock_conservative` mode
- artifact sanitization and masked-only persistence

### `tests/test_pii_eval.py`

Covers:

- `rag pii-eval` artifact generation
- single-mode exact-match metric calculation
- label mismatch accounting
- unknown-label normalization failures
- Step 3 load failure fallback during benchmarking
- Step 4 `mock_conservative` runtime status during benchmarking
- masked-only error CSV output

### `tests/test_report_utils.py`

Covers:

- config profile resolution
- experiment snapshot/result handling
- dataset scope metadata in reports
- clean vs poisoned pairing
- reranker ON/OFF pairing
- report generation using stored PII summaries

### `tests/test_attack_eval.py`

Covers:

- R2 evaluator behavior
- R4 evaluator behavior
- R9 evaluator behavior

## Manual Verification Checklist

Build the indexes:

```bash
rag ingest --path data/documents/ --env clean --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R2 --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R2 --profile reranker_off --incremental
rag ingest --path data/documents/ --env poisoned --scenario R2 --profile reranker_off --incremental --sync-delete
```

Run at least one pair for environment comparison:

```bash
rag run --scenario R2 --attacker A1 --env clean --profile reranker_off
rag run --scenario R2 --attacker A1 --env poisoned --profile reranker_off
```

Run at least one pair for reranker comparison:

```bash
rag run --scenario R2 --attacker A1 --env clean --profile reranker_off
rag run --scenario R2 --attacker A1 --env clean --profile reranker_on
```

Then generate a report:

```bash
rag report --run-id RAG-YYYY-MMDD-001
```

Run the benchmark:

```bash
rag pii-eval --dataset-path C:\path\to\local-kdpii.jsonl --all-modes
```

Check manually that:

- `snapshot.yaml` contains the expected `scenario_scope` and `dataset_scope`
- `*_result.json` contains masked `response`
- `*_result.json` contains `dataset_scope` and `index_manifest_ref`
- `manifest.json` contains `source_state`, `last_ingest_delta`, and `last_ingest_mode`
- `pii_runtime_status.step3.model_source` is `hub` or `local`
- `pii_runtime_status.step4.mode` is `api` or `mock_conservative`
- CSV rows contain masked response text only
- CSV rows contain dataset scope columns
- PDF summary contains both comparison sections and PII runtime status
- `pii_eval_summary.json` contains `label_schema_version`
- `pii_eval_errors.csv` does not include raw matched spans

## Acceptance Decision

The sprint is acceptable when:

- code, tests, and docs agree on the same runtime behavior
- canonical and legacy dataset selection behave deterministically
- retrieval controls materially affect saved traces
- PII runtime status is explicit instead of silently skipped
- persisted artifacts are masked-only by default
- KDPII benchmark metrics are reproducible from a local JSONL dataset
