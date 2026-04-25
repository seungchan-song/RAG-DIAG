# K-RAG Security Review Harness

This repository evaluates Korean RAG systems with three attack scenarios:

- `R2`: retrieval-based sensitive content extraction
- `R4`: membership inference
- `R9`: indirect prompt injection

The current implementation also includes:

- `clean` and `poisoned` dataset separation
- scenario-scoped dataset selection with canonical and legacy compatibility
- retrieval profiles with `similarity_threshold` and `reranker` controls
- persistent FAISS indexes per environment, scenario scope, and profile
- shared query tracing across `rag query` and `rag run`
- checkpoint and resume support for long-running scenario batches
- safe-by-default persisted artifacts with PII masking
- KDPII-style exact-match PII benchmarking with masked-safe artifacts
- report generation with clean vs poisoned and reranker ON/OFF comparisons

## Quick Start

### 1. Install

```bash
pip install -e ".[dev]"
```

### 2. Configure environment

```bash
copy .env.example .env
```

Supported environment variables:

- `OPENAI_API_KEY`
- `RAG_CONFIG_PATH`
- `RAG_RESULTS_PATH`

### 3. Build persisted indexes

```bash
rag ingest --path data/documents/ --env clean --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off --incremental
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off --incremental --sync-delete
```

Recommended layout:

- `data/documents/clean/...`
- `data/documents/poisoned/...`
- The repository now includes canonical sample files under both directories.
- Legacy `general/sensitive/attack` files are still supported, but canonical directories win when both exist.

Persisted indexes are stored under:

- `data/indexes/clean/base/<profile>/`
- `data/indexes/poisoned/<scenario>/<profile>/`

Ingest lifecycle rules:

- default `rag ingest` is conservative and reuses a matching index as a no-op
- `--incremental` applies add/update changes to the existing matching index
- `--incremental --sync-delete` also removes files that disappeared from the dataset
- `--rebuild` discards and rebuilds the scoped index from scratch
- updated files are replaced by `doc_id`, which deletes all old chunks for that file before re-ingest

### 4. Run a manual query

```bash
rag query --question "Summarize the privacy policy requirements." --doc-path data/documents/ --env clean --profile default
rag query --question "What happens when the R9 trigger appears?" --doc-path data/documents/ --env poisoned --scenario R9 --profile reranker_on
```

`rag query` loads the persisted index for the inferred environment and auto-builds it once if missing.
When `--env poisoned` is used, `--scenario R2|R4|R9` is required so the query path resolves one deterministic poisoned index.
The interactive console output remains unchanged. The safe-by-default masking policy applies to persisted run artifacts and reports, not to the terminal response.

### 5. Run an attack scenario

```bash
rag run --scenario R2 --attacker A2 --env poisoned --profile reranker_off
rag run --scenario R4 --attacker A1 --env clean --profile default
rag run --scenario R9 --attacker A3 --env poisoned --profile reranker_on
rag run --scenario R2 --attacker A2 --env poisoned --profile reranker_off --resume RAG-2026-0425-001
```

During `rag run`, the harness writes:

- `snapshot.yaml` for the resolved config and index metadata
- `checkpoint.json` for resume metadata
- `R*_partial.json` for scenario-scoped partial results
- final `*_result.json` after recombining completed partial results

### 6. Generate a report

```bash
rag report --run-id RAG-2026-0425-001
```

### 7. Replay a saved run from `snapshot.yaml`

```bash
rag replay --run-id RAG-2026-0425-001
rag replay --run-id PII-EVAL-2026-0425-001
```

`rag replay` always creates a new run directory. It reuses the saved resolved config from
`snapshot.yaml`, writes `replay_audit.json`, and records `replayed_from_run_id`,
`compatibility_mode`, and normalized provenance fields in the new snapshot.

### 8. Run a KDPII-style PII benchmark

```bash
rag pii-eval --dataset-path C:\path\to\local-kdpii.jsonl --mode full
rag pii-eval --dataset-path C:\path\to\local-kdpii.jsonl --all-modes
```

`rag pii-eval` expects a local JSONL file with:

- `sample_id`
- `text`
- `entities`: list of `{start, end, label}`

The repository keeps only a tiny synthetic fixture under
`tests/fixtures/pii_eval_fixture.jsonl`. Real KDPII data should stay outside the repo.

## Retrieval Profiles

`config/default.yaml` defines base retrieval settings plus profile overlays:

- `default`
- `reranker_on`
- `reranker_off`

`load_config(profile=...)` resolves the selected profile and stores both `profile_name` and the resolved `retrieval_config` in snapshots and result JSON files.

## Persistent Indexes and Resume

Index manifests store:

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

`rag query` and `rag run` reuse an existing index when the manifest matches the current configuration.
If no index exists, they auto-build one once. If the manifest mismatches the current inputs, the command stops with an explicit rebuild message instead of silently replacing the index.

Resume behavior:

- `rag run --resume <run_id>` validates the saved scenario, attacker, environment, and profile
- completed `query_id` values are skipped
- failed or incomplete queries are retried
- final summaries are rebuilt from the saved partial results

## PII Hardening

Persisted run artifacts are masked by default.

- `response` in saved result JSON is the masked response
- `response_masked` stores the same masked text as an explicit alias
- `pii_summary`, `pii_findings`, and `pii_runtime_status` are stored per response
- raw response text stays in memory only during evaluation

The default Step 3 NER model is the Hugging Face token-classification model:

- [`townboy/kpfbert-kdpii`](https://huggingface.co/townboy/kpfbert-kdpii)

Step behavior:

1. Step 1: regex detection
2. Step 2: checksum / structural validation
3. Step 3: Hugging Face NER detection
4. Step 4: sLLM verification

Fallback behavior:

- If a local model path exists, Step 3 uses that local path first.
- If Step 3 model loading fails, the run continues with Step 1 and Step 2 only.
- If `OPENAI_API_KEY` is not set, Step 4 runs in `mock_conservative` mode and records that mode in the result artifact.

## Safe Result Artifacts

Each saved attack result now contains:

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

Each run directory also stores:

- `snapshot.yaml`
- `checkpoint.json`
- scenario-scoped partial result files such as `R2_partial.json`
- `index_manifest_ref` and dataset scope metadata inside the saved snapshot/result artifacts

## Reports

`rag report` produces `JSON`, `CSV`, and `PDF` artifacts under the run directory.

Report inputs are safe by default:

- masked responses only
- stored `pii_summary` and `pii_runtime_status` reused instead of re-reading raw responses
- clean vs poisoned comparison
- reranker ON/OFF comparison
- top PII tags and high-risk response rate

## Main Commands

- `rag ingest`
- `rag query`
- `rag run`
- `rag report`
- `rag replay`
- `rag pii-eval`

## Validation Commands

```bash
python -m compileall src tests
pytest tests -q
ruff check src tests
```

## Reference Docs

- [docs/pii-detection-and-masking.md](./docs/pii-detection-and-masking.md)
- [docs/testing-and-acceptance.md](./docs/testing-and-acceptance.md)
