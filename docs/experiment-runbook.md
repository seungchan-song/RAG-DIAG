# Experiment Runbook

This document describes the canonical dataset layout and the runtime rules for
building indexes, running scenarios, and generating reports.

## Canonical dataset layout

```text
data/documents/
  clean/
    normal/
    sensitive/
  poisoned/
    normal/
    sensitive/
    attack/
      r2/
      r4/
      r9/
```

Rules:

- `clean` uses the shared `base` scenario scope.
- `poisoned` uses one explicit scenario scope: `R2`, `R4`, or `R9`.
- non-attack documents are shared across scenario scopes.
- attack documents are selected only when their `attack_type` matches the requested scenario.

Legacy compatibility:

- `general/`, `sensitive/`, and `attack/` are still supported.
- when canonical `clean/` or `poisoned/` directories exist, the canonical layout wins.

## Dataset metadata

Each ingested file is normalized into metadata with at least:

- `doc_id`
- `source`
- `version`
- `file_hash`
- `dataset_group`
- `environment_scope`
- `scenario_scope`
- `dataset_scope`
- `dataset_selection_mode`
- `doc_role`
- `attack_type`

Chunk metadata also includes:

- `chunk_id`
- `chunk_index`
- `keyword`
- `keywords`

## Index scopes

Persisted FAISS indexes are now scenario-aware:

- `clean/base/<profile>/`
- `poisoned/R2/<profile>/`
- `poisoned/R4/<profile>/`
- `poisoned/R9/<profile>/`

Each `manifest.json` stores:

- `environment_type`
- `scenario_scope`
- `dataset_scope`
- `dataset_selection_mode`
- `dataset_manifest_hash`
- `doc_selection_summary`
- `embedding_model`
- `profile_name`
- `file_hashes`
- `source_state`
- `last_ingest_delta`
- `last_ingest_mode`

## CLI rules

### Build indexes

```bash
rag ingest --path data/documents/ --env clean --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off --incremental
rag ingest --path data/documents/ --env poisoned --scenario R9 --profile reranker_off --incremental --sync-delete
```

Rules:

- `--env clean` always resolves to `scenario_scope=base`.
- `--env poisoned` requires `--scenario R2|R4|R9`.
- default `rag ingest` is safe-by-default and reuses a matching manifest without changing the index.
- use `--incremental` to apply added or updated files to the persisted index.
- use `--incremental --sync-delete` when you also want missing files removed from the index.
- use `--rebuild` when the scope/config changed or you intentionally want a fresh index.
- updated files are applied as file-level replace using stable `doc_id`.

### Run manual queries

```bash
rag query --question "Summarize the privacy policy." --doc-path data/documents/ --env clean --profile default
rag query --question "What does the trigger do?" --doc-path data/documents/ --env poisoned --scenario R9 --profile reranker_on
```

### Run attacks

```bash
rag run --scenario R2 --attacker A1 --env clean --profile reranker_off
rag run --scenario R9 --attacker A1 --env poisoned --profile reranker_on
rag run --all-scenarios --attacker A1 --all-envs --all-profiles
```

Suite behavior:

- clean child cells reuse `clean/base`
- poisoned child cells reuse `poisoned/<scenario>`

## Snapshots and reports

Single-run snapshots and saved results now keep:

- `scenario_scope`
- `dataset_scope`
- `dataset_selection_mode`
- `index_manifest_ref`

Reports reuse the saved result artifacts and surface dataset/index trace fields in:

- `report_summary.json`
- `report_detail.csv`
- `report.pdf`

## Operator checklist

Before running:

- confirm the dataset is synthetic
- confirm canonical `clean/` and `poisoned/` directories are correct
- choose the intended `profile`
- choose the intended poisoned `scenario` when applicable

After running:

- verify the expected `dataset_scope` in `snapshot.yaml`
- verify the expected `index_manifest_ref` in `*_result.json`
- verify `last_ingest_mode` and `last_ingest_delta` in `manifest.json`
- verify reports contain masked responses only
