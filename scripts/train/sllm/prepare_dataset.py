# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bbanany

"""Validate, deduplicate, and stratify the FINAL chat dataset.

The three source JSONL files are preserved. This script combines them, removes
exact duplicate records, and creates new train/validation/test splits that are
disjoint and stratified by (PII label, candidate tag).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SOURCE_FILES = ("train.jsonl", "valid.jsonl", "test.jsonl")
OUTPUT_FILES = {
    "train": "train.clean.jsonl",
    "valid": "valid.clean.jsonl",
    "test": "test.clean.jsonl",
}
EXPECTED_LABELS = {"PII", "NOT_PII"}
EXPECTED_ROLES = ("system", "user", "assistant")


@dataclass(frozen=True)
class Record:
    row: dict[str, Any]
    canonical: str
    digest: str
    label: str
    tag: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input-dir", type=Path, default=HERE)
    parser.add_argument("--output-dir", type=Path, default=HERE)
    parser.add_argument("--seed", type=int, default=20260810)
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--valid-ratio", type=float, default=0.1)
    parser.add_argument("--overwrite", action="store_true")
    return parser.parse_args()


def canonical_json(row: dict[str, Any]) -> str:
    return json.dumps(
        row,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def validate_row(row: Any, path: Path, line_number: int) -> Record:
    where = f"{path}:{line_number}"
    if not isinstance(row, dict) or set(row) != {"messages"}:
        raise ValueError(f"{where}: each row must contain only a messages field")
    messages = row["messages"]
    if not isinstance(messages, list) or len(messages) != 3:
        raise ValueError(f"{where}: messages must contain exactly three entries")
    roles = tuple(message.get("role") for message in messages)
    if roles != EXPECTED_ROLES:
        raise ValueError(f"{where}: expected roles {EXPECTED_ROLES}, got {roles}")
    if not all(isinstance(message.get("content"), str) for message in messages):
        raise ValueError(f"{where}: every message content must be a string")

    label = messages[-1]["content"].strip()
    if label not in EXPECTED_LABELS:
        raise ValueError(f"{where}: unexpected assistant label {label!r}")
    if messages[-1]["content"] != label:
        raise ValueError(f"{where}: assistant label has surrounding whitespace")

    try:
        payload = json.loads(messages[1]["content"])
        answer = payload["answer"]
        candidate = payload["candidate"]
        candidate_text = candidate["text"]
        tag = candidate["tag"]
        start = candidate["start"]
        end = candidate["end"]
    except (json.JSONDecodeError, KeyError, TypeError) as exc:
        raise ValueError(f"{where}: malformed user payload or candidate") from exc
    if not isinstance(answer, str) or not isinstance(candidate_text, str):
        raise ValueError(f"{where}: answer and candidate.text must be strings")
    if not isinstance(tag, str) or not tag:
        raise ValueError(f"{where}: candidate.tag must be a non-empty string")
    if not isinstance(start, int) or isinstance(start, bool):
        raise ValueError(f"{where}: candidate.start must be an integer")
    if not isinstance(end, int) or isinstance(end, bool):
        raise ValueError(f"{where}: candidate.end must be an integer")
    if not 0 <= start < end <= len(answer):
        raise ValueError(f"{where}: candidate offsets are outside the answer")
    actual = answer[start:end]
    if actual != candidate_text:
        raise ValueError(
            f"{where}: candidate offset mismatch; expected {candidate_text!r}, got {actual!r}"
        )

    canonical = canonical_json(row)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return Record(row=row, canonical=canonical, digest=digest, label=label, tag=tag)


def read_jsonl(path: Path) -> list[Record]:
    records: list[Record] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc}") from exc
            records.append(validate_row(row, path, line_number))
    if not records:
        raise ValueError(f"{path}: no records found")
    return records


def stable_bucket_seed(seed: int, tag: str, label: str) -> int:
    value = f"{seed}\0{tag}\0{label}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(value).digest()[:8], "big")


def split_bucket(
    records: list[Record],
    *,
    train_ratio: float,
    valid_ratio: float,
    seed: int,
) -> tuple[list[Record], list[Record], list[Record]]:
    shuffled = list(records)
    rng = random.Random(seed)
    rng.shuffle(shuffled)
    count = len(shuffled)
    test_ratio = 1.0 - train_ratio - valid_ratio
    valid_count = max(1, round(count * valid_ratio))
    test_count = max(1, round(count * test_ratio))
    if valid_count + test_count >= count:
        if count < 3:
            raise ValueError(
                "Each (label, tag) stratum needs at least three unique records; "
                f"found {count}."
            )
        valid_count = 1
        test_count = 1
    train_count = count - valid_count - test_count
    return (
        shuffled[:train_count],
        shuffled[train_count : train_count + valid_count],
        shuffled[train_count + valid_count :],
    )


def summarize(records: list[Record]) -> dict[str, Any]:
    label_counts = Counter(record.label for record in records)
    tag_counts = Counter(record.tag for record in records)
    strata_counts = Counter((record.tag, record.label) for record in records)
    return {
        "rows": len(records),
        "labels": dict(sorted(label_counts.items())),
        "tags": dict(sorted(tag_counts.items())),
        "strata": {
            tag: {
                label: strata_counts[(tag, label)]
                for label in sorted(EXPECTED_LABELS)
            }
            for tag in sorted(tag_counts)
        },
    }


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_jsonl(path: Path, records: list[Record]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(
                json.dumps(record.row, ensure_ascii=False, separators=(",", ":")) + "\n"
            )


def main() -> None:
    args = parse_args()
    if not 0.0 < args.train_ratio < 1.0:
        raise ValueError("--train-ratio must be between zero and one")
    if not 0.0 < args.valid_ratio < 1.0:
        raise ValueError("--valid-ratio must be between zero and one")
    if args.train_ratio + args.valid_ratio >= 1.0:
        raise ValueError("train and validation ratios must sum to less than one")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    output_paths = {
        split: args.output_dir / filename for split, filename in OUTPUT_FILES.items()
    }
    report_path = args.output_dir / "dataset_report.json"
    existing = [path for path in (*output_paths.values(), report_path) if path.exists()]
    if existing and not args.overwrite:
        names = ", ".join(str(path) for path in existing)
        raise FileExistsError(f"Output files already exist: {names}; use --overwrite")

    sources: dict[str, list[Record]] = {}
    source_digest_sets: dict[str, set[str]] = {}
    for filename in SOURCE_FILES:
        path = args.input_dir / filename
        if not path.exists():
            raise FileNotFoundError(path)
        records = read_jsonl(path)
        sources[filename] = records
        source_digest_sets[filename] = {record.digest for record in records}

    unique_by_digest: dict[str, Record] = {}
    for filename in SOURCE_FILES:
        for record in sources[filename]:
            unique_by_digest.setdefault(record.digest, record)
    unique_records = list(unique_by_digest.values())

    buckets: dict[tuple[str, str], list[Record]] = defaultdict(list)
    for record in unique_records:
        buckets[(record.tag, record.label)].append(record)

    clean: dict[str, list[Record]] = {"train": [], "valid": [], "test": []}
    for (tag, label), records in sorted(buckets.items()):
        train_rows, valid_rows, test_rows = split_bucket(
            records,
            train_ratio=args.train_ratio,
            valid_ratio=args.valid_ratio,
            seed=stable_bucket_seed(args.seed, tag, label),
        )
        clean["train"].extend(train_rows)
        clean["valid"].extend(valid_rows)
        clean["test"].extend(test_rows)

    for index, split in enumerate(("train", "valid", "test")):
        random.Random(args.seed + index).shuffle(clean[split])

    clean_sets = {
        split: {record.digest for record in records} for split, records in clean.items()
    }
    if clean_sets["train"] & clean_sets["valid"]:
        raise AssertionError("Clean train and validation splits overlap")
    if clean_sets["train"] & clean_sets["test"]:
        raise AssertionError("Clean train and test splits overlap")
    if clean_sets["valid"] & clean_sets["test"]:
        raise AssertionError("Clean validation and test splits overlap")
    if set().union(*clean_sets.values()) != set(unique_by_digest):
        raise AssertionError("Clean splits do not preserve all unique source records")

    for split, path in output_paths.items():
        write_jsonl(path, clean[split])

    source_pairs = (
        ("train.jsonl", "valid.jsonl"),
        ("train.jsonl", "test.jsonl"),
        ("valid.jsonl", "test.jsonl"),
    )
    total_source_rows = sum(len(records) for records in sources.values())
    report = {
        "schema_version": 1,
        "seed": args.seed,
        "split_ratios": {
            "train": args.train_ratio,
            "valid": args.valid_ratio,
            "test": 1.0 - args.train_ratio - args.valid_ratio,
        },
        "source": {
            "files": {
                filename: summarize(records)
                for filename, records in sources.items()
            },
            "total_rows": total_source_rows,
            "unique_rows": len(unique_records),
            "duplicate_rows_removed": total_source_rows - len(unique_records),
            "exact_cross_split_overlap": {
                f"{left}__{right}": len(
                    source_digest_sets[left] & source_digest_sets[right]
                )
                for left, right in source_pairs
            },
        },
        "clean": {
            "files": {
                OUTPUT_FILES[split]: {
                    **summarize(records),
                    "sha256": sha256_file(output_paths[split]),
                }
                for split, records in clean.items()
            },
            "total_rows": sum(len(records) for records in clean.values()),
            "pairwise_overlap": {
                "train__valid": len(clean_sets["train"] & clean_sets["valid"]),
                "train__test": len(clean_sets["train"] & clean_sets["test"]),
                "valid__test": len(clean_sets["valid"] & clean_sets["test"]),
            },
        },
    }
    report_path.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            {
                "source_rows": total_source_rows,
                "unique_rows": len(unique_records),
                "duplicates_removed": total_source_rows - len(unique_records),
                "clean_rows": {
                    split: len(records) for split, records in clean.items()
                },
                "report": str(report_path),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
