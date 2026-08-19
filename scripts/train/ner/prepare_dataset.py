# SPDX-License-Identifier: MIT
# Copyright (c) 2026 townboy

"""Convert character-span Korean PII JSONL into KPF-BERT BIO JSONL.

Input rows use ``source_text`` and ``privacy_mask`` character offsets.  The
converter validates every span before tokenization and writes one combined BIO
file plus train/validation/test split files.
"""
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import json
from pathlib import Path

from transformers import AutoTokenizer


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def build_label_map(rows: list[dict]) -> dict:
    labels = sorted(
        {
            str(mask.get("label") or mask.get("tag"))
            for row in rows
            for mask in row.get("privacy_mask", [])
            if mask.get("label") or mask.get("tag")
        }
    )
    label2id = {"O": 0}
    for label in labels:
        label2id[f"B-{label}"] = len(label2id)
        label2id[f"I-{label}"] = len(label2id)
    return {"label2id": label2id, "id2label": {str(index): label for label, index in label2id.items()}}


def normalize_masks(row: dict) -> list[dict]:
    text = row.get("source_text", row.get("text"))
    if not isinstance(text, str):
        raise ValueError(f"row {row.get('id')} has no source_text/text")
    masks = []
    for mask in row.get("privacy_mask", row.get("entities", [])):
        label = mask.get("label") or mask.get("tag")
        value = mask.get("value", mask.get("text"))
        start, end = mask.get("start"), mask.get("end")
        if not label or not isinstance(value, str) or not isinstance(start, int) or not isinstance(end, int):
            raise ValueError(f"row {row.get('id')} contains an invalid privacy span: {mask}")
        if start < 0 or end <= start or end > len(text) or text[start:end] != value:
            raise ValueError(f"row {row.get('id')} has a span mismatch for {label}: {value!r}")
        masks.append({"label": str(label), "start": start, "end": end})
    masks.sort(key=lambda item: (item["start"], item["end"]))
    for left, right in zip(masks, masks[1:]):
        if left["end"] > right["start"]:
            raise ValueError(f"row {row.get('id')} contains overlapping spans")
    return masks


def encode_row(row: dict, tokenizer, label2id: dict[str, int], max_length: int) -> dict:
    text = row.get("source_text", row.get("text"))
    masks = normalize_masks(row)
    encoded = tokenizer(
        text,
        add_special_tokens=True,
        truncation=False,
        max_length=max_length,
        return_offsets_mapping=True,
    )
    if len(encoded["input_ids"]) > max_length:
        raise ValueError(f"row {row.get('id')} tokenizes to {len(encoded['input_ids'])} > max_length={max_length}")

    offsets = encoded.pop("offset_mapping")
    labels = [label2id["O"]] * len(offsets)
    for mask in masks:
        token_indexes = [
            index
            for index, (start, end) in enumerate(offsets)
            if end > start and min(end, mask["end"]) > max(start, mask["start"])
        ]
        if not token_indexes:
            raise ValueError(f"row {row.get('id')} span {mask} did not align to a token")
        for position, token_index in enumerate(token_indexes):
            prefix = "B" if position == 0 else "I"
            labels[token_index] = label2id[f"{prefix}-{mask['label']}"]

    # Special tokens have offset (0, 0) and must be ignored by the loss.
    labels = [-100 if end <= start else label for label, (start, end) in zip(labels, offsets)]
    result = {
        "id": row.get("id"),
        "split": row.get("split", "train"),
        "input_ids": encoded["input_ids"],
        "attention_mask": encoded["attention_mask"],
        "labels": labels,
    }
    if "token_type_ids" in encoded:
        result["token_type_ids"] = encoded["token_type_ids"]
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="Raw combined JSONL with character spans")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--tokenizer", default="KPF/KPF-bert-ner")
    parser.add_argument("--label-map", type=Path, default=None)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--local-files-only", action="store_true")
    return parser.parse_args()


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
    )


def main() -> None:
    args = parse_args()
    rows = read_jsonl(args.input)
    if not rows:
        raise ValueError("input JSONL is empty")
    label_data = (
        json.loads(args.label_map.read_text(encoding="utf-8"))
        if args.label_map
        else build_label_map(rows)
    )
    label2id = label_data["label2id"]
    tokenizer = AutoTokenizer.from_pretrained(
        args.tokenizer,
        use_fast=True,
        local_files_only=args.local_files_only,
    )
    encoded_rows = [encode_row(row, tokenizer, label2id, args.max_length) for row in rows]
    unknown_splits = sorted({row["split"] for row in encoded_rows} - {"train", "validation", "test"})
    if unknown_splits:
        raise ValueError(f"unsupported split values: {unknown_splits}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_jsonl(args.output_dir / "corpus_all_bio.jsonl", encoded_rows)
    for split in ("train", "validation", "test"):
        write_jsonl(args.output_dir / f"{split}.jsonl", [row for row in encoded_rows if row["split"] == split])
    (args.output_dir / "label_map.json").write_text(
        json.dumps(label_data, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    stats = {
        "source_file": args.input.name,
        "tokenizer": args.tokenizer,
        "max_length": args.max_length,
        "total_rows": len(encoded_rows),
        "rows_by_split": {split: sum(row["split"] == split for row in encoded_rows) for split in ("train", "validation", "test")},
        "bio_labels": len(label2id),
    }
    (args.output_dir / "bio_stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(stats, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
