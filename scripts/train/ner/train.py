# SPDX-License-Identifier: MIT
# Copyright (c) 2026 townboy

"""Fine-tune KPF-BERT for Korean PII BIO token classification.

The script intentionally accepts only relative/portable dataset arguments and
does not embed local machine paths, credentials, or example personal data.
"""
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import json
import math
import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

import torch
import torch.nn.functional as F
from torch.optim import AdamW
from torch.utils.data import DataLoader, Sampler
from transformers import (
    AutoConfig,
    AutoModelForTokenClassification,
    AutoTokenizer,
    get_linear_schedule_with_warmup,
)


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_splits(path: Path) -> dict[str, list[dict]]:
    """Load either a combined JSONL file or a directory of split JSONL files."""
    if path.is_dir():
        result = {}
        for split in ("train", "validation", "test"):
            split_path = path / f"{split}.jsonl"
            if not split_path.exists():
                raise FileNotFoundError(f"Missing split file: {split_path}")
            result[split] = read_jsonl(split_path)
        return result

    rows = read_jsonl(path)
    result = {split: [row for row in rows if row.get("split") == split] for split in ("train", "validation", "test")}
    missing = [split for split, values in result.items() if not values]
    if missing:
        raise ValueError(f"No rows found for split(s): {', '.join(missing)}")
    return result


def collate(rows: list[dict]) -> dict[str, torch.Tensor]:
    max_length = max(len(row["input_ids"]) for row in rows)

    def padded(key: str, padding: int) -> torch.Tensor:
        values = [row.get(key, [0] * len(row["input_ids"])) for row in rows]
        return torch.tensor(
            [value + [padding] * (max_length - len(value)) for value in values],
            dtype=torch.long,
        )

    return {
        "input_ids": padded("input_ids", 0),
        "attention_mask": padded("attention_mask", 0),
        "token_type_ids": padded("token_type_ids", 0),
        "labels": padded("labels", -100),
    }


class LengthBucketBatchSampler(Sampler[list[int]]):
    """Reduce padding while keeping deterministic, shuffled mini-batches."""

    def __init__(self, rows: list[dict], batch_size: int, seed: int, max_length: int) -> None:
        self.rows = rows
        self.batch_size = batch_size
        self.seed = seed
        self.max_length = max_length
        self.epoch = 0

    def set_epoch(self, epoch: int) -> None:
        self.epoch = epoch

    def __iter__(self) -> Iterable[list[int]]:
        rng = random.Random(self.seed + self.epoch)
        boundaries = [64, 128, 256, self.max_length]
        buckets: dict[int, list[int]] = {boundary: [] for boundary in boundaries}
        for index, row in enumerate(self.rows):
            length = len(row["input_ids"])
            if length > self.max_length:
                raise ValueError(f"row {row.get('id', index)} exceeds max_length={self.max_length}")
            boundary = next(boundary for boundary in boundaries if length <= boundary)
            buckets[boundary].append(index)

        batches: list[list[int]] = []
        for indexes in buckets.values():
            rng.shuffle(indexes)
            batches.extend(indexes[i : i + self.batch_size] for i in range(0, len(indexes), self.batch_size))
        rng.shuffle(batches)
        yield from batches

    def __len__(self) -> int:
        boundaries = [64, 128, 256, self.max_length]
        counts = Counter(
            next(boundary for boundary in boundaries if len(row["input_ids"]) <= boundary)
            for row in self.rows
        )
        return sum(math.ceil(count / self.batch_size) for count in counts.values())


def extract_entities(sequence: list[int], id2label: dict[int, str]) -> set[tuple[str, int, int]]:
    entities: set[tuple[str, int, int]] = set()
    active_type: str | None = None
    active_start = -1
    for index, label_id in enumerate(sequence + [-100]):
        label = id2label.get(label_id, "O") if label_id != -100 else "O"
        prefix, entity_type = label.split("-", 1) if "-" in label else ("O", "")
        if active_type is not None and not (prefix == "I" and entity_type == active_type):
            entities.add((active_type, active_start, index))
            active_type = None
        if prefix == "B" or (prefix == "I" and active_type is None):
            active_type = entity_type
            active_start = index
    return entities


@torch.no_grad()
def evaluate(model, loader, device: torch.device, id2label: dict[int, str]) -> dict:
    model.eval()
    counts: dict[str, Counter] = defaultdict(Counter)
    for batch in loader:
        labels = batch["labels"]
        model_inputs = {key: value.to(device) for key, value in batch.items() if key != "labels"}
        predictions = model(**model_inputs).logits.argmax(dim=-1).cpu()
        for predicted, expected in zip(predictions.tolist(), labels.tolist()):
            predicted = [value if gold != -100 else -100 for value, gold in zip(predicted, expected)]
            predicted_entities = extract_entities(predicted, id2label)
            expected_entities = extract_entities(expected, id2label)
            for entity in predicted_entities & expected_entities:
                counts[entity[0]]["tp"] += 1
            for entity in predicted_entities - expected_entities:
                counts[entity[0]]["fp"] += 1
            for entity in expected_entities - predicted_entities:
                counts[entity[0]]["fn"] += 1

    per_label = {}
    total = Counter()
    entity_types = sorted(label[2:] for label in id2label.values() if label.startswith("B-"))
    for entity_type in entity_types:
        values = counts[entity_type]
        tp, fp, fn = values["tp"], values["fp"], values["fn"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        per_label[entity_type] = {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp,
            "fp": fp,
            "fn": fn,
        }
        total.update(values)
    tp, fp, fn = total["tp"], total["fp"], total["fn"]
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"micro_precision": precision, "micro_recall": recall, "micro_f1": f1, "per_label": per_label}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True, help="Combined BIO JSONL or directory with train/validation/test JSONL")
    parser.add_argument("--label-map", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--model", default="KPF/KPF-bert-ner")
    parser.add_argument("--tokenizer", default=None)
    parser.add_argument("--epochs", type=int, default=3)
    parser.add_argument("--batch-size", type=int, default=4)
    parser.add_argument("--validation-batch-size", type=int, default=8)
    parser.add_argument("--gradient-accumulation", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=3e-5)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--patience", type=int, default=2)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--class-weighted", action="store_true")
    parser.add_argument("--no-amp", action="store_true", help="Disable CUDA mixed precision")
    parser.add_argument("--local-files-only", action="store_true")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA GPU is required for local KPF-BERT training")
    if args.gradient_accumulation < 1 or args.batch_size < 1:
        raise ValueError("batch size and gradient accumulation must be positive")

    random.seed(args.seed)
    torch.manual_seed(args.seed)
    torch.cuda.manual_seed_all(args.seed)
    torch.backends.cuda.matmul.allow_tf32 = True
    device = torch.device("cuda")
    use_amp = not args.no_amp

    splits = load_splits(args.data)
    label_data = json.loads(args.label_map.read_text(encoding="utf-8"))
    label2id = label_data["label2id"]
    id2label = {int(key): value for key, value in label_data["id2label"].items()}
    for split, rows in splits.items():
        if any(len(row["input_ids"]) > args.max_length for row in rows):
            raise ValueError(f"{split} contains a sequence longer than max_length={args.max_length}")

    sampler = LengthBucketBatchSampler(splits["train"], args.batch_size, args.seed, args.max_length)
    train_loader = DataLoader(splits["train"], batch_sampler=sampler, collate_fn=collate, pin_memory=True)
    validation_loader = DataLoader(
        splits["validation"],
        batch_size=args.validation_batch_size,
        shuffle=False,
        collate_fn=collate,
        pin_memory=True,
    )

    source_model = args.model
    tokenizer_name = args.tokenizer or args.model
    config_kwargs = {"num_labels": len(label2id), "label2id": label2id, "id2label": id2label}
    config = AutoConfig.from_pretrained(source_model, **config_kwargs, local_files_only=args.local_files_only)
    config.max_seq_len = args.max_length
    config.training_max_length = args.max_length
    model = AutoModelForTokenClassification.from_pretrained(
        source_model,
        config=config,
        ignore_mismatched_sizes=True,
        local_files_only=args.local_files_only,
    )
    model.gradient_checkpointing_enable()
    model.to(device)

    args.output.mkdir(parents=True, exist_ok=True)
    class_weights = None
    if args.class_weighted:
        token_counts = Counter(label for row in splits["train"] for label in row["labels"] if label != -100)
        non_o_counts = sorted(count for label, count in token_counts.items() if label != label2id["O"])
        reference = non_o_counts[len(non_o_counts) // 2] if non_o_counts else 1
        weights = [
            0.10 if label_id == label2id["O"] else min(6.0, max(0.25, math.sqrt(reference / token_counts.get(label_id, 1))))
            for label_id in range(len(label2id))
        ]
        class_weights = torch.tensor(weights, dtype=torch.float32, device=device)
        (args.output / "class_weights.json").write_text(
            json.dumps({id2label[index]: round(value, 6) for index, value in enumerate(weights)}, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )

    optimizer = AdamW(model.parameters(), lr=args.learning_rate, weight_decay=0.01)
    optimizer_steps_per_epoch = math.ceil(len(train_loader) / args.gradient_accumulation)
    total_steps = optimizer_steps_per_epoch * args.epochs
    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=max(1, int(total_steps * 0.1)),
        num_training_steps=total_steps,
    )
    scaler = torch.amp.GradScaler("cuda", enabled=use_amp)
    run_config = {
        "base_model": source_model,
        "tokenizer": tokenizer_name,
        "dataset_file": args.data.name if args.data.is_file() else args.data.name,
        "label_map_file": args.label_map.name,
        "output_dir": args.output.name,
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "validation_batch_size": args.validation_batch_size,
        "gradient_accumulation": args.gradient_accumulation,
        "effective_batch_size": args.batch_size * args.gradient_accumulation,
        "learning_rate": args.learning_rate,
        "max_length": args.max_length,
        "patience": args.patience,
        "seed": args.seed,
        "class_weighted": args.class_weighted,
        "mixed_precision": use_amp,
        "train_rows": len(splits["train"]),
        "validation_rows": len(splits["validation"]),
        "test_rows": len(splits["test"]),
        "optimizer_steps_per_epoch": optimizer_steps_per_epoch,
    }
    (args.output / "training_config.json").write_text(json.dumps(run_config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    history: list[dict] = []
    best_f1 = -1.0
    stale_epochs = 0
    for epoch in range(1, args.epochs + 1):
        sampler.set_epoch(epoch)
        model.train()
        optimizer.zero_grad(set_to_none=True)
        loss_sum = 0.0
        for step, batch in enumerate(train_loader, 1):
            batch = {key: value.to(device, non_blocking=True) for key, value in batch.items()}
            with torch.autocast(device_type="cuda", dtype=torch.float16, enabled=use_amp):
                if class_weights is None:
                    loss = model(**batch).loss
                else:
                    logits = model(**{key: value for key, value in batch.items() if key != "labels"}).logits
                    loss = F.cross_entropy(
                        logits.float().reshape(-1, len(label2id)),
                        batch["labels"].reshape(-1),
                        weight=class_weights,
                        ignore_index=-100,
                    )
            loss_sum += float(loss.item())
            scaler.scale(loss / args.gradient_accumulation).backward()
            if step % args.gradient_accumulation == 0 or step == len(train_loader):
                scaler.unscale_(optimizer)
                torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
                scaler.step(optimizer)
                scaler.update()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)

        metrics = evaluate(model, validation_loader, device, id2label)
        result = {
            "epoch": epoch,
            "train_loss": loss_sum / max(1, len(train_loader)),
            "peak_gpu_memory_mb": round(torch.cuda.max_memory_allocated() / 1024**2, 1),
            **metrics,
        }
        history.append(result)
        print(json.dumps({key: value for key, value in result.items() if key != "per_label"}, ensure_ascii=False), flush=True)
        if metrics["micro_f1"] > best_f1:
            best_f1 = metrics["micro_f1"]
            stale_epochs = 0
            model.save_pretrained(args.output)
            AutoTokenizer.from_pretrained(tokenizer_name, use_fast=True, local_files_only=args.local_files_only).save_pretrained(args.output)
            (args.output / "label_map.json").write_text(json.dumps(label_data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
            (args.output / "best_validation_metrics.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        else:
            stale_epochs += 1
            if stale_epochs >= args.patience:
                break

    (args.output / "training_history.json").write_text(json.dumps(history, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"best_validation_micro_f1": best_f1, "epochs_completed": len(history), "output": args.output.name}, ensure_ascii=False), flush=True)


if __name__ == "__main__":
    main()
