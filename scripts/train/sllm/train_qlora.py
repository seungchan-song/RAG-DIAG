# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bbanany

"""QLoRA fine-tuning for Qwen2.5-3B-Instruct on the FINAL JSONL dataset.

Only the final assistant label contributes to the loss. System and user prompt
tokens are masked with -100.
"""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import math
import os
import random
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any, Mapping


RUNPOD_VOLUME = Path(os.environ.get("RUNPOD_VOLUME_PATH", "/workspace"))
os.environ.setdefault("HF_HOME", str(RUNPOD_VOLUME / "cache" / "huggingface"))
os.environ.setdefault(
    "HF_DATASETS_CACHE",
    str(RUNPOD_VOLUME / "cache" / "huggingface" / "datasets"),
)
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
# RunPod images can export this retired backend flag without installing
# hf_transfer. huggingface_hub will use its bundled hf_xet backend instead.
os.environ.pop("HF_HUB_ENABLE_HF_TRANSFER", None)

import torch
from datasets import Dataset
from peft import LoraConfig, get_peft_model, prepare_model_for_kbit_training
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    EarlyStoppingCallback,
    Trainer,
    TrainingArguments,
    set_seed,
)


HERE = Path(__file__).resolve().parent
LABELS = {"PII", "NOT_PII"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-name", default="Qwen/Qwen2.5-3B-Instruct")
    parser.add_argument(
        "--train-file",
        type=Path,
        default=HERE / "train.clean.jsonl",
    )
    parser.add_argument(
        "--valid-file",
        type=Path,
        default=HERE / "valid.clean.jsonl",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=RUNPOD_VOLUME / "outputs" / "final-mode-adapter",
    )
    parser.add_argument("--epochs", type=float, default=2.0)
    parser.add_argument("--learning-rate", type=float, default=1e-4)
    parser.add_argument("--max-length", type=int, default=512)
    parser.add_argument("--batch-size", type=int, default=8)
    parser.add_argument("--eval-batch-size", type=int, default=16)
    parser.add_argument("--gradient-accumulation-steps", type=int, default=2)
    parser.add_argument("--warmup-ratio", type=float, default=0.05)
    parser.add_argument("--logging-steps", type=int, default=10)
    parser.add_argument("--eval-steps", type=int, default=200)
    parser.add_argument("--save-steps", type=int, default=200)
    parser.add_argument("--save-total-limit", type=int, default=3)
    parser.add_argument("--early-stopping-patience", type=int, default=3)
    parser.add_argument("--lora-r", type=int, default=16)
    parser.add_argument("--lora-alpha", type=int, default=32)
    parser.add_argument("--lora-dropout", type=float, default=0.05)
    parser.add_argument("--seed", type=int, default=20260810)
    parser.add_argument("--num-workers", type=int, default=4)
    parser.add_argument(
        "--resume-from-checkpoint",
        default=None,
        help="Use 'auto' to resume from the newest checkpoint in output-dir.",
    )
    parser.add_argument(
        "--smoke-test",
        action="store_true",
        help="Train on 128 rows and validate on 64 rows.",
    )
    return parser.parse_args()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_number}: {exc}") from exc
            messages = row.get("messages")
            if not isinstance(messages, list) or len(messages) != 3:
                raise ValueError(f"Invalid messages at {path}:{line_number}")
            if tuple(message.get("role") for message in messages) != (
                "system",
                "user",
                "assistant",
            ):
                raise ValueError(f"Unexpected roles at {path}:{line_number}")
            label = messages[-1].get("content")
            if label not in LABELS:
                raise ValueError(
                    f"Unexpected assistant label {label!r} at {path}:{line_number}"
                )
            rows.append(row)
    if not rows:
        raise ValueError(f"No records found in {path}")
    return rows


def extract_input_ids(encoded: Any) -> list[int]:
    # transformers 4.x normally returns a list; newer releases can return a
    # BatchEncoding. Supporting both keeps data inspection forward-compatible.
    if isinstance(encoded, Mapping):
        encoded = encoded["input_ids"]
    if encoded and isinstance(encoded[0], list):
        if len(encoded) != 1:
            raise ValueError("Expected a single unbatched chat template")
        encoded = encoded[0]
    return list(encoded)


def apply_chat_template_ids(
    tokenizer: Any,
    messages: list[dict[str, str]],
    *,
    add_generation_prompt: bool,
) -> list[int]:
    encoded = tokenizer.apply_chat_template(
        messages,
        tokenize=True,
        add_generation_prompt=add_generation_prompt,
    )
    return extract_input_ids(encoded)


def encode_row(
    row: dict[str, Any],
    tokenizer: Any,
    max_length: int,
) -> dict[str, Any]:
    messages = row["messages"]
    prompt_ids = apply_chat_template_ids(
        tokenizer,
        messages[:-1],
        add_generation_prompt=True,
    )
    full_ids = apply_chat_template_ids(
        tokenizer,
        messages,
        add_generation_prompt=False,
    )
    if full_ids[: len(prompt_ids)] != prompt_ids:
        raise ValueError("Chat template prompt is not a prefix of the completed sample")

    target_ids = full_ids[len(prompt_ids) :]
    if not target_ids:
        raise ValueError("Assistant target produced no tokens")
    if len(target_ids) >= max_length:
        raise ValueError(
            f"Assistant target has {len(target_ids)} tokens, exceeding max_length"
        )

    truncated_tokens = max(0, len(full_ids) - max_length)
    if truncated_tokens:
        # Preserve the label and the most recent user context. The supplied
        # FINAL dataset is below 512 tokens, so this is a defensive fallback.
        prompt_budget = max_length - len(target_ids)
        prompt_ids = prompt_ids[-prompt_budget:]
    input_ids = prompt_ids + target_ids
    labels = [-100] * len(prompt_ids) + target_ids
    return {
        "input_ids": input_ids,
        "attention_mask": [1] * len(input_ids),
        "labels": labels,
        "original_length": len(full_ids),
        "truncated_tokens": truncated_tokens,
    }


@dataclass
class AssistantOnlyDataCollator:
    tokenizer: Any
    pad_to_multiple_of: int = 8

    def __call__(self, features: list[dict[str, Any]]) -> dict[str, torch.Tensor]:
        longest = max(len(feature["input_ids"]) for feature in features)
        padded_length = (
            math.ceil(longest / self.pad_to_multiple_of) * self.pad_to_multiple_of
        )
        input_ids: list[list[int]] = []
        attention_masks: list[list[int]] = []
        labels: list[list[int]] = []
        for feature in features:
            padding = padded_length - len(feature["input_ids"])
            input_ids.append(
                feature["input_ids"] + [self.tokenizer.pad_token_id] * padding
            )
            attention_masks.append(feature["attention_mask"] + [0] * padding)
            labels.append(feature["labels"] + [-100] * padding)
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention_masks, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
        }


def latest_checkpoint(output_dir: Path) -> str | None:
    checkpoints: list[tuple[int, Path]] = []
    for path in output_dir.glob("checkpoint-*"):
        try:
            checkpoints.append((int(path.name.rsplit("-", 1)[-1]), path))
        except ValueError:
            continue
    return str(max(checkpoints)[1]) if checkpoints else None


def json_default(value: Any) -> Any:
    if hasattr(value, "item"):
        return value.item()
    raise TypeError(f"Not JSON serializable: {type(value).__name__}")


def package_versions() -> dict[str, str]:
    result = {"torch": torch.__version__}
    for package in (
        "transformers",
        "datasets",
        "accelerate",
        "peft",
        "bitsandbytes",
        "huggingface_hub",
        "safetensors",
    ):
        try:
            result[package] = version(package)
        except PackageNotFoundError:
            result[package] = "not installed"
    return result


def main() -> None:
    args = parse_args()
    if not torch.cuda.is_available():
        raise RuntimeError("QLoRA training requires an NVIDIA CUDA GPU")

    set_seed(args.seed)
    random.seed(args.seed)
    args.output_dir.mkdir(parents=True, exist_ok=True)

    device_index = int(os.environ.get("LOCAL_RANK", "0"))
    torch.cuda.set_device(device_index)
    major, _minor = torch.cuda.get_device_capability(device_index)
    use_bf16 = bool(
        major >= 8
        and hasattr(torch.cuda, "is_bf16_supported")
        and torch.cuda.is_bf16_supported()
    )
    compute_dtype = torch.bfloat16 if use_bf16 else torch.float16
    print(f"GPU: {torch.cuda.get_device_name(device_index)}")
    print(f"QLoRA compute dtype: {compute_dtype}")
    print(
        "Batch: "
        f"micro={args.batch_size}, "
        f"accumulation={args.gradient_accumulation_steps}, "
        f"effective={args.batch_size * args.gradient_accumulation_steps}"
    )

    tokenizer = AutoTokenizer.from_pretrained(args.model_name, use_fast=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    tokenizer.padding_side = "right"

    train_rows = read_jsonl(args.train_file)
    valid_rows = read_jsonl(args.valid_file)
    if args.smoke_test:
        train_rows = train_rows[:128]
        valid_rows = valid_rows[:64]
        args.epochs = min(args.epochs, 1.0)
        args.eval_steps = min(args.eval_steps, 4)
        args.save_steps = min(args.save_steps, 4)

    def tokenize_row(row: dict[str, Any]) -> dict[str, Any]:
        return encode_row(row, tokenizer, args.max_length)

    train_dataset = Dataset.from_list(train_rows).map(
        tokenize_row,
        remove_columns=list(train_rows[0]),
        desc="Tokenizing train",
        num_proc=args.num_workers,
    )
    valid_dataset = Dataset.from_list(valid_rows).map(
        tokenize_row,
        remove_columns=list(valid_rows[0]),
        desc="Tokenizing validation",
        num_proc=args.num_workers,
    )
    train_lengths = train_dataset["original_length"]
    valid_lengths = valid_dataset["original_length"]
    train_truncated = sum(value > 0 for value in train_dataset["truncated_tokens"])
    valid_truncated = sum(value > 0 for value in valid_dataset["truncated_tokens"])
    print(
        f"Rows: train={len(train_dataset):,}, valid={len(valid_dataset):,}; "
        f"max tokens: train={max(train_lengths)}, valid={max(valid_lengths)}; "
        f"truncated: train={train_truncated}, valid={valid_truncated}"
    )
    train_dataset = train_dataset.remove_columns(
        ["original_length", "truncated_tokens"]
    )
    valid_dataset = valid_dataset.remove_columns(
        ["original_length", "truncated_tokens"]
    )

    quantization_config = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_use_double_quant=True,
        bnb_4bit_compute_dtype=compute_dtype,
    )
    model = AutoModelForCausalLM.from_pretrained(
        args.model_name,
        quantization_config=quantization_config,
        device_map={"": device_index},
        torch_dtype=compute_dtype,
        attn_implementation="sdpa",
    )
    model.config.use_cache = False
    model.config.pad_token_id = tokenizer.pad_token_id
    model = prepare_model_for_kbit_training(
        model,
        use_gradient_checkpointing=True,
    )
    model.gradient_checkpointing_enable(
        gradient_checkpointing_kwargs={"use_reentrant": False}
    )

    lora_config = LoraConfig(
        r=args.lora_r,
        lora_alpha=args.lora_alpha,
        lora_dropout=args.lora_dropout,
        bias="none",
        task_type="CAUSAL_LM",
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()

    training_args = TrainingArguments(
        output_dir=str(args.output_dir),
        num_train_epochs=args.epochs,
        learning_rate=args.learning_rate,
        lr_scheduler_type="cosine",
        warmup_ratio=args.warmup_ratio,
        weight_decay=0.0,
        per_device_train_batch_size=args.batch_size,
        per_device_eval_batch_size=args.eval_batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        gradient_checkpointing=True,
        gradient_checkpointing_kwargs={"use_reentrant": False},
        eval_strategy="steps",
        eval_steps=args.eval_steps,
        save_strategy="steps",
        save_steps=args.save_steps,
        logging_steps=args.logging_steps,
        save_total_limit=args.save_total_limit,
        load_best_model_at_end=True,
        metric_for_best_model="eval_loss",
        greater_is_better=False,
        optim="paged_adamw_8bit",
        max_grad_norm=0.3,
        bf16=use_bf16,
        fp16=not use_bf16,
        tf32=major >= 8,
        dataloader_num_workers=args.num_workers,
        remove_unused_columns=False,
        group_by_length=True,
        report_to=["tensorboard"],
        run_name="final-mode-qwen25-3b-qlora",
        seed=args.seed,
        data_seed=args.seed,
        push_to_hub=False,
    )
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=valid_dataset,
        data_collator=AssistantOnlyDataCollator(tokenizer),
        callbacks=[EarlyStoppingCallback(args.early_stopping_patience)],
    )

    resume = args.resume_from_checkpoint
    if resume == "auto":
        resume = latest_checkpoint(args.output_dir)
        print(f"Auto-resume checkpoint: {resume}")
    train_result = trainer.train(resume_from_checkpoint=resume)
    trainer.save_model(str(args.output_dir))
    trainer.save_state()
    tokenizer.save_pretrained(args.output_dir)
    metrics = trainer.evaluate()

    (args.output_dir / "final_eval_metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, indent=2, default=json_default) + "\n",
        encoding="utf-8",
    )
    summary = {
        "artifact_type": "peft_qlora_adapter",
        "base_model": args.model_name,
        "train_file": str(args.train_file),
        "valid_file": str(args.valid_file),
        "train_rows": len(train_dataset),
        "valid_rows": len(valid_dataset),
        "max_length": args.max_length,
        "max_observed_train_tokens": max(train_lengths),
        "max_observed_valid_tokens": max(valid_lengths),
        "train_rows_truncated": train_truncated,
        "valid_rows_truncated": valid_truncated,
        "epochs": args.epochs,
        "learning_rate": args.learning_rate,
        "per_device_train_batch_size": args.batch_size,
        "per_device_eval_batch_size": args.eval_batch_size,
        "gradient_accumulation_steps": args.gradient_accumulation_steps,
        "effective_batch_size": args.batch_size
        * args.gradient_accumulation_steps,
        "lora_r": args.lora_r,
        "lora_alpha": args.lora_alpha,
        "lora_dropout": args.lora_dropout,
        "best_checkpoint": trainer.state.best_model_checkpoint,
        "best_metric": trainer.state.best_metric,
        "gpu": torch.cuda.get_device_name(device_index),
        "compute_dtype": str(compute_dtype),
        "package_versions": package_versions(),
        "train_metrics": train_result.metrics,
        "eval_metrics": metrics,
    }
    (args.output_dir / "training_summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, default=json_default) + "\n",
        encoding="utf-8",
    )
    print(f"Final adapter: {args.output_dir}")


if __name__ == "__main__":
    main()
