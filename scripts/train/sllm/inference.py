# SPDX-License-Identifier: MIT
# Copyright (c) 2026 bbanany

"""Run bbanany/qwen25-3b-korean-pii-qlora3 on CUDA, MPS, or CPU."""

# ruff: noqa: E402

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any


os.environ.setdefault("PYTORCH_ENABLE_MPS_FALLBACK", "1")
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer


SYSTEM_PROMPT = (
    "당신은 문서 기반 RAG 검색 결과에서 지정된 candidate span이 특정 자연인에게 "
    "연결되는 정보인지 판정합니다. 같은 응답에는 고객·직원·학생 정보와 "
    "상품·시스템·법인·테스트 기준값이 함께 있을 수 있습니다. candidate.start/end가 "
    "가리키는 바로 그 출현이 자연인의 기록이면 PII, 비인적 업무 대상의 값이면 "
    "NOT_PII입니다. 반드시 PII 또는 NOT_PII 중 하나만 출력하세요."
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--model",
        default="bbanany/qwen25-3b-korean-pii-qlora3",
    )
    parser.add_argument("--input-json", type=Path)
    parser.add_argument("--answer")
    parser.add_argument("--candidate-text")
    parser.add_argument("--tag")
    parser.add_argument("--start", type=int)
    parser.add_argument("--end", type=int)
    parser.add_argument("--device", choices=("auto", "cuda", "mps", "cpu"), default="auto")
    parser.add_argument("--max-new-tokens", type=int, default=8)
    return parser.parse_args()


def choose_device(requested: str) -> str:
    if requested == "cuda":
        if not torch.cuda.is_available():
            raise RuntimeError("CUDA was requested but is unavailable")
        return "cuda"
    if requested == "mps":
        if not torch.backends.mps.is_available():
            raise RuntimeError("MPS was requested but is unavailable")
        return "mps"
    if requested == "cpu":
        return "cpu"
    if torch.cuda.is_available():
        return "cuda"
    if torch.backends.mps.is_available():
        return "mps"
    return "cpu"


def build_payload(args: argparse.Namespace) -> dict[str, Any]:
    if args.input_json:
        payload = json.loads(args.input_json.read_text(encoding="utf-8"))
    else:
        if args.answer is None or args.candidate_text is None or args.tag is None:
            raise ValueError(
                "Provide --input-json, or all of --answer, --candidate-text, and --tag"
            )
        start = args.start
        end = args.end
        if start is None:
            first = args.answer.find(args.candidate_text)
            last = args.answer.rfind(args.candidate_text)
            if first < 0:
                raise ValueError("candidate-text does not occur in answer")
            if first != last:
                raise ValueError(
                    "candidate-text occurs more than once; provide --start and --end"
                )
            start = first
            end = first + len(args.candidate_text)
        elif end is None:
            end = start + len(args.candidate_text)
        payload = {
            "answer": args.answer,
            "candidate": {
                "text": args.candidate_text,
                "tag": args.tag,
                "start": start,
                "end": end,
            },
        }

    try:
        answer = payload["answer"]
        candidate = payload["candidate"]
        candidate_text = candidate["text"]
        start = candidate["start"]
        end = candidate["end"]
        tag = candidate["tag"]
    except (KeyError, TypeError) as exc:
        raise ValueError("Input must contain answer and candidate fields") from exc
    if not isinstance(answer, str) or not isinstance(candidate_text, str):
        raise ValueError("answer and candidate.text must be strings")
    if not isinstance(tag, str) or not tag:
        raise ValueError("candidate.tag must be a non-empty string")
    if not isinstance(start, int) or not isinstance(end, int):
        raise ValueError("candidate.start/end must be integers")
    if not 0 <= start < end <= len(answer):
        raise ValueError("candidate offsets are outside answer")
    if answer[start:end] != candidate_text:
        raise ValueError(
            f"Offset mismatch: answer[{start}:{end}] is {answer[start:end]!r}, "
            f"not {candidate_text!r}"
        )
    return payload


def normalize_label(text: str) -> str:
    upper = text.strip().upper()
    if re.search(r"(?<![A-Z_])NOT_PII(?![A-Z_])", upper):
        return "NOT_PII"
    if re.search(r"(?<![A-Z_])PII(?![A-Z_])", upper):
        return "PII"
    return "INVALID"


def load_model(model_id: str, device: str) -> tuple[Any, Any]:
    tokenizer = AutoTokenizer.from_pretrained(model_id, use_fast=True)
    if tokenizer.pad_token_id is None:
        tokenizer.pad_token = tokenizer.eos_token
    if device in {"cuda", "mps"}:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float16,
            device_map={"": device if device == "mps" else 0},
            low_cpu_mem_usage=True,
            attn_implementation="sdpa",
        )
    else:
        model = AutoModelForCausalLM.from_pretrained(
            model_id,
            torch_dtype=torch.float32,
            low_cpu_mem_usage=True,
            attn_implementation="sdpa",
        ).to("cpu")
    model.eval()
    return model, tokenizer


def main() -> None:
    args = parse_args()
    payload = build_payload(args)
    device = choose_device(args.device)
    model, tokenizer = load_model(args.model, device)
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {
            "role": "user",
            "content": json.dumps(payload, ensure_ascii=False, separators=(",", ":")),
        },
    ]
    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
    )
    inputs = tokenizer(prompt, return_tensors="pt")
    inputs = {key: value.to(model.device) for key, value in inputs.items()}
    with torch.inference_mode():
        output = model.generate(
            **inputs,
            max_new_tokens=args.max_new_tokens,
            do_sample=False,
            use_cache=True,
            pad_token_id=tokenizer.pad_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )
    generated = output[:, inputs["input_ids"].shape[1] :]
    raw_output = tokenizer.batch_decode(
        generated,
        skip_special_tokens=True,
    )[0]
    result = {
        "label": normalize_label(raw_output),
        "raw_output": raw_output,
        "device": device,
        "model": args.model,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
