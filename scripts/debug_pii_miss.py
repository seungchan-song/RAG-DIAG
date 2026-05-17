"""
PII 미탐 재현 스크립트.

실험 결과 JSON에서 특정 키워드(기본 "마루") 가 포함된 응답을 모아
4단계 PII 탐지 파이프라인을 단계별로 다시 실행하면서 후보가 어디서
사라지는지 추적한다.

확인하려는 가설:
  H1) 응답이 길어서 KPF-BERT 입력 한계(512 토큰)를 초과 → 추론 실패로 NER 0건
  H2) truncation=True 로 첫 512 토큰만 보낼 때 키워드가 PER 로 잡히는가?
  H3) 잡힌다면 raw confidence 가 임계값(0.8) 미만이라 조용히 버려지는가?

각 응답에 대해 다음을 출력한다:
  - 응답 길이(문자/토큰), 토큰 한계 초과 여부
  - Step 1 정규식 결과 / Step 2 체크섬 결과
  - Step 3 (현재 코드 그대로 호출) load_status, error, match_count
  - Step 3-raw (truncation 강제, 임계값 무관 전체 raw 출력)
      - PER 후보 전수, 키워드 부근 토큰의 score
  - 저장된 pii_findings 및 pii_runtime_status.step3 (대조용)

사용:
  python scripts/debug_pii_miss.py
  python scripts/debug_pii_miss.py --run RAG-2026-0516-009 --keyword 마루 --limit 5
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from loguru import logger
from rich.console import Console
from rich.table import Table

from rag.pii.step1_regex import RegexDetector
from rag.pii.step2_checksum import ChecksumValidator
from rag.pii.step3_ner import NERDetector
from rag.utils.config import load_config

console = Console()

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RESULT_DIR = PROJECT_ROOT / "data" / "results"
SCENARIOS = ["NORMAL", "R2", "R4", "R7", "R9"]


def latest_run_dir(results_root: Path) -> Path:
  """data/results 하위에서 가장 최근에 수정된 실행 디렉토리를 고른다."""
  candidates = [p for p in results_root.iterdir() if p.is_dir() and not p.name.startswith(".")]
  if not candidates:
    raise FileNotFoundError(f"실행 디렉토리가 비어 있습니다: {results_root}")
  return max(candidates, key=lambda p: p.stat().st_mtime)


def collect_hits(run_dir: Path, keyword: str) -> list[dict[str, Any]]:
  """run_dir 내 모든 시나리오 결과에서 keyword 가 포함된 응답을 추출한다."""
  hits: list[dict[str, Any]] = []
  for scenario in SCENARIOS:
    path = run_dir / f"{scenario}_result.json"
    if not path.exists():
      continue
    data = json.loads(path.read_text(encoding="utf-8"))
    for r in data.get("results", []):
      response_masked = str(r.get("response_masked") or "")
      response_raw = str(r.get("response") or "")
      combined = f"{response_masked}\n{response_raw}"
      if keyword in combined:
        hits.append(
          {
            "scenario": scenario,
            "query_id": r.get("query_id"),
            "response": response_raw or response_masked,
            "response_masked": response_masked,
            "pii_findings": r.get("pii_findings", []),
            "pii_runtime_status": r.get("pii_runtime_status", {}),
          }
        )
  return hits


def run_step3_raw(
  text: str,
  model_id: str,
  keyword: str,
  hard_max_len: int = 512,
) -> dict[str, Any]:
  """
  토크나이저로 입력 길이를 측정하고 max_length=512 자동 truncation 으로 다시
  추론하여 임계값(0.8) 을 적용하기 전 raw 결과를 돌려준다.

  - KPF-BERT 토크나이저의 model_max_length 가 sentinel(~1e30) 인 경우가 있어
    실제 모델 한계(BERT-base = 512) 를 hard_max_len 으로 강제한다.
  - TokenClassificationPipeline 은 호출 시 truncation 키워드를 직접 받지
    않으므로, 토크나이저의 model_max_length 자체를 덮어써서 자동 truncation
    을 유도한다.
  """
  from transformers import AutoTokenizer
  from transformers import pipeline as hf_pipeline

  tokenizer = AutoTokenizer.from_pretrained(model_id)

  tokenizer_max_len = int(getattr(tokenizer, "model_max_length", 0) or 0)
  effective_max_len = hard_max_len if tokenizer_max_len > 100000 else min(
    tokenizer_max_len or hard_max_len, hard_max_len
  )

  encoded_full = tokenizer(text, add_special_tokens=True)["input_ids"]
  token_count = len(encoded_full)
  exceeds = token_count > effective_max_len

  info: dict[str, Any] = {
    "token_count": token_count,
    "tokenizer_model_max_length_raw": tokenizer_max_len,
    "max_len_effective": effective_max_len,
    "exceeds_limit": exceeds,
  }

  try:
    # 자동 truncation 유도: 토크나이저의 model_max_length 를 강제로 낮춘다.
    tokenizer.model_max_length = effective_max_len
    pipe = hf_pipeline(
      "token-classification",
      model=model_id,
      tokenizer=tokenizer,
      aggregation_strategy="simple",
      device=-1,
    )
    raw = pipe(text)
  except Exception as error:
    info["inference_error"] = str(error)
    return info

  per_entities = [e for e in raw if str(e.get("entity_group")) == "PER"]
  keyword_hits: list[dict[str, Any]] = []
  for e in raw:
    word = str(e.get("word") or "")
    start = int(e.get("start") or 0)
    end = int(e.get("end") or 0)
    snippet = text[max(0, start - 5) : end + 5]
    if keyword in word or keyword in snippet:
      keyword_hits.append(
        {
          "text": word,
          "tag": e.get("entity_group"),
          "score": round(float(e.get("score", 0.0)), 3),
          "start": start,
          "end": end,
          "snippet": snippet,
        }
      )

  info.update(
    {
      "raw_total": len(raw),
      "per_total": len(per_entities),
      "per_keyword_hits": keyword_hits,
      "per_samples": [
        {
          "text": e.get("word"),
          "score": round(float(e.get("score", 0.0)), 3),
          "start": e.get("start"),
          "end": e.get("end"),
        }
        for e in per_entities[:8]
      ],
    }
  )
  return info


def run_debug(text: str, config: dict[str, Any], keyword: str) -> dict[str, Any]:
  """단일 텍스트에 대해 Step 1~3 을 모두 실행하고 결과를 모은다."""
  out: dict[str, Any] = {"text_len_chars": len(text)}

  regex = RegexDetector()
  step1 = regex.detect(text)
  out["step1"] = {
    "count": len(step1),
    "tags": sorted({m.tag for m in step1}),
  }

  checksum = ChecksumValidator()
  step2 = checksum.filter_valid(step1)
  out["step2"] = {"count": len(step2)}

  ner = NERDetector(config)
  ner.warm_up()
  step3 = ner.detect(text)
  out["step3_current"] = {
    "load_status": ner.load_status,
    "error": ner.error_message,
    "threshold": ner.confidence_threshold,
    "match_count": len(step3),
    "tags": sorted({m.tag for m in step3}),
    "keyword_hits": [
      {"text": m.text, "tag": m.tag, "score": round(m.confidence, 3)}
      for m in step3
      if keyword in m.text
    ],
  }

  out["step3_raw"] = run_step3_raw(
    text=text,
    model_id=ner.resolved_model_identifier,
    keyword=keyword,
  )
  return out


def render_hit(index: int, hit: dict[str, Any], debug: dict[str, Any]) -> None:
  """한 응답의 디버그 결과를 콘솔에 표 형태로 출력한다."""
  console.rule(f"[{index}] {hit['scenario']} | {hit['query_id']}")
  table = Table(show_header=True, header_style="bold cyan")
  table.add_column("Stage", style="bold")
  table.add_column("Value")

  table.add_row("text_len_chars", str(debug["text_len_chars"]))
  table.add_row("step1.count", str(debug["step1"]["count"]))
  table.add_row("step1.tags", ", ".join(debug["step1"]["tags"]) or "-")
  table.add_row("step2.count", str(debug["step2"]["count"]))

  s3c = debug["step3_current"]
  status_color = "green" if s3c["load_status"] == "ready" else "red"
  table.add_row(
    "step3_current.load_status",
    f"[{status_color}]{s3c['load_status']}[/{status_color}]",
  )
  table.add_row("step3_current.threshold", str(s3c["threshold"]))
  if s3c["error"]:
    table.add_row("step3_current.error", s3c["error"][:160])
  table.add_row("step3_current.match_count", str(s3c["match_count"]))
  table.add_row(
    "step3_current.keyword_hits",
    json.dumps(s3c["keyword_hits"], ensure_ascii=False) or "[]",
  )

  s3r = debug["step3_raw"]
  exceeds = bool(s3r.get("exceeds_limit"))
  exceeds_color = "red" if exceeds else "green"
  table.add_row("step3_raw.token_count", str(s3r.get("token_count")))
  table.add_row(
    "step3_raw.tokenizer_model_max_length_raw",
    str(s3r.get("tokenizer_model_max_length_raw")),
  )
  table.add_row("step3_raw.max_len_effective", str(s3r.get("max_len_effective")))
  table.add_row(
    "step3_raw.exceeds_limit",
    f"[{exceeds_color}]{exceeds}[/{exceeds_color}]",
  )
  if "inference_error" in s3r:
    table.add_row("step3_raw.inference_error", s3r["inference_error"][:200])
  else:
    table.add_row("step3_raw.raw_total", str(s3r.get("raw_total")))
    table.add_row("step3_raw.per_total", str(s3r.get("per_total")))
    table.add_row(
      "step3_raw.per_keyword_hits",
      json.dumps(s3r.get("per_keyword_hits"), ensure_ascii=False) or "[]",
    )
    table.add_row(
      "step3_raw.per_samples",
      json.dumps(s3r.get("per_samples"), ensure_ascii=False) or "[]",
    )

  console.print(table)

  console.print("[dim]저장된 pii_findings (실험 결과 그대로):[/dim]")
  if hit["pii_findings"]:
    for f in hit["pii_findings"]:
      console.print(
        f"  - {f.get('tag')} | {f.get('source')} | {f.get('route')} | {f.get('masked_text')}"
      )
  else:
    console.print("  (없음)")

  saved_step3 = hit["pii_runtime_status"].get("step3", {})
  console.print("[dim]저장된 pii_runtime_status.step3:[/dim]")
  console.print(json.dumps(saved_step3, ensure_ascii=False, indent=2))


def summarize(debugs: list[dict[str, Any]]) -> None:
  """전체 응답에 대한 집계 통계를 콘솔에 찍는다."""
  if not debugs:
    return
  total = len(debugs)
  current_fail = sum(1 for d in debugs if d["step3_current"]["load_status"] != "ready")
  exceeds = sum(1 for d in debugs if d["step3_raw"].get("exceeds_limit"))
  per_found_after_truncate = sum(
    1 for d in debugs if d["step3_raw"].get("per_keyword_hits")
  )

  console.rule("[bold]요약")
  console.print(f"분석 응답 수: {total}")
  console.print(f"  현재 코드 Step3 실패 응답: {current_fail} / {total}")
  console.print(f"  토큰 한계(512) 초과 응답: {exceeds} / {total}")
  console.print(
    f"  truncation 적용 시 키워드 부근 PER 후보 발견: {per_found_after_truncate} / {total}"
  )


def main() -> None:
  parser = argparse.ArgumentParser(description="PII 미탐 재현 디버그 스크립트")
  parser.add_argument(
    "--run",
    default=None,
    help="실행 디렉토리명 (예: RAG-2026-0516-009). 생략 시 최근 디렉토리 사용.",
  )
  parser.add_argument(
    "--results-root",
    default=str(DEFAULT_RESULT_DIR),
    help="실험 결과 루트 경로",
  )
  parser.add_argument("--keyword", default="마루", help="추적할 미탐 키워드")
  parser.add_argument("--limit", type=int, default=5, help="분석할 응답 최대 개수")
  args = parser.parse_args()

  logger.remove()
  logger.add(lambda msg: None, level="WARNING")

  results_root = Path(args.results_root)
  run_dir = results_root / args.run if args.run else latest_run_dir(results_root)
  console.print(f"[bold]실행 디렉토리:[/bold] {run_dir.name}")

  hits = collect_hits(run_dir, args.keyword)
  console.print(f"[bold]{args.keyword}[/bold] 포함 응답: {len(hits)} 건")
  if not hits:
    console.print("키워드가 포함된 응답이 없습니다. --keyword 를 조정하세요.")
    return

  config = load_config()

  debugs: list[dict[str, Any]] = []
  for i, hit in enumerate(hits[: args.limit], start=1):
    text = hit["response_masked"] or hit["response"]
    debug = run_debug(text=text, config=config, keyword=args.keyword)
    debugs.append(debug)
    render_hit(i, hit, debug)

  summarize(debugs)


if __name__ == "__main__":
  main()
