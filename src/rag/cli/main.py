"""
RAG CLI 메인 진입점

Typer + Rich를 사용한 명령줄 인터페이스입니다.
사용자는 이 CLI를 통해 공격 시나리오를 실행하고 결과를 확인할 수 있습니다.

사용 예시:
  # 공격 실험 실행
  rag run --scenario R2 --attacker A2 --env poisoned

  # 문서 등록
  rag ingest --path data/documents/

  # 실험 결과 확인
  rag report --run-id RAG-2026-0413-001
"""

from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from rag.utils.config import load_config, load_env
from rag.utils.logger import setup_logger

# === Typer 앱 생성 ===
# Typer는 파이썬 함수를 CLI 명령어로 자동 변환해주는 프레임워크입니다.
app = typer.Typer(
  name="rag",
  help="RAG 공격 및 정보 유출 진단 시스템",
  add_completion=False,  # 자동완성 기능 비활성화 (불필요)
)

# === Rich 콘솔 생성 ===
# Rich는 터미널에 색상, 테이블, 진행바 등을 표시해주는 라이브러리입니다.
console = Console()


@app.callback()
def main_callback() -> None:
  """
  모든 명령어 실행 전에 공통으로 실행되는 콜백 함수입니다.
  환경변수 로드와 로거 설정을 수행합니다.
  """
  # .env 파일에서 API 키 등의 환경변수를 로드합니다
  load_env()
  # 로거를 설정합니다 (콘솔에 색상 로그 출력)
  setup_logger()


@app.command()
def run(
  scenario: str = typer.Option(
    ...,
    "--scenario", "-s",
    help="공격 시나리오 선택 (R2: 검색 데이터 유출, R4: 멤버십 추론, R9: 간접 프롬프트 주입)",
  ),
  attacker: str = typer.Option(
    "A1",
    "--attacker", "-a",
    help=(
      "공격자 유형 (A1: 블랙박스/일반, A2: 블랙박스/정보보유, "
      "A3: 화이트박스/정보보유, A4: 화이트박스/일반)"
    ),
  ),
  env: str = typer.Option(
    "poisoned",
    "--env", "-e",
    help="실행 환경 (clean: 대조군, poisoned: 실험군)",
  ),
  profile: str = typer.Option(
    "default",
    "--profile", "-p",
    help="실험 프로파일명 (설정 파일에서 프로파일별 설정을 로드)",
  ),
  config_path: Optional[str] = typer.Option(
    None,
    "--config", "-c",
    help="커스텀 설정 파일 경로 (미지정시 config/default.yaml 사용)",
  ),
) -> None:
  """
  공격 시나리오를 실행합니다.

  선택한 시나리오(R2/R4/R9), 공격자 유형(A1~A4), 환경(clean/poisoned)을
  조합하여 RAG 시스템에 대한 공격을 자동으로 수행하고 결과를 평가합니다.
  """
  # 설정 파일 로드
  config = load_config(config_path)

  # 실행 정보를 터미널에 표시합니다
  _show_run_info(scenario, attacker, env, profile)

  # === 1. 실험 ID 생성 및 설정 스냅샷 저장 ===
  from rag.utils.experiment import ExperimentManager

  exp_manager = ExperimentManager(config)
  run_id = exp_manager.create_run()
  exp_manager.save_snapshot(run_id, config)

  console.print(f"\n[cyan]실험 ID: [bold]{run_id}[/bold][/cyan]")

  # === 2. 문서 인덱싱 (대상 문서를 벡터 DB에 등록) ===
  from rag.ingest.pipeline import run_ingest

  doc_path = config.get("attack", {}).get("doc_path", "data/documents/")
  console.print(f"\n[cyan]1단계: 문서 인덱싱 중... (경로: {doc_path})[/cyan]")

  try:
    document_store, docs_written = run_ingest(doc_path, config)
    console.print(f"  → [green]{docs_written}개 청크 저장 완료[/green]")
  except (FileNotFoundError, ValueError) as e:
    console.print(f"\n[red]문서 인덱싱 실패: {e}[/red]")
    raise typer.Exit(code=1)

  # === 3. RAG 파이프라인 빌드 ===
  from rag.retriever.pipeline import build_rag_pipeline

  console.print("[cyan]2단계: RAG 파이프라인 구성 중...[/cyan]")

  try:
    rag_pipeline = build_rag_pipeline(document_store, config)
    rag_pipeline.warm_up()
    console.print("  → [green]RAG 파이프라인 준비 완료[/green]")
  except ValueError as e:
    console.print(f"\n[red]RAG 파이프라인 구성 실패: {e}[/red]")
    raise typer.Exit(code=1)

  # === 4. 공격 대상 문서 목록 준비 ===
  # DocumentStore에 저장된 문서들을 공격 대상으로 사용합니다
  stored_docs = document_store.filter_documents()
  target_docs = [
    {
      "content": doc.content,
      "meta": doc.meta,
      "doc_id": doc.id,
    }
    for doc in stored_docs
  ]
  console.print(f"  → 공격 대상 문서: [bold]{len(target_docs)}[/bold]개")

  # === 5. 공격 실행 ===
  from rag.attack.runner import AttackRunner

  console.print(
    f"\n[cyan]3단계: {scenario} 공격 실행 중... "
    f"(공격자={attacker}, 환경={env})[/cyan]"
  )

  runner = AttackRunner(config)
  try:
    results = runner.run(
      scenario=scenario,
      rag_pipeline=rag_pipeline,
      target_docs=target_docs,
      attacker=attacker,
      env=env,
    )
    console.print(
      f"  → [green]공격 {len(results)}회 실행 완료[/green]"
    )
  except ValueError as e:
    console.print(f"\n[red]공격 실행 실패: {e}[/red]")
    raise typer.Exit(code=1)

  # === 6. 평가 ===
  console.print(f"\n[cyan]4단계: {scenario} 공격 결과 평가 중...[/cyan]")

  summary = _evaluate_results(scenario, config, results)

  # === 7. 결과 출력 ===
  _show_evaluation_result(scenario, summary)

  # === 8. 결과 저장 ===
  # AttackResult를 직렬화 가능한 형태로 변환합니다
  serializable_summary = _serialize_summary(summary)
  exp_manager.save_result(run_id, serializable_summary, f"{scenario}_result.json")

  console.print(
    f"\n[green]실험 완료![/green] 결과 저장 위치: "
    f"[bold]data/results/{run_id}/[/bold]"
  )


@app.command()
def ingest(
  path: str = typer.Option(
    "data/documents/",
    "--path",
    help="등록할 문서가 있는 디렉토리 경로",
  ),
  config_path: Optional[str] = typer.Option(
    None,
    "--config", "-c",
    help="커스텀 설정 파일 경로",
  ),
) -> None:
  """
  문서를 벡터 DB에 등록합니다.

  지정된 경로의 PDF/TXT/MD 문서를 읽어서 청킹, 임베딩 과정을 거쳐
  FAISS 벡터 DB에 저장합니다.
  """
  config = load_config(config_path)

  console.print(Panel(
    f"[bold]문서 등록 시작[/bold]\n경로: {path}",
    title="[blue]RAG Ingest[/blue]",
  ))

  # 인덱싱 파이프라인을 실행합니다
  from rag.ingest.pipeline import run_ingest

  try:
    document_store, docs_written = run_ingest(path, config)
    console.print(
      f"\n[green]문서 등록 완료![/green] "
      f"총 [bold]{docs_written}[/bold]개 청크가 저장되었습니다."
    )
  except (FileNotFoundError, ValueError) as e:
    console.print(f"\n[red]오류: {e}[/red]")


@app.command()
def query(
  question: str = typer.Option(
    ...,
    "--question", "-q",
    help="질의할 질문 텍스트",
  ),
  doc_path: str = typer.Option(
    "data/documents/",
    "--doc-path", "-d",
    help="문서 디렉토리 경로 (인덱싱 후 질의)",
  ),
  config_path: Optional[str] = typer.Option(
    None,
    "--config", "-c",
    help="커스텀 설정 파일 경로",
  ),
) -> None:
  """
  문서를 인덱싱한 뒤 질문에 대한 RAG 답변을 생성합니다.

  지정된 경로의 문서를 벡터 DB에 등록하고,
  질문을 검색 → LLM 답변 생성 파이프라인으로 처리합니다.
  """
  config = load_config(config_path)

  # 1. 문서 인덱싱
  from rag.ingest.pipeline import run_ingest

  console.print(Panel(
    f"[bold]RAG 질의[/bold]\n질문: {question}\n문서 경로: {doc_path}",
    title="[blue]RAG Query[/blue]",
  ))

  try:
    console.print("\n[cyan]1단계: 문서 인덱싱 중...[/cyan]")
    document_store, docs_written = run_ingest(doc_path, config)
    console.print(f"  → {docs_written}개 청크 저장 완료")
  except (FileNotFoundError, ValueError) as e:
    console.print(f"\n[red]오류: {e}[/red]")
    return

  # 2. RAG 질의 파이프라인 실행
  from rag.retriever.pipeline import build_rag_pipeline, run_query

  console.print("[cyan]2단계: RAG 파이프라인으로 답변 생성 중...[/cyan]")

  try:
    rag_pipeline = build_rag_pipeline(document_store, config)
  except ValueError as e:
    console.print(f"\n[red]오류: {e}[/red]")
    return

  rag_pipeline.warm_up()

  result = run_query(rag_pipeline, question)

  # 3. 결과 출력
  replies = result.get("generator", {}).get("replies", [])
  retrieved_docs = result.get("retriever", {}).get("documents", [])

  if replies:
    console.print(Panel(
      replies[0],
      title="[bold green]답변[/bold green]",
      border_style="green",
    ))
  else:
    console.print("\n[red]답변을 생성하지 못했습니다.[/red]")

  # 검색된 문서 출처 표시
  if retrieved_docs:
    source_table = Table(title="참고 문서", show_header=True)
    source_table.add_column("#", style="cyan", width=3)
    source_table.add_column("출처", style="green")
    source_table.add_column("내용 미리보기", style="white", max_width=60)

    for i, doc in enumerate(retrieved_docs, 1):
      source = doc.meta.get("file_path", "알 수 없음")
      preview = doc.content[:80] + "..." if len(doc.content) > 80 else doc.content
      source_table.add_row(str(i), str(source), preview)

    console.print(source_table)


@app.command()
def report(
  run_id: str = typer.Option(
    ...,
    "--run-id", "-r",
    help="결과를 확인할 실험 ID (예: RAG-2026-0413-001)",
  ),
  config_path: Optional[str] = typer.Option(
    None,
    "--config", "-c",
    help="커스텀 설정 파일 경로",
  ),
) -> None:
  """
  실험 결과 리포트를 생성합니다.

  지정된 run_id의 실험 결과를 분석하여
  공격 성공률, PII 유출 프로파일, 위험도 판정 등을 출력합니다.
  JSON 요약, CSV 상세, PDF 종합 리포트를 생성합니다.
  """
  config = load_config(config_path)

  console.print(Panel(
    f"[bold]리포트 생성[/bold]\nRun ID: {run_id}",
    title="[blue]RAG Report[/blue]",
  ))

  from rag.report.generator import ReportGenerator

  report_gen = ReportGenerator(config)

  try:
    generated_files = report_gen.generate(run_id)
  except FileNotFoundError as e:
    console.print(f"\n[red]오류: {e}[/red]")
    raise typer.Exit(code=1)

  # 생성된 파일 목록 표시
  file_table = Table(title="생성된 리포트", show_header=True)
  file_table.add_column("형식", style="cyan", width=8)
  file_table.add_column("파일 경로", style="green")

  for fmt, path in generated_files.items():
    file_table.add_row(fmt.upper(), str(path))

  console.print()
  console.print(file_table)
  console.print(
    f"\n[green]리포트 생성 완료![/green] "
    f"총 [bold]{len(generated_files)}[/bold]개 파일"
  )


def _evaluate_results(
  scenario: str,
  config: dict,
  results: list,
) -> dict:
  """
  시나리오에 맞는 평가기를 선택하여 공격 결과를 평가합니다.

  Args:
    scenario: 공격 시나리오 ("R2", "R4", "R9")
    config: 설정 딕셔너리
    results: AttackResult 목록

  Returns:
    dict: 평가 요약 딕셔너리
  """
  scenario_upper = scenario.upper()

  if scenario_upper == "R2":
    from rag.evaluator.r2_evaluator import R2Evaluator
    evaluator = R2Evaluator(config)
  elif scenario_upper == "R4":
    from rag.evaluator.r4_evaluator import R4Evaluator
    evaluator = R4Evaluator(config)
  elif scenario_upper == "R9":
    from rag.evaluator.r9_evaluator import R9Evaluator
    evaluator = R9Evaluator(config)
  else:
    raise ValueError(f"지원하지 않는 시나리오: {scenario}")

  return evaluator.evaluate_batch(results)


def _show_evaluation_result(scenario: str, summary: dict) -> None:
  """
  평가 결과를 Rich 테이블로 터미널에 출력합니다.

  Args:
    scenario: 공격 시나리오
    summary: evaluate_batch()가 반환한 요약 딕셔너리
  """
  scenario_upper = scenario.upper()

  # 결과 테이블 생성
  result_table = Table(title=f"{scenario_upper} 공격 평가 결과", show_header=True)
  result_table.add_column("지표", style="cyan", width=20)
  result_table.add_column("값", style="green")

  result_table.add_row("전체 시행 수", str(summary.get("total", 0)))

  if scenario_upper == "R2":
    result_table.add_row(
      "성공 수 (유출)", str(summary.get("success_count", 0))
    )
    result_table.add_row(
      "성공률", f"{summary.get('success_rate', 0):.2%}"
    )
    result_table.add_row(
      "평균 ROUGE-L", f"{summary.get('avg_score', 0):.4f}"
    )
    result_table.add_row(
      "최고 ROUGE-L", f"{summary.get('max_score', 0):.4f}"
    )
    result_table.add_row(
      "임계값", str(summary.get("threshold", "N/A"))
    )

  elif scenario_upper == "R4":
    result_table.add_row(
      "적중 수 (b̂=b)", str(summary.get("hit_count", 0))
    )
    result_table.add_row(
      "적중률 (hit_rate)", f"{summary.get('hit_rate', 0):.2%}"
    )
    result_table.add_row(
      "멤버 적중률", f"{summary.get('member_hit_rate', 0):.2%}"
    )
    result_table.add_row(
      "비멤버 적중률", f"{summary.get('non_member_hit_rate', 0):.2%}"
    )
    is_success = summary.get("is_inference_successful", False)
    result_table.add_row(
      "추론 성공 여부",
      "[red]성공 (프라이버시 위험)[/red]" if is_success
      else "[green]실패 (안전)[/green]"
    )

  elif scenario_upper == "R9":
    result_table.add_row(
      "성공 수 (주입)", str(summary.get("success_count", 0))
    )
    result_table.add_row(
      "성공률", f"{summary.get('success_rate', 0):.2%}"
    )
    # 트리거별 결과 표시
    by_trigger = summary.get("by_trigger", {})
    for trigger, stats in by_trigger.items():
      result_table.add_row(
        f"  트리거: {trigger[:20]}",
        f"{stats.get('success', 0)}/{stats.get('total', 0)} "
        f"({stats.get('rate', 0):.2%})"
      )

  console.print()
  console.print(Panel(result_table, title="[bold blue]평가 결과[/bold blue]"))


def _serialize_summary(summary: dict) -> dict:
  """
  평가 요약을 JSON 직렬화 가능한 형태로 변환합니다.

  AttackResult 객체를 딕셔너리로 변환합니다.

  Args:
    summary: evaluate_batch()가 반환한 요약

  Returns:
    dict: JSON 직렬화 가능한 딕셔너리
  """
  from dataclasses import asdict

  serialized = {}
  for key, value in summary.items():
    if key == "results":
      # AttackResult 리스트를 딕셔너리 리스트로 변환
      serialized[key] = [asdict(r) for r in value]
    else:
      serialized[key] = value
  return serialized


def _show_run_info(scenario: str, attacker: str, env: str, profile: str) -> None:
  """
  실험 실행 정보를 Rich 테이블로 표시하는 내부 함수입니다.

  Args:
    scenario: 공격 시나리오 (R2, R4, R9)
    attacker: 공격자 유형 (A1~A4)
    env: 실행 환경 (clean, poisoned)
    profile: 실험 프로파일명
  """
  # 시나리오별 한국어 설명 매핑
  scenario_desc = {
    "R2": "검색 데이터 유출",
    "R4": "멤버십 추론 공격",
    "R9": "간접 프롬프트 주입",
  }

  # Rich 테이블 생성 (터미널에 깔끔한 표 형태로 출력)
  table = Table(title="실험 실행 정보", show_header=True)
  table.add_column("항목", style="cyan", width=15)
  table.add_column("값", style="green")

  table.add_row("시나리오", f"{scenario} ({scenario_desc.get(scenario, '알 수 없음')})")
  table.add_row("공격자 유형", attacker)
  table.add_row("실행 환경", env)
  table.add_row("프로파일", profile)

  console.print()
  console.print(Panel(table, title="[bold blue]RAG 공격 시뮬레이션[/bold blue]"))


# === 메인 실행 ===
# 이 파일을 직접 실행하거나 "python -m rag" 으로 실행할 때 CLI가 시작됩니다
if __name__ == "__main__":
  app()
