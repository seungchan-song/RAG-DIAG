"""CLI entrypoints for ingest, query, run, and report workflows."""

from __future__ import annotations

import copy
import json
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich import box

from rag.attack.base import AttackResult, ExecutionFailureRecord
from rag.utils.config import load_config, load_env
from rag.utils.logger import setup_logger

app = typer.Typer(
    name="rag",
    help="RAG attack and retrieval diagnostics CLI",
    add_completion=False,
    invoke_without_command=True,  # 서브커맨드 없이 실행해도 callback이 호출되도록
)
console = Console()

_VERSION = "0.1.0"

_BANNER = r"""
██████╗  █████╗  ██████╗      ██████╗  ██╗ █████╗  ██████╗
██╔══██╗██╔══██╗██╔════╝      ██╔══██╗ ██║██╔══██╗██╔════╝
██████╔╝███████║██║  ███╗     ██║  ██║ ██║███████║██║  ███╗
██╔══██╗██╔══██║██║   ██║     ██║  ██║ ██║██╔══██║██║   ██║
██║  ██║██║  ██║╚██████╔╝     ██████╔╝ ██║██║  ██║╚██████╔╝
╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝      ╚═════╝  ╚═╝╚═╝  ╚═╝ ╚═════╝
"""


def _show_banner() -> None:
    """
    시작 화면 배너와 명령어 목록을 출력한다.

    `python -m rag` 를 인수 없이 실행했을 때 호출되며,
    ASCII 아트 로고, 버전, 프로젝트 설명, 명령어 목록을 Rich로 렌더링한다.
    """
    # ── 로고 패널 ──────────────────────────────────────────
    banner_text = Text(_BANNER, style="bold cyan", justify="center")
    subtitle = Text(
        f"RAG 공격 및 한국형 PII 유출 진단 시스템  •  v{_VERSION}  •  팀 수박",
        style="bold white",
        justify="center",
    )
    console.print(
        Panel(
            Text.assemble(banner_text, "\n", subtitle),
            border_style="cyan",
            padding=(0, 2),
        )
    )

    # ── 명령어 목록 ────────────────────────────────────────
    cmd_table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        padding=(0, 2),
        expand=True,
    )
    cmd_table.add_column("명령어", style="bold green", no_wrap=True)
    cmd_table.add_column("설명", style="white")
    cmd_table.add_column("예시", style="dim")

    cmd_table.add_row(
        "run",
        "공격 시나리오 실행 (R2 / R4 / R9)",
        "rag run --all-scenarios --all-envs --auto-report",
    )
    cmd_table.add_row(
        "ingest",
        "TXT/PDF 문서를 벡터 DB(FAISS)에 등록",
        "rag ingest --env clean",
    )
    cmd_table.add_row(
        "query",
        "RAG 시스템에 직접 질문해서 응답 확인",
        'rag query -q "홍길동의 주민번호 알려줘"',
    )
    cmd_table.add_row(
        "report",
        "실행 결과로 HTML/CSV/JSON 리포트 생성",
        "rag report --run-id <run_id>",
    )
    cmd_table.add_row(
        "pii-eval",
        "PII 탐지 4단계 파이프라인 성능 벤치마크",
        "rag pii-eval --dataset-path kdpii.jsonl",
    )
    cmd_table.add_row(
        "replay",
        "이전 실험을 동일 설정으로 재실행",
        "rag replay --run-id <run_id>",
    )

    console.print(
        Panel(
            cmd_table,
            title="[bold blue]사용 가능한 명령어[/bold blue]",
            border_style="blue",
            padding=(1, 1),
        )
    )

    # ── 빠른 시작 순서 ────────────────────────────────────
    quick_start = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    quick_start.add_column("Step", style="bold yellow", no_wrap=True)
    quick_start.add_column("Command", style="green")
    quick_start.add_column("Description", style="dim")
    quick_start.add_row("1단계", "rag ingest --env clean", "Clean DB 인덱스 구축")
    quick_start.add_row(
        "2단계", "rag ingest --env poisoned -s R2", "Poisoned DB 인덱스 구축"
    )
    quick_start.add_row(
        "3단계",
        "rag run --all-scenarios --all-envs --all-profiles --auto-report",
        "전체 매트릭스 실행 + 리포트 자동 생성",
    )

    console.print(
        Panel(
            quick_start,
            title="[bold yellow]빠른 시작[/bold yellow]",
            border_style="yellow",
            padding=(0, 1),
        )
    )

    # ── 팁 & 힌트 ─────────────────────────────────────────
    tips = Table(show_header=False, box=None, padding=(0, 1))
    tips.add_column("tip", style="white")
    tips.add_row(
        "[bold]--auto-report[/bold]  실행 완료 후 리포트를 자동으로 생성합니다."
    )
    tips.add_row(
        "[bold]--resume <run_id>[/bold]  중간에 끊긴 실험을 이어서 실행할 수 있습니다."
    )
    tips.add_row(
        "[bold]rag run -s R2 -a A1 -e poisoned[/bold]  단일 시나리오만 빠르게 테스트할 수 있습니다."
    )
    tips.add_row(
        "[bold]rag [italic]<명령어>[/italic] --help[/bold]  각 명령어의 전체 옵션을 확인합니다."
    )

    console.print(
        Panel(
            tips,
            title="[bold dim]Tips[/bold dim]",
            border_style="dim",
            padding=(0, 2),
        )
    )


@dataclass(frozen=True)
class SuiteCell:
    """One orchestrated child run in a suite matrix."""

    scenario: str
    environment_type: str
    profile_name: str

    @property
    def cell_id(self) -> str:
        return f"{self.scenario.upper()}__{self.environment_type}__{self.profile_name}"

    def to_dict(self) -> dict[str, str]:
        return {
            "cell_id": self.cell_id,
            "scenario": self.scenario.upper(),
            "environment_type": self.environment_type,
            "profile_name": self.profile_name,
            "child_run_id": self.cell_id,
        }


@dataclass
class SingleRunOutcome:
    """Result metadata for one completed single-run execution."""

    run_id: str
    scenario: str
    environment_type: str
    profile_name: str
    status: str
    summary: dict[str, Any]


@app.callback()
def main_callback(ctx: typer.Context) -> None:
    """
    모든 명령어 실행 전에 공통으로 호출되는 콜백 함수.

    - 환경변수(.env)를 로드한다.
    - loguru 로거를 초기화한다.
    - 서브커맨드 없이 `rag`만 입력하면 시작 화면을 출력하고 종료한다.
    """
    load_env()
    setup_logger()
    # 서브커맨드가 없을 때만 시작 화면 출력
    if ctx.invoked_subcommand is None:
        _show_banner()


@app.command()
def run(
    scenario: Optional[str] = typer.Option(
        None,
        "--scenario",
        "-s",
        help="실행할 시나리오 (R2, R4, R9). --all-scenarios 미사용 시 필수.",
    ),
    attacker: str = typer.Option(
        "A1",
        "--attacker",
        "-a",
        help="공격자 유형 (A1=앵커쿼리, A2=명령어프롬프트, A3=혼합, A4=반복). 기본값: A1",
    ),
    env: str = typer.Option(
        "poisoned",
        "--env",
        "-e",
        help="실행 환경 (clean=대조군, poisoned=실험군). 기본값: poisoned",
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="Retrieval profile name to resolve from config",
    ),
    all_envs: bool = typer.Option(
        False,
        "--all-envs",
        help="Run the configured environment matrix instead of one environment",
    ),
    all_profiles: bool = typer.Option(
        False,
        "--all-profiles",
        help="Run the configured profile matrix instead of one profile",
    ),
    all_scenarios: bool = typer.Option(
        False,
        "--all-scenarios",
        help="Run R2, R4, and R9 in one suite",
    ),
    resume: Optional[str] = typer.Option(
        None,
        "--resume",
        help="Resume a previous run id instead of starting a new one",
    ),
    auto_report: bool = typer.Option(
        False,
        "--auto-report",
        help="실험 완료 후 자동으로 HTML/CSV/JSON 리포트를 생성합니다.",
    ),
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom config file",
    ),
) -> None:
    """Run one attack scenario or an orchestrated experiment suite."""
    if scenario and all_scenarios:
        console.print(
            "\n[red]Error:[/red] `--scenario` and `--all-scenarios` cannot be used together."
        )
        raise typer.Exit(code=1)

    base_config = load_config(config_path)
    from rag.utils.experiment import ExperimentManager

    base_exp_manager = ExperimentManager(base_config)
    is_suite_resume = bool(
        resume and base_exp_manager.suite_manifest_path(resume).exists()
    )
    is_suite_run = is_suite_resume or all_envs or all_profiles or all_scenarios

    if is_suite_run:
        _show_suite_run_info(
            scenario=scenario,
            attacker=attacker,
            env=env,
            profile=profile,
            all_envs=all_envs,
            all_profiles=all_profiles,
            all_scenarios=all_scenarios,
            resume=resume,
        )
        try:
            suite_run_id = _execute_suite_run(
                base_config=base_config,
                base_exp_manager=base_exp_manager,
                scenario=scenario,
                attacker=attacker,
                env=env,
                profile=profile,
                all_envs=all_envs,
                all_profiles=all_profiles,
                all_scenarios=all_scenarios,
                resume=resume,
                config_path=config_path,
            )
        except (FileNotFoundError, ValueError) as error:
            console.print(f"\n[red]Suite execution failed: {error}[/red]")
            raise typer.Exit(code=1) from error

        console.print(
            "\n[green]Suite complete.[/green] "
            f"Results saved under [bold]data/results/{suite_run_id}/[/bold]"
        )

        if auto_report:
            _run_auto_report(suite_run_id, base_config)

        return

    if resume and scenario is None:
        try:
            checkpoint = base_exp_manager.load_checkpoint(resume)
            snapshot = base_exp_manager.load_snapshot(resume)
        except FileNotFoundError as error:
            console.print(f"\n[red]Resume failed: {error}[/red]")
            raise typer.Exit(code=1) from error

        scenario = str(checkpoint.get("scenario", "")).upper() or scenario
        attacker = str(checkpoint.get("attacker", attacker))
        env = str(checkpoint.get("environment_type", env))
        profile = str(
            snapshot.get("config", {}).get("profile_name")
            or checkpoint.get("profile_name")
            or profile
        )

    if not scenario:
        console.print(
            "\n[red]Error:[/red] `--scenario` is required unless `--all-scenarios` is used."
        )
        raise typer.Exit(code=1)

    config = load_config(config_path, profile=profile)
    _show_run_info(scenario, attacker, env, profile, resume=resume)

    try:
        outcome = _execute_single_run(
            config,
            scenario=scenario,
            attacker=attacker,
            env=env,
            profile=profile,
            exp_manager=ExperimentManager(config),
            run_id=resume,
            resume_existing=bool(resume),
        )
    except Exception as error:
        console.print(f"\n[red]Run failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    if str(outcome.status).startswith("failed_"):
        console.print(
            "\n[red]Run stopped during "
            f"{outcome.status}.[/red] "
            f"Failure artifacts were saved under [bold]data/results/{outcome.run_id}/[/bold]."
        )
        raise typer.Exit(code=1)

    console.print(
        f"\n[green]Run complete.[/green] "
        f"Status: [bold]{outcome.status}[/bold]  |  "
        f"Run ID: [bold]{outcome.run_id}[/bold]\n"
        f"Results saved under [bold]data/results/{outcome.run_id}/[/bold]"
        + (
            ""
            if auto_report
            else f"\nNext step → [bold]rag report --run-id {outcome.run_id}[/bold]"
        )
    )

    if auto_report:
        _run_auto_report(outcome.run_id, base_config)


@app.command()
def ingest(
    path: str = typer.Option(
        "data/documents/",
        "--path",
        help="Document directory to ingest",
    ),
    env: str = typer.Option(
        "clean",
        "--env",
        "-e",
        help="Environment to ingest (clean or poisoned)",
    ),
    scenario: Optional[str] = typer.Option(
        None,
        "--scenario",
        "-s",
        help="Scenario scope for poisoned indexes (R2, R4, R9)",
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="Retrieval profile name to resolve from config",
    ),
    rebuild: bool = typer.Option(
        False,
        "--rebuild",
        help="Force rebuilding the environment index even if one already exists",
    ),
    incremental: bool = typer.Option(
        False,
        "--incremental",
        help="Apply add/update changes to an existing matching index",
    ),
    sync_delete: bool = typer.Option(
        False,
        "--sync-delete",
        help="When used with --incremental, remove files that disappeared from the dataset",
    ),
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom config file",
    ),
) -> None:
    """Build or refresh the persisted FAISS index for one environment."""
    if rebuild and incremental:
        console.print(
            "\n[red]Error:[/red] `--rebuild` and `--incremental` cannot be used together."
        )
        raise typer.Exit(code=1)
    if sync_delete and not incremental:
        console.print(
            "\n[red]Error:[/red] `--sync-delete` can only be used together with `--incremental`."
        )
        raise typer.Exit(code=1)

    try:
        _require_scenario_for_poisoned(env, scenario)
    except ValueError as error:
        console.print(f"\n[red]Error: {error}[/red]")
        raise typer.Exit(code=1) from error
    config = load_config(config_path, profile=profile)
    scenario_label = _resolve_cli_scenario_scope(env, scenario)

    console.print(
        Panel(
            (
                f"[bold]Document ingest[/bold]\n"
                f"Path: {path}\n"
                f"Environment: {env}\n"
                f"Scenario scope: {scenario_label}\n"
                f"Profile: {profile}\n"
                f"Rebuild: {rebuild}\n"
                f"Incremental: {incremental}\n"
                f"Sync delete: {sync_delete}"
            ),
            title="[blue]RAG Ingest[/blue]",
        )
    )

    from rag.index.manager import PersistentIndexManager

    index_manager = PersistentIndexManager(
        config,
        doc_path=path,
        environment=env,
        scenario=scenario,
    )
    try:
        _, manifest, status = index_manager.ensure_index(
            rebuild=rebuild,
            incremental=incremental,
            sync_delete=sync_delete,
            auto_build_if_missing=True,
        )
    except (FileNotFoundError, ValueError) as error:
        console.print(f"\n[red]Error: {error}[/red]")
        raise typer.Exit(code=1) from error

    console.print(
        "\n[green]Ingest complete.[/green] "
        f"Index status: [bold]{status}[/bold], "
        f"dataset_scope: [bold]{manifest.get('dataset_scope', scenario_label)}[/bold], "
        f"documents: [bold]{manifest.get('doc_count', 0)}[/bold]"
    )
    delta = manifest.get("last_ingest_delta", {})
    if delta:
        retained_deleted = delta.get("retained_deleted", {})
        if retained_deleted.get("count", 0):
            console.print(
                "[yellow]Deleted files were retained in the index.[/yellow] "
                "Run the same command with [bold]--incremental --sync-delete[/bold] "
                "or [bold]--rebuild[/bold] to restore exact dataset parity."
            )


@app.command()
def query(
    question: str = typer.Option(
        ...,
        "--question",
        "-q",
        help="Question to ask the RAG system",
    ),
    doc_path: str = typer.Option(
        "data/documents/",
        "--doc-path",
        "-d",
        help="Document directory used to resolve the persisted index",
    ),
    env: Optional[str] = typer.Option(
        None,
        "--env",
        "-e",
        help="Environment to query against (clean or poisoned). Defaults to path inference.",
    ),
    scenario: Optional[str] = typer.Option(
        None,
        "--scenario",
        "-s",
        help="Scenario scope for poisoned indexes (R2, R4, R9)",
    ),
    profile: str = typer.Option(
        "default",
        "--profile",
        "-p",
        help="Retrieval profile name to resolve from config",
    ),
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom config file",
    ),
) -> None:
    """Run a one-off RAG query using the persisted environment index."""
    resolved_env = env or _infer_environment_from_doc_path(doc_path)
    try:
        _require_scenario_for_poisoned(resolved_env, scenario)
    except ValueError as error:
        console.print(f"\n[red]Error: {error}[/red]")
        raise typer.Exit(code=1) from error
    config = load_config(config_path, profile=profile)
    scenario_label = _resolve_cli_scenario_scope(resolved_env, scenario)

    console.print(
        Panel(
            (
                f"[bold]RAG Query[/bold]\n"
                f"Question: {question}\n"
                f"Document path: {doc_path}\n"
                f"Environment: {resolved_env}\n"
                f"Scenario scope: {scenario_label}\n"
                f"Profile: {profile}"
            ),
            title="[blue]RAG Query[/blue]",
        )
    )

    from rag.index.manager import PersistentIndexManager
    from rag.retriever.pipeline import build_rag_pipeline, run_query

    console.print("\n[cyan]1. Loading persisted index[/cyan]")
    index_manager = PersistentIndexManager(
        config,
        doc_path=doc_path,
        environment=resolved_env,
        scenario=scenario,
    )
    try:
        document_store, manifest, status = index_manager.ensure_index(
            rebuild=False,
            auto_build_if_missing=config.get("index", {}).get(
                "auto_build_if_missing", True
            ),
        )
    except (FileNotFoundError, ValueError) as error:
        console.print(f"\n[red]Error: {error}[/red]")
        raise typer.Exit(code=1) from error
    console.print(
        "  [green]Index ready[/green] "
        f"({status}, dataset_scope={manifest.get('dataset_scope', scenario_label)}, "
        f"documents={manifest.get('doc_count', 0)})"
    )

    console.print("[cyan]2. Running query[/cyan]")
    try:
        rag_pipeline = build_rag_pipeline(document_store, config)
    except ValueError as error:
        console.print(f"\n[red]Error: {error}[/red]")
        raise typer.Exit(code=1) from error
    rag_pipeline.warm_up()

    result = run_query(rag_pipeline, question)
    replies = result.get("generator", {}).get("replies", [])
    retrieved_docs = result.get("retrieved_documents", [])

    if replies:
        console.print(
            Panel(
                replies[0],
                title="[bold green]Answer[/bold green]",
                border_style="green",
            )
        )
    else:
        console.print("\n[red]No answer was generated.[/red]")

    reranker_state = "ON" if result.get("reranker_enabled") else "OFF"
    console.print(
        f"\n[cyan]Profile:[/cyan] {result.get('profile_name', profile)} "
        f"| [cyan]Environment:[/cyan] {resolved_env} "
        f"| [cyan]Dataset:[/cyan] {manifest.get('dataset_scope', scenario_label)} "
        f"| [cyan]Reranker:[/cyan] {reranker_state}"
    )

    if result.get("context_empty"):
        console.print("[yellow]No documents survived retrieval filtering.[/yellow]")

    if retrieved_docs:
        source_table = Table(title="Retrieved Documents", show_header=True)
        source_table.add_column("#", style="cyan", width=3)
        source_table.add_column("Source", style="green")
        source_table.add_column("Preview", style="white", max_width=60)

        for index, doc in enumerate(retrieved_docs, start=1):
            meta = doc.get("meta", {})
            content = doc.get("content", "")
            source = meta.get("file_path") or meta.get("source") or "unknown"
            preview = content[:80] + "..." if len(content) > 80 else content
            source_table.add_row(str(index), str(source), preview)

        console.print(source_table)


@app.command()
def report(
    run_id: str = typer.Option(
        ...,
        "--run-id",
        "-r",
        help="Run ID to summarize",
    ),
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom config file",
    ),
) -> None:
    """Generate report artifacts for an existing run directory."""
    config = load_config(config_path)

    console.print(
        Panel(
            f"[bold]Generate report[/bold]\nRun ID: {run_id}",
            title="[blue]RAG Report[/blue]",
        )
    )

    from rag.report.generator import ReportGenerator

    report_gen = ReportGenerator(config)
    try:
        generated_files = report_gen.generate(run_id)
    except FileNotFoundError as error:
        console.print(f"\n[red]Error: {error}[/red]")
        raise typer.Exit(code=1) from error

    table = Table(title="Generated Files", show_header=True)
    table.add_column("Format", style="cyan", width=10)
    table.add_column("Path", style="green")

    for fmt, path in generated_files.items():
        table.add_row(fmt.upper(), str(path))

    console.print()
    console.print(table)
    console.print(
        f"\n[green]Report generation complete.[/green] "
        f"Created [bold]{len(generated_files)}[/bold] files."
    )


@app.command("pii-eval")
def pii_eval(
    dataset_path: str = typer.Option(
        ...,
        "--dataset-path",
        help="Local KDPII-style JSONL dataset path",
    ),
    mode: str = typer.Option(
        "full",
        "--mode",
        help="Evaluation mode: step1, step1_2, step1_2_3, or full",
    ),
    all_modes: bool = typer.Option(
        False,
        "--all-modes",
        help="Run step1, step1_2, step1_2_3, and full in one benchmark run",
    ),
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a custom config file",
    ),
) -> None:
    """Run a KDPII-style exact-match benchmark for the layered PII pipeline."""
    config = load_config(config_path)

    from rag.pii.eval import (
        PIIBenchmarkRunner,
        build_dataset_manifest,
        load_eval_dataset,
        resolve_eval_modes,
        serialize_eval_snapshot,
    )
    from rag.utils.experiment import ExperimentManager

    try:
        modes = resolve_eval_modes(mode, all_modes)
        resolved_dataset_path, samples = load_eval_dataset(dataset_path)
    except (FileNotFoundError, ValueError) as error:
        console.print(f"\n[red]Error: {error}[/red]")
        raise typer.Exit(code=1) from error

    dataset_manifest = build_dataset_manifest(resolved_dataset_path, samples)
    exp_manager = ExperimentManager(config)
    run_id = exp_manager.create_run(prefix="PII-EVAL")
    run_dir = exp_manager.run_dir(run_id)

    console.print(
        Panel(
            (
                f"[bold]PII Benchmark[/bold]\n"
                f"Dataset: {resolved_dataset_path}\n"
                f"Modes: {', '.join(modes)}\n"
                f"Samples: {dataset_manifest['sample_count']}\n"
                f"Entities: {dataset_manifest['entity_count']}"
            ),
            title="[blue]RAG PII Eval[/blue]",
        )
    )
    console.print(f"\n[cyan]Run ID:[/cyan] [bold]{run_id}[/bold]")

    runner = PIIBenchmarkRunner(config)
    exp_manager.save_snapshot(
        run_id,
        config,
        metadata=serialize_eval_snapshot(
            dataset_manifest=dataset_manifest,
            modes=modes,
            label_schema_version=runner.label_schema_version,
        ),
    )

    try:
        generated_files = runner.evaluate(
            dataset_path=resolved_dataset_path,
            modes=modes,
            run_id=run_id,
            output_dir=run_dir,
        )
    except ValueError as error:
        console.print(f"\n[red]PII evaluation failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    table = Table(title="Generated Files", show_header=True)
    table.add_column("Artifact", style="cyan", width=18)
    table.add_column("Path", style="green")
    table.add_row("SNAPSHOT", str(run_dir / "snapshot.yaml"))
    for name, path in generated_files.items():
        table.add_row(name.upper(), str(path))

    console.print()
    console.print(table)
    console.print(
        f"\n[green]PII benchmark complete.[/green] "
        f"Results saved under [bold]{run_dir}[/bold]"
    )


@app.command()
def replay(
    run_id: str = typer.Option(
        ...,
        "--run-id",
        "-r",
        help="Completed run id to replay into a new run directory",
    ),
    config_path: Optional[str] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to a config used to resolve the base results directory",
    ),
) -> None:
    """Replay a completed single run, suite run, or pii benchmark into a new run id."""
    base_config = load_config(config_path)
    from rag.utils.experiment import ExperimentManager

    exp_manager = ExperimentManager(base_config)

    try:
        snapshot = exp_manager.load_snapshot(run_id)
    except FileNotFoundError as error:
        console.print(f"\n[red]Replay failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    source_run_type = _detect_replay_run_type(exp_manager, snapshot, run_id)

    console.print(
        Panel(
            (
                f"[bold]Replay run[/bold]\n"
                f"Source run: {run_id}\n"
                f"Detected type: {source_run_type}"
            ),
            title="[blue]RAG Replay[/blue]",
        )
    )

    try:
        if source_run_type == "suite":
            replayed_run_id = _replay_suite_run(
                source_run_id=run_id,
                source_snapshot=snapshot,
                base_exp_manager=exp_manager,
            )
        elif source_run_type == "pii_eval":
            replayed_run_id = _replay_pii_eval_run(
                source_run_id=run_id,
                source_snapshot=snapshot,
            )
        else:
            replayed_run_id = _replay_single_run(
                source_run_id=run_id,
                source_snapshot=snapshot,
            )
    except Exception as error:
        console.print(f"\n[red]Replay failed: {error}[/red]")
        raise typer.Exit(code=1) from error

    console.print(
        "\n[green]Replay complete.[/green] "
        f"Created [bold]{replayed_run_id}[/bold] from [bold]{run_id}[/bold]."
    )


def _detect_replay_run_type(
    exp_manager: Any,
    snapshot: dict[str, Any],
    run_id: str,
) -> str:
    """Infer the replay source type from saved artifacts."""
    if exp_manager.suite_manifest_path(run_id).exists() or snapshot.get("suite"):
        return "suite"
    if snapshot.get("pii_eval"):
        return "pii_eval"
    return "single"


def _replay_single_run(
    *,
    source_run_id: str,
    source_snapshot: dict[str, Any],
) -> str:
    """Replay one completed single scenario run into a fresh run id."""
    from rag.utils.experiment import (
        ExperimentManager,
        build_replay_audit,
        snapshot_uses_compatibility_mode,
    )

    source_config = _resolve_replay_config(source_snapshot)
    runtime = source_snapshot.get("runtime", {})
    compatibility_mode = snapshot_uses_compatibility_mode(source_snapshot)
    scenario = str(runtime.get("scenario") or "").upper() or _infer_single_run_scenario(
        ExperimentManager(source_config).run_dir(source_run_id)
    )
    env = str(runtime.get("environment_type") or "poisoned")
    attacker = str(runtime.get("attacker") or "A1")
    profile = str(
        source_config.get("profile_name") or runtime.get("profile_name") or "default"
    )
    if not scenario:
        raise ValueError(
            "Replay requires a saved scenario in snapshot runtime metadata."
        )

    index_manifest_match = _validate_replay_index_artifact(source_snapshot)
    exp_manager = ExperimentManager(source_config)
    replayed_run_id = exp_manager.create_run()
    replay_context = {
        "replayed_from_run_id": source_run_id,
        "compatibility_mode": compatibility_mode,
    }

    outcome = _execute_single_run(
        source_config,
        scenario=scenario,
        attacker=attacker,
        env=env,
        profile=profile,
        exp_manager=exp_manager,
        run_id=replayed_run_id,
        resume_existing=False,
        snapshot_metadata=replay_context,
        replay_context=replay_context,
    )

    replay_snapshot = exp_manager.load_snapshot(replayed_run_id)
    exp_manager.save_replay_audit(
        replayed_run_id,
        build_replay_audit(
            source_run_id=source_run_id,
            source_run_type="single",
            replayed_run_id=replayed_run_id,
            source_snapshot=source_snapshot,
            replay_snapshot=replay_snapshot,
            compatibility_mode=compatibility_mode,
            index_manifest_match=index_manifest_match,
        ),
    )
    if str(outcome.status).startswith("failed_"):
        raise RuntimeError(
            f"Replay stopped during {outcome.status}. "
            f"Failure artifacts were saved under run {replayed_run_id}."
        )
    return replayed_run_id


def _replay_suite_run(
    *,
    source_run_id: str,
    source_snapshot: dict[str, Any],
    base_exp_manager: Any,
) -> str:
    """Replay a saved suite into a fresh parent run with fresh child runs."""
    from rag.utils.experiment import (
        ExperimentManager,
        build_replay_audit,
        snapshot_uses_compatibility_mode,
    )

    source_config = _resolve_replay_config(source_snapshot)
    source_suite = dict(source_snapshot.get("suite", {}))
    if (
        not source_suite
        and base_exp_manager.suite_manifest_path(source_run_id).exists()
    ):
        source_suite = dict(base_exp_manager.load_suite_manifest(source_run_id))

    planned_payloads = source_suite.get("planned_cells", [])
    if not planned_payloads:
        raise ValueError(
            "Suite replay requires planned_cells in snapshot.yaml or suite_manifest.json."
        )

    planned_cells = [_deserialize_suite_cell(item) for item in planned_payloads]
    attacker = str(source_suite.get("attacker") or "A1")
    compatibility_mode = snapshot_uses_compatibility_mode(source_snapshot)

    source_child_root = base_exp_manager.run_dir(source_run_id) / "runs"
    source_child_manager = _create_child_experiment_manager(
        source_config, source_child_root
    )
    prepared_cells: list[tuple[SuiteCell, dict[str, Any], dict[str, Any]]] = []
    manifest_matches: list[bool] = []
    for cell in planned_cells:
        child_snapshot = source_child_manager.load_snapshot(cell.cell_id)
        compatibility_mode = compatibility_mode or snapshot_uses_compatibility_mode(
            child_snapshot
        )
        manifest_matches.append(_validate_replay_index_artifact(child_snapshot))
        prepared_cells.append(
            (cell, child_snapshot, _resolve_replay_config(child_snapshot))
        )

    exp_manager = ExperimentManager(source_config)
    replayed_run_id = exp_manager.create_run()
    suite_manifest = {
        "scenario_mode": str(source_suite.get("scenario_mode", "single")),
        "attacker": attacker,
        "scenarios": sorted({cell.scenario for cell in planned_cells}),
        "environments": sorted({cell.environment_type for cell in planned_cells}),
        "profiles": sorted({cell.profile_name for cell in planned_cells}),
        "planned_cells": [cell.to_dict() for cell in planned_cells],
        "status": "running",
        "replayed_from_run_id": source_run_id,
        "compatibility_mode": compatibility_mode,
    }
    exp_manager.save_snapshot(
        replayed_run_id,
        source_config,
        metadata={
            "suite": suite_manifest,
            "replayed_from_run_id": source_run_id,
            "compatibility_mode": compatibility_mode,
        },
    )
    exp_manager.save_suite_manifest(replayed_run_id, suite_manifest)
    suite_checkpoint = {
        "scenario_mode": suite_manifest["scenario_mode"],
        "planned_cells": [cell.cell_id for cell in planned_cells],
        "completed_cells": [],
        "failed_cells": [],
        "status": "running",
    }
    exp_manager.save_suite_checkpoint(replayed_run_id, suite_checkpoint)

    child_results_root = exp_manager.run_dir(replayed_run_id) / "runs"
    completed_cells: set[str] = set()
    failed_cells: set[str] = set()
    replay_context = {
        "replayed_from_run_id": source_run_id,
        "compatibility_mode": compatibility_mode,
    }

    console.print(f"\n[cyan]Suite Replay ID:[/cyan] [bold]{replayed_run_id}[/bold]")
    console.print(f"[cyan]Planned cells:[/cyan] [bold]{len(planned_cells)}[/bold]")

    for index, (cell, _, child_config) in enumerate(prepared_cells, start=1):
        console.print(
            "\n[cyan]Replay cell "
            f"{index}/{len(planned_cells)}:[/cyan] "
            f"{cell.cell_id}"
        )
        child_manager = _create_child_experiment_manager(
            child_config, child_results_root
        )

        try:
            outcome = _execute_single_run(
                child_config,
                scenario=cell.scenario,
                attacker=attacker,
                env=cell.environment_type,
                profile=cell.profile_name,
                exp_manager=child_manager,
                run_id=cell.cell_id,
                resume_existing=False,
                snapshot_metadata={
                    "suite_run_id": replayed_run_id,
                    "suite_cell_id": cell.cell_id,
                    "cell_environment": cell.environment_type,
                    "cell_profile_name": cell.profile_name,
                    "replayed_from_run_id": source_run_id,
                    "compatibility_mode": compatibility_mode,
                    "replay_source_cell_id": cell.cell_id,
                },
                suite_context={
                    "suite_run_id": replayed_run_id,
                    "suite_cell_id": cell.cell_id,
                    "cell_environment": cell.environment_type,
                    "cell_profile_name": cell.profile_name,
                },
                replay_context=replay_context,
            )
            if outcome.status == "completed":
                completed_cells.add(cell.cell_id)
                failed_cells.discard(cell.cell_id)
            else:
                failed_cells.add(cell.cell_id)
        except Exception as error:
            failed_cells.add(cell.cell_id)
            suite_checkpoint["last_error"] = f"{cell.cell_id}: {error}"
            console.print(
                f"[yellow]Replay cell failed:[/yellow] {cell.cell_id} ({error})"
            )

        suite_checkpoint["completed_cells"] = sorted(completed_cells)
        suite_checkpoint["failed_cells"] = sorted(failed_cells)
        suite_checkpoint["status"] = (
            "completed" if len(completed_cells) == len(planned_cells) else "partial"
        )
        exp_manager.save_suite_checkpoint(replayed_run_id, suite_checkpoint)
        _refresh_suite_results(
            exp_manager,
            suite_run_id=replayed_run_id,
            config=source_config,
            suite_result_metadata=replay_context,
        )

    suite_manifest["status"] = (
        "completed" if len(completed_cells) == len(planned_cells) else "partial"
    )
    exp_manager.save_suite_manifest(replayed_run_id, suite_manifest)
    replay_snapshot = exp_manager.load_snapshot(replayed_run_id)
    exp_manager.save_replay_audit(
        replayed_run_id,
        build_replay_audit(
            source_run_id=source_run_id,
            source_run_type="suite",
            replayed_run_id=replayed_run_id,
            source_snapshot=source_snapshot,
            replay_snapshot=replay_snapshot,
            compatibility_mode=compatibility_mode,
            index_manifest_match=all(manifest_matches) if manifest_matches else None,
        ),
    )
    return replayed_run_id


def _replay_pii_eval_run(
    *,
    source_run_id: str,
    source_snapshot: dict[str, Any],
) -> str:
    """Replay a saved PII benchmark run into a new PII-EVAL run id."""
    from rag.pii.eval import (
        PIIBenchmarkRunner,
        build_dataset_manifest,
        load_eval_dataset,
        serialize_eval_snapshot,
    )
    from rag.utils.experiment import (
        ExperimentManager,
        build_replay_audit,
        snapshot_uses_compatibility_mode,
    )

    source_config = _resolve_replay_config(source_snapshot)
    pii_eval_metadata = dict(source_snapshot.get("pii_eval", {}))
    dataset_manifest = dict(pii_eval_metadata.get("dataset_manifest", {}))
    dataset_path = dataset_manifest.get("dataset_path")
    if not dataset_path:
        raise ValueError(
            "PII eval replay requires dataset_manifest.dataset_path in snapshot.yaml."
        )

    requested_modes = list(pii_eval_metadata.get("requested_modes", []))
    if not requested_modes:
        mode = pii_eval_metadata.get("mode")
        requested_modes = [str(mode)] if mode else []
    if not requested_modes:
        raise ValueError("PII eval replay requires requested_modes in snapshot.yaml.")

    resolved_dataset_path = _resolve_existing_path(
        str(dataset_path),
        label="PII evaluation dataset",
    )
    compatibility_mode = snapshot_uses_compatibility_mode(source_snapshot)
    exp_manager = ExperimentManager(source_config)
    replayed_run_id = exp_manager.create_run(prefix="PII-EVAL")
    run_dir = exp_manager.run_dir(replayed_run_id)

    runner = PIIBenchmarkRunner(source_config)
    loaded_dataset_path, samples = load_eval_dataset(resolved_dataset_path)
    current_manifest = build_dataset_manifest(loaded_dataset_path, samples)
    exp_manager.save_snapshot(
        replayed_run_id,
        source_config,
        metadata={
            **serialize_eval_snapshot(
                dataset_manifest=current_manifest,
                modes=requested_modes,
                label_schema_version=runner.label_schema_version,
            ),
            "replayed_from_run_id": source_run_id,
            "compatibility_mode": compatibility_mode,
        },
    )
    runner.evaluate(
        dataset_path=loaded_dataset_path,
        modes=requested_modes,
        run_id=replayed_run_id,
        output_dir=run_dir,
        summary_metadata={
            "replayed_from_run_id": source_run_id,
            "compatibility_mode": compatibility_mode,
        },
    )

    replay_snapshot = exp_manager.load_snapshot(replayed_run_id)
    exp_manager.save_replay_audit(
        replayed_run_id,
        build_replay_audit(
            source_run_id=source_run_id,
            source_run_type="pii_eval",
            replayed_run_id=replayed_run_id,
            source_snapshot=source_snapshot,
            replay_snapshot=replay_snapshot,
            compatibility_mode=compatibility_mode,
            index_manifest_match=None,
        ),
    )
    return replayed_run_id


def _execute_single_run(
    config: dict[str, Any],
    *,
    scenario: str,
    attacker: str,
    env: str,
    profile: str,
    exp_manager: Any,
    run_id: str | None = None,
    resume_existing: bool = False,
    snapshot_metadata: dict[str, Any] | None = None,
    suite_context: dict[str, str] | None = None,
    replay_context: dict[str, Any] | None = None,
) -> SingleRunOutcome:
    """Run one scenario using the existing single-run execution path."""
    from rag.attack.runner import AttackRunner
    from rag.index.manager import PersistentIndexManager
    from rag.pii.artifacts import StorageSanitizer
    from rag.retriever.pipeline import build_rag_pipeline

    actual_run_id = run_id or exp_manager.create_run()
    stored_results_payload = exp_manager.load_partial_results(actual_run_id, scenario)
    stored_failure_payload = exp_manager.load_partial_failures(actual_run_id, scenario)
    checkpoint: dict[str, Any]
    profile_name = config.get("profile_name", profile)

    if resume_existing:
        checkpoint = exp_manager.load_checkpoint(actual_run_id)
        snapshot = exp_manager.load_snapshot(actual_run_id)
        _validate_resume_request(
            checkpoint=checkpoint,
            snapshot=snapshot,
            scenario=scenario,
            attacker=attacker,
            env=env,
            profile_name=profile_name,
        )
    else:
        checkpoint = {
            "scenario": scenario.upper(),
            "attacker": attacker,
            "environment_type": env,
            "profile_name": profile_name,
            "completed_query_ids": [],
            "failed_query_ids": [],
            "index_manifest_ref": "",
            "failure_attempt_count": 0,
            "failure_stage_counts": {},
            "last_error_stage": "",
            "status": "running",
        }

    failures = [
        _deserialize_execution_failure(payload) for payload in stored_failure_payload
    ]
    _update_checkpoint_failure_state(
        checkpoint,
        failures=failures,
        last_error_stage=str(checkpoint.get("last_error_stage", "")),
        status=str(checkpoint.get("status", "running")),
    )

    completed_query_ids = set(checkpoint.get("completed_query_ids", []))
    failed_query_ids = set(checkpoint.get("failed_query_ids", []))
    planned_query_count = int(checkpoint.get("planned_query_count", 0) or 0)
    evaluated_results = [
        _deserialize_attack_result(payload) for payload in stored_results_payload
    ]
    stored_results = [
        _deserialize_attack_result(payload) for payload in stored_results_payload
    ]
    storage_sanitizer = StorageSanitizer(config)
    index_manifest: dict[str, Any] = {}
    index_manifest_ref = str(checkpoint.get("index_manifest_ref", "") or "")
    document_store: Any = None

    console.print(f"\n[cyan]Run ID:[/cyan] [bold]{actual_run_id}[/bold]")

    doc_path = config.get("attack", {}).get("doc_path", "data/documents/")
    if not resume_existing:
        exp_manager.save_snapshot(
            actual_run_id,
            config,
            metadata={
                "runtime": {
                    "scenario": scenario.upper(),
                    "attacker": attacker,
                    "environment_type": env,
                    "profile_name": profile_name,
                    "scenario_scope": checkpoint.get("scenario_scope", ""),
                    "dataset_scope": checkpoint.get("dataset_scope", ""),
                },
                **(snapshot_metadata or {}),
            },
        )

    checkpoint["status"] = "running"
    exp_manager.save_checkpoint(actual_run_id, checkpoint)

    console.print(f"\n[cyan]1. Loading index for {env} from {doc_path}[/cyan]")
    try:
        index_manager = PersistentIndexManager(
            config,
            doc_path=doc_path,
            environment=env,
            scenario=scenario,
        )
        document_store, index_manifest, index_status = index_manager.ensure_index(
            rebuild=False,
            auto_build_if_missing=config.get("index", {}).get(
                "auto_build_if_missing", True
            ),
        )
        index_manifest_ref = str(index_manager.manifest_path)
        checkpoint["index_manifest_ref"] = index_manifest_ref
        checkpoint["scenario_scope"] = str(index_manifest.get("scenario_scope", ""))
        checkpoint["dataset_scope"] = str(index_manifest.get("dataset_scope", ""))
        console.print(
            "  [green]Index ready[/green] "
            f"({index_status}, dataset_scope={index_manifest.get('dataset_scope', '')}, "
            f"documents={index_manifest.get('doc_count', 0)})"
        )
    except Exception as error:
        failure = _build_failure_record(
            scenario=scenario,
            query_id="",
            query_text="",
            stage="index_load",
            error=error,
            attempt_index=_next_failure_attempt_index(
                failures,
                query_id="",
                stage="index_load",
            ),
            environment_type=env,
            profile_name=profile_name,
            scenario_scope=str(checkpoint.get("scenario_scope", "")),
            dataset_scope=str(checkpoint.get("dataset_scope", "")),
            index_manifest_ref=index_manifest_ref,
            suite_context=suite_context,
            replay_context=replay_context,
            storage_sanitizer=storage_sanitizer,
            metadata={"doc_path": doc_path, "attacker": attacker},
        )
        _append_failure_record(
            exp_manager=exp_manager,
            run_id=actual_run_id,
            scenario=scenario,
            failures=failures,
            failure=failure,
            checkpoint=checkpoint,
            checkpoint_status="failed_setup",
        )
        summary = _build_single_run_summary(
            scenario=scenario,
            config=config,
            evaluated_results=evaluated_results,
            stored_results=stored_results,
            failures=failures,
            checkpoint=checkpoint,
            profile_name=profile_name,
            index_manifest=index_manifest,
            index_manifest_ref=index_manifest_ref,
            planned_query_count=planned_query_count,
            completed_query_ids=completed_query_ids,
            failed_query_ids=failed_query_ids,
            suite_context=suite_context,
            replay_context=replay_context,
        )
        try:
            exp_manager.save_result(
                actual_run_id,
                _serialize_summary(summary),
                f"{scenario.upper()}_result.json",
            )
        except Exception:
            pass
        return SingleRunOutcome(
            run_id=actual_run_id,
            scenario=scenario.upper(),
            environment_type=env,
            profile_name=profile_name,
            status="failed_setup",
            summary=summary,
        )

    if not resume_existing:
        merged_snapshot_metadata = {
            "runtime": {
                "scenario": scenario.upper(),
                "attacker": attacker,
                "environment_type": env,
                "profile_name": profile_name,
                "scenario_scope": index_manifest.get("scenario_scope", ""),
                "dataset_scope": index_manifest.get("dataset_scope", ""),
            },
            "index_manifest": index_manifest,
            "index_manifest_ref": index_manifest_ref,
            "index_path": str(index_manager.index_dir),
        }
        if snapshot_metadata:
            merged_snapshot_metadata.update(snapshot_metadata)
        exp_manager.save_snapshot(
            actual_run_id,
            config,
            metadata=merged_snapshot_metadata,
        )

    exp_manager.save_checkpoint(actual_run_id, checkpoint)

    console.print("[cyan]2. Building RAG pipeline[/cyan]")
    try:
        rag_pipeline = build_rag_pipeline(document_store, config)
        rag_pipeline.warm_up()
        console.print("  [green]Pipeline ready[/green]")
    except Exception as error:
        failure = _build_failure_record(
            scenario=scenario,
            query_id="",
            query_text="",
            stage="pipeline_build",
            error=error,
            attempt_index=_next_failure_attempt_index(
                failures,
                query_id="",
                stage="pipeline_build",
            ),
            environment_type=env,
            profile_name=profile_name,
            scenario_scope=str(index_manifest.get("scenario_scope", "")),
            dataset_scope=str(index_manifest.get("dataset_scope", "")),
            index_manifest_ref=index_manifest_ref,
            suite_context=suite_context,
            replay_context=replay_context,
            storage_sanitizer=storage_sanitizer,
            metadata={"attacker": attacker},
        )
        _append_failure_record(
            exp_manager=exp_manager,
            run_id=actual_run_id,
            scenario=scenario,
            failures=failures,
            failure=failure,
            checkpoint=checkpoint,
            checkpoint_status="failed_setup",
        )
        summary = _build_single_run_summary(
            scenario=scenario,
            config=config,
            evaluated_results=evaluated_results,
            stored_results=stored_results,
            failures=failures,
            checkpoint=checkpoint,
            profile_name=profile_name,
            index_manifest=index_manifest,
            index_manifest_ref=index_manifest_ref,
            planned_query_count=planned_query_count,
            completed_query_ids=completed_query_ids,
            failed_query_ids=failed_query_ids,
            suite_context=suite_context,
            replay_context=replay_context,
        )
        try:
            exp_manager.save_result(
                actual_run_id,
                _serialize_summary(summary),
                f"{scenario.upper()}_result.json",
            )
        except Exception:
            pass
        return SingleRunOutcome(
            run_id=actual_run_id,
            scenario=scenario.upper(),
            environment_type=env,
            profile_name=profile_name,
            status="failed_setup",
            summary=summary,
        )

    try:
        stored_docs = document_store.filter_documents()
        candidate_docs = [
            {
                "content": doc.content,
                "meta": doc.meta,
                "doc_id": doc.meta.get("chunk_id") or doc.meta.get("doc_id") or doc.id,
                "keyword": doc.meta.get("keyword", ""),
            }
            for doc in stored_docs
        ]
        target_docs = [
            doc
            for doc in candidate_docs
            if doc.get("meta", {}).get("doc_role") != "attack"
        ] or candidate_docs
        console.print(f"  Target documents: [bold]{len(target_docs)}[/bold]")

        console.print(f"\n[cyan]3. Executing {scenario}[/cyan]")
        runner = AttackRunner(config)
        attack, queries = runner.prepare_queries(
            scenario, target_docs, attacker=attacker, env=env
        )
        evaluator = _create_evaluator(scenario, config)
        planned_query_count = len(queries)
        checkpoint["planned_query_count"] = planned_query_count
        checkpoint["status"] = "running"
        exp_manager.save_checkpoint(actual_run_id, checkpoint)
    except Exception as error:
        checkpoint["planned_query_count"] = planned_query_count
        failure = _build_failure_record(
            scenario=scenario,
            query_id="",
            query_text="",
            stage="query_prepare",
            error=error,
            attempt_index=_next_failure_attempt_index(
                failures,
                query_id="",
                stage="query_prepare",
            ),
            environment_type=env,
            profile_name=profile_name,
            scenario_scope=str(index_manifest.get("scenario_scope", "")),
            dataset_scope=str(index_manifest.get("dataset_scope", "")),
            index_manifest_ref=index_manifest_ref,
            suite_context=suite_context,
            replay_context=replay_context,
            storage_sanitizer=storage_sanitizer,
            metadata={"attacker": attacker},
        )
        _append_failure_record(
            exp_manager=exp_manager,
            run_id=actual_run_id,
            scenario=scenario,
            failures=failures,
            failure=failure,
            checkpoint=checkpoint,
            checkpoint_status="failed_setup",
        )
        summary = _build_single_run_summary(
            scenario=scenario,
            config=config,
            evaluated_results=evaluated_results,
            stored_results=stored_results,
            failures=failures,
            checkpoint=checkpoint,
            profile_name=profile_name,
            index_manifest=index_manifest,
            index_manifest_ref=index_manifest_ref,
            planned_query_count=planned_query_count,
            completed_query_ids=completed_query_ids,
            failed_query_ids=failed_query_ids,
            suite_context=suite_context,
            replay_context=replay_context,
        )
        try:
            exp_manager.save_result(
                actual_run_id,
                _serialize_summary(summary),
                f"{scenario.upper()}_result.json",
            )
        except Exception:
            pass
        return SingleRunOutcome(
            run_id=actual_run_id,
            scenario=scenario.upper(),
            environment_type=env,
            profile_name=profile_name,
            status="failed_setup",
            summary=summary,
        )

    executed_now = 0
    failed_now = 0
    skipped_count = sum(
        1 for q in queries if str(q.get("query_id", "")) in completed_query_ids
    )
    pending_count = len(queries) - skipped_count

    progress = Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(bar_width=30),
        TaskProgressColumn(),
        TextColumn("[dim]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    )
    task_id = progress.add_task(
        f"{scenario} 공격 쿼리 실행 중",
        total=pending_count,
    )

    with progress:
        for trial_index, query_info in enumerate(queries):
            query_id = str(query_info.get("query_id", ""))
            if query_id and query_id in completed_query_ids:
                continue

            current_stage = "query_execute"
            try:
                result = runner.execute_query(
                    attack,
                    query_info=query_info,
                    rag_pipeline=rag_pipeline,
                    attacker=attacker,
                    env=env,
                    trial_index=trial_index,
                )
                _apply_index_context(
                    result,
                    index_manifest=index_manifest,
                    index_manifest_ref=str(index_manager.manifest_path),
                )
                _apply_suite_context(
                    result,
                    suite_context=suite_context,
                    env=env,
                    profile=profile_name,
                )
                _apply_replay_context(result, replay_context=replay_context)
                current_stage = "evaluate"
                evaluator.evaluate(result)
                sanitized_result = storage_sanitizer.sanitized_copy(result)
                current_stage = "persist"
                next_evaluated_results = evaluated_results + [result]
                next_stored_results = stored_results + [sanitized_result]
                next_completed_query_ids = set(completed_query_ids)
                next_failed_query_ids = set(failed_query_ids)
                if query_id:
                    next_completed_query_ids.add(query_id)
                    next_failed_query_ids.discard(query_id)

                next_checkpoint = dict(checkpoint)
                next_checkpoint["completed_query_ids"] = sorted(
                    next_completed_query_ids
                )
                next_checkpoint["failed_query_ids"] = sorted(next_failed_query_ids)
                next_checkpoint["planned_query_count"] = len(queries)
                next_checkpoint["status"] = "running"
                exp_manager.save_partial_results(
                    actual_run_id,
                    scenario,
                    [_serialize_value(item) for item in next_stored_results],
                )
                exp_manager.save_checkpoint(actual_run_id, next_checkpoint)
                evaluated_results = next_evaluated_results
                stored_results = next_stored_results
                completed_query_ids = next_completed_query_ids
                failed_query_ids = next_failed_query_ids
                checkpoint = next_checkpoint
                executed_now += 1
                success_label = "[green]✓[/green]" if result.success else "[dim]–[/dim]"
                progress.update(
                    task_id,
                    advance=1,
                    description=f"{scenario} 공격 쿼리 실행 중  {success_label} {query_id or trial_index}",
                )
            except Exception as error:
                if query_id:
                    failed_query_ids.add(query_id)
                checkpoint["completed_query_ids"] = sorted(completed_query_ids)
                checkpoint["failed_query_ids"] = sorted(failed_query_ids)
                checkpoint["planned_query_count"] = len(queries)
                failure = _build_failure_record(
                    scenario=scenario,
                    query_id=query_id,
                    query_text=str(query_info.get("query", "")),
                    stage=current_stage,
                    error=error,
                    attempt_index=_next_failure_attempt_index(
                        failures,
                        query_id=query_id,
                        stage=current_stage,
                    ),
                    environment_type=env,
                    profile_name=profile_name,
                    scenario_scope=str(index_manifest.get("scenario_scope", "")),
                    dataset_scope=str(index_manifest.get("dataset_scope", "")),
                    index_manifest_ref=index_manifest_ref,
                    suite_context=suite_context,
                    replay_context=replay_context,
                    storage_sanitizer=storage_sanitizer,
                    metadata={
                        "attacker": attacker,
                        "trial_index": trial_index,
                    },
                )
                _append_failure_record(
                    exp_manager=exp_manager,
                    run_id=actual_run_id,
                    scenario=scenario,
                    failures=failures,
                    failure=failure,
                    checkpoint=checkpoint,
                    checkpoint_status="running",
                )
                failed_now += 1
                progress.update(
                    task_id,
                    advance=1,
                    description=f"{scenario} 공격 쿼리 실행 중  [yellow]✗[/yellow] {query_id or trial_index}",
                )
                progress.console.print(
                    f"  [yellow]쿼리 실패 (체크포인트 저장됨):[/yellow] "
                    f"{query_id or 'unknown'} — {error}"
                )

    fail_suffix = f"  [yellow]실패: {failed_now}건[/yellow]" if failed_now else ""
    console.print(
        f"  [green]완료: {executed_now}건[/green]  [dim]재개 스킵: {skipped_count}건[/dim]"
        + fail_suffix
    )

    console.print(f"\n[cyan]4. Evaluating {scenario} results[/cyan]")
    checkpoint["completed_query_ids"] = sorted(completed_query_ids)
    checkpoint["failed_query_ids"] = sorted(failed_query_ids)
    checkpoint["planned_query_count"] = len(queries)
    checkpoint["status"] = (
        "completed" if len(completed_query_ids) == len(queries) else "partial"
    )
    summary = _build_single_run_summary(
        scenario=scenario,
        config=config,
        evaluated_results=evaluated_results,
        stored_results=stored_results,
        failures=failures,
        checkpoint=checkpoint,
        profile_name=profile_name,
        index_manifest=index_manifest,
        index_manifest_ref=index_manifest_ref,
        planned_query_count=len(queries),
        completed_query_ids=completed_query_ids,
        failed_query_ids=failed_query_ids,
        suite_context=suite_context,
        replay_context=replay_context,
    )

    try:
        _show_evaluation_result(scenario, summary)
        exp_manager.save_result(
            actual_run_id,
            _serialize_summary(summary),
            f"{scenario.upper()}_result.json",
        )
        _update_checkpoint_failure_state(
            checkpoint,
            failures=failures,
            last_error_stage=str(checkpoint.get("last_error_stage", "")),
            status=str(checkpoint["status"]),
        )
        exp_manager.save_checkpoint(actual_run_id, checkpoint)
    except Exception as error:
        failure = _build_failure_record(
            scenario=scenario,
            query_id="",
            query_text="",
            stage="finalize",
            error=error,
            attempt_index=_next_failure_attempt_index(
                failures,
                query_id="",
                stage="finalize",
            ),
            environment_type=env,
            profile_name=profile_name,
            scenario_scope=str(index_manifest.get("scenario_scope", "")),
            dataset_scope=str(index_manifest.get("dataset_scope", "")),
            index_manifest_ref=index_manifest_ref,
            suite_context=suite_context,
            replay_context=replay_context,
            storage_sanitizer=storage_sanitizer,
            metadata={"attacker": attacker},
        )
        _append_failure_record(
            exp_manager=exp_manager,
            run_id=actual_run_id,
            scenario=scenario,
            failures=failures,
            failure=failure,
            checkpoint=checkpoint,
            checkpoint_status="failed_finalize",
        )
        summary = _build_single_run_summary(
            scenario=scenario,
            config=config,
            evaluated_results=evaluated_results,
            stored_results=stored_results,
            failures=failures,
            checkpoint=checkpoint,
            profile_name=profile_name,
            index_manifest=index_manifest,
            index_manifest_ref=index_manifest_ref,
            planned_query_count=len(queries),
            completed_query_ids=completed_query_ids,
            failed_query_ids=failed_query_ids,
            suite_context=suite_context,
            replay_context=replay_context,
        )
        try:
            exp_manager.save_result(
                actual_run_id,
                _serialize_summary(summary),
                f"{scenario.upper()}_result.json",
            )
        except Exception:
            pass
        return SingleRunOutcome(
            run_id=actual_run_id,
            scenario=scenario.upper(),
            environment_type=env,
            profile_name=profile_name,
            status="failed_finalize",
            summary=summary,
        )

    return SingleRunOutcome(
        run_id=actual_run_id,
        scenario=scenario.upper(),
        environment_type=env,
        profile_name=profile_name,
        status=str(checkpoint["status"]),
        summary=summary,
    )


def _execute_suite_run(
    *,
    base_config: dict[str, Any],
    base_exp_manager: Any,
    scenario: str | None,
    attacker: str,
    env: str,
    profile: str,
    all_envs: bool,
    all_profiles: bool,
    all_scenarios: bool,
    resume: str | None,
    config_path: str | None,
    single_run_executor: Callable[..., SingleRunOutcome] = _execute_single_run,
) -> str:
    """Run or resume a suite matrix under one parent run id."""
    if resume:
        suite_run_id = resume
        suite_manifest = base_exp_manager.load_suite_manifest(suite_run_id)
        suite_checkpoint = base_exp_manager.load_suite_checkpoint(suite_run_id)
        planned_cells = [
            _deserialize_suite_cell(item)
            for item in suite_manifest.get("planned_cells", [])
        ]
        attacker = str(suite_manifest.get("attacker", attacker))
    else:
        planned_cells = _build_suite_cells(
            scenario=scenario,
            env=env,
            profile=profile,
            all_envs=all_envs,
            all_profiles=all_profiles,
            all_scenarios=all_scenarios,
            config=base_config,
        )
        suite_run_id = base_exp_manager.create_run()
        suite_manifest = {
            "scenario_mode": "all" if all_scenarios else "single",
            "attacker": attacker,
            "scenarios": sorted({cell.scenario for cell in planned_cells}),
            "environments": sorted({cell.environment_type for cell in planned_cells}),
            "profiles": sorted({cell.profile_name for cell in planned_cells}),
            "planned_cells": [cell.to_dict() for cell in planned_cells],
            "status": "running",
        }
        base_exp_manager.save_snapshot(
            suite_run_id,
            base_config,
            metadata={"suite": suite_manifest},
        )
        base_exp_manager.save_suite_manifest(suite_run_id, suite_manifest)
        suite_checkpoint = {
            "scenario_mode": suite_manifest["scenario_mode"],
            "planned_cells": [cell.cell_id for cell in planned_cells],
            "completed_cells": [],
            "failed_cells": [],
            "status": "running",
        }
        base_exp_manager.save_suite_checkpoint(suite_run_id, suite_checkpoint)

    parent_run_dir = base_exp_manager.run_dir(suite_run_id)
    child_results_root = parent_run_dir / "runs"
    completed_cells = set(suite_checkpoint.get("completed_cells", []))
    failed_cells = set(suite_checkpoint.get("failed_cells", []))

    console.print(f"\n[cyan]Suite Run ID:[/cyan] [bold]{suite_run_id}[/bold]")
    console.print(f"[cyan]Planned cells:[/cyan] [bold]{len(planned_cells)}[/bold]")

    for index, cell in enumerate(planned_cells, start=1):
        if cell.cell_id in completed_cells:
            continue

        console.print(
            "\n[cyan]Cell " f"{index}/{len(planned_cells)}:[/cyan] " f"{cell.cell_id}"
        )
        child_config = load_config(config_path, profile=cell.profile_name)
        child_manager = _create_child_experiment_manager(
            child_config, child_results_root
        )
        child_resume = child_manager.checkpoint_path(cell.cell_id).exists()

        try:
            outcome = single_run_executor(
                child_config,
                scenario=cell.scenario,
                attacker=attacker,
                env=cell.environment_type,
                profile=cell.profile_name,
                exp_manager=child_manager,
                run_id=cell.cell_id,
                resume_existing=child_resume,
                snapshot_metadata={
                    "suite_run_id": suite_run_id,
                    "suite_cell_id": cell.cell_id,
                    "cell_environment": cell.environment_type,
                    "cell_profile_name": cell.profile_name,
                },
                suite_context={
                    "suite_run_id": suite_run_id,
                    "suite_cell_id": cell.cell_id,
                    "cell_environment": cell.environment_type,
                    "cell_profile_name": cell.profile_name,
                },
            )
            if outcome.status == "completed":
                completed_cells.add(cell.cell_id)
                failed_cells.discard(cell.cell_id)
            else:
                failed_cells.add(cell.cell_id)
        except Exception as error:
            failed_cells.add(cell.cell_id)
            suite_checkpoint["last_error"] = f"{cell.cell_id}: {error}"
            console.print(
                f"[yellow]Cell failed and was checkpointed:[/yellow] {cell.cell_id} ({error})"
            )

        suite_checkpoint["completed_cells"] = sorted(completed_cells)
        suite_checkpoint["failed_cells"] = sorted(failed_cells)
        suite_checkpoint["status"] = (
            "completed" if len(completed_cells) == len(planned_cells) else "partial"
        )
        base_exp_manager.save_suite_checkpoint(suite_run_id, suite_checkpoint)
        _refresh_suite_results(
            base_exp_manager,
            suite_run_id=suite_run_id,
            config=base_config,
        )

    suite_manifest["status"] = (
        "completed" if len(completed_cells) == len(planned_cells) else "partial"
    )
    base_exp_manager.save_suite_manifest(suite_run_id, suite_manifest)
    return suite_run_id


def _build_suite_cells(
    *,
    scenario: str | None,
    env: str,
    profile: str,
    all_envs: bool,
    all_profiles: bool,
    all_scenarios: bool,
    config: dict[str, Any],
) -> list[SuiteCell]:
    """Resolve the requested matrix axes into concrete suite cells."""
    matrix_config = config.get("experiment", {}).get("matrix", {})
    scenarios = (
        list(matrix_config.get("scenarios", ["R2", "R4", "R9"]))
        if all_scenarios
        else [str(scenario or "").upper()]
    )
    environments = (
        list(matrix_config.get("environments", ["clean", "poisoned"]))
        if all_envs
        else [env]
    )
    profiles = (
        list(matrix_config.get("profiles", ["reranker_off", "reranker_on"]))
        if all_profiles
        else [profile]
    )

    if not all_scenarios and not scenario:
        raise ValueError("`--scenario` is required when `--all-scenarios` is not used.")

    cells: list[SuiteCell] = []
    for scenario_name in scenarios:
        for environment_name in environments:
            for profile_name in profiles:
                cells.append(
                    SuiteCell(
                        scenario=str(scenario_name).upper(),
                        environment_type=str(environment_name),
                        profile_name=str(profile_name),
                    )
                )
    return cells


def _refresh_suite_results(
    exp_manager: Any,
    *,
    suite_run_id: str,
    config: dict[str, Any],
    suite_result_metadata: dict[str, Any] | None = None,
) -> None:
    """Aggregate child scenario results into parent suite artifacts."""
    child_run_dir = exp_manager.run_dir(suite_run_id) / "runs"
    child_payloads, child_failure_only = _load_child_artifacts(child_run_dir)

    for scenario in sorted(set(child_payloads) | set(child_failure_only)):
        scenario_payloads = child_payloads.get(scenario, [])
        results: list[AttackResult] = []
        failures = list(child_failure_only.get(scenario, []))
        for payload in scenario_payloads:
            results.extend(
                _deserialize_attack_result(item) for item in payload.get("results", [])
            )
            failures.extend(
                _deserialize_execution_failure(item)
                for item in payload.get("execution_failures", [])
            )

        summary = summarize_suite_results(
            scenario,
            config,
            results,
            child_payloads=scenario_payloads,
            execution_failures=failures,
        )
        if suite_result_metadata:
            summary.update(suite_result_metadata)
        exp_manager.save_result(
            suite_run_id,
            _serialize_summary(summary),
            f"{scenario.upper()}_result.json",
        )


def summarize_suite_results(
    scenario: str,
    config: dict[str, Any],
    results: list[AttackResult],
    *,
    child_payloads: list[dict[str, Any]] | None = None,
    execution_failures: list[ExecutionFailureRecord] | None = None,
) -> dict[str, Any]:
    """Build one aggregated scenario summary from many child runs."""
    from rag.evaluator.summary import summarize_evaluated_results

    payloads = child_payloads or []
    failures = execution_failures or []
    summary = summarize_evaluated_results(scenario, config, results)
    summary["results"] = results

    unique_profiles = sorted(
        {result.profile_name for result in results if result.profile_name}
    )
    unique_environments = sorted(
        {result.environment_type for result in results if result.environment_type}
    )
    unique_suite_ids = sorted(
        {result.suite_run_id for result in results if result.suite_run_id}
    )
    unique_query_ids = sorted(
        {result.query_id for result in results if result.query_id}
    )
    unique_dataset_scopes = sorted(
        {result.dataset_scope for result in results if result.dataset_scope}
    )
    unique_scenario_scopes = sorted(
        {result.scenario_scope for result in results if result.scenario_scope}
    )
    unique_selection_modes = sorted(
        {
            result.dataset_selection_mode
            for result in results
            if result.dataset_selection_mode
        }
    )
    unique_manifest_refs = sorted(
        {result.index_manifest_ref for result in results if result.index_manifest_ref}
    )
    unique_replay_sources = sorted(
        {
            result.replayed_from_run_id
            for result in results
            if result.replayed_from_run_id
        }
    )
    reranker_states = sorted(
        {
            str(result.metadata.get("reranker_state", ""))
            for result in results
            if result.metadata.get("reranker_state")
        }
    )
    payload_statuses = [str(payload.get("status", "completed")) for payload in payloads]
    failed_cell_ids = {
        failure.suite_cell_id for failure in failures if failure.suite_cell_id
    }
    if not unique_profiles:
        unique_profiles = sorted(
            {
                str(payload.get("profile_name", ""))
                for payload in payloads
                if payload.get("profile_name")
            }
        )
    if not unique_environments:
        unique_environments = sorted(
            {
                str(environment)
                for payload in payloads
                for environment in payload.get("suite_environments", [])
                if environment
            }
        )
    if not unique_dataset_scopes:
        unique_dataset_scopes = sorted(
            {
                str(payload.get("dataset_scope", ""))
                for payload in payloads
                if payload.get("dataset_scope")
            }
        )
    if not unique_scenario_scopes:
        unique_scenario_scopes = sorted(
            {
                str(payload.get("scenario_scope", ""))
                for payload in payloads
                if payload.get("scenario_scope")
            }
        )
    if not unique_selection_modes:
        unique_selection_modes = sorted(
            {
                str(payload.get("dataset_selection_mode", ""))
                for payload in payloads
                if payload.get("dataset_selection_mode")
            }
        )
    if not unique_manifest_refs:
        unique_manifest_refs = sorted(
            {
                str(payload.get("index_manifest_ref", ""))
                for payload in payloads
                if payload.get("index_manifest_ref")
            }
        )
    if not unique_suite_ids:
        unique_suite_ids = sorted(
            {
                str(payload.get("suite_run_id", ""))
                for payload in payloads
                if payload.get("suite_run_id")
            }
        )
    if not unique_replay_sources:
        unique_replay_sources = sorted(
            {
                str(payload.get("replayed_from_run_id", ""))
                for payload in payloads
                if payload.get("replayed_from_run_id")
            }
        )

    summary["profile_name"] = (
        unique_profiles[0] if len(unique_profiles) == 1 else "mixed"
    )
    summary["retrieval_config"] = (
        results[0].retrieval_config if len(unique_profiles) == 1 and results else {}
    )
    summary["reranker_state"] = (
        reranker_states[0] if len(reranker_states) == 1 else "mixed"
    )
    summary["completed_query_ids"] = unique_query_ids
    summary["failed_query_ids"] = sorted(
        {
            str(query_id)
            for payload in payloads
            for query_id in payload.get("failed_query_ids", [])
            if query_id
        }
    )
    summary["planned_query_count"] = sum(
        int(payload.get("planned_query_count", 0) or 0) for payload in payloads
    )
    summary["scenario_scope"] = (
        unique_scenario_scopes[0] if len(unique_scenario_scopes) == 1 else "mixed"
    )
    summary["dataset_scope"] = (
        unique_dataset_scopes[0] if len(unique_dataset_scopes) == 1 else "mixed"
    )
    summary["dataset_scopes"] = unique_dataset_scopes
    summary["dataset_selection_mode"] = (
        unique_selection_modes[0] if len(unique_selection_modes) == 1 else "mixed"
    )
    summary["index_manifest_ref"] = (
        unique_manifest_refs[0] if len(unique_manifest_refs) == 1 else ""
    )
    summary["index_manifest_refs"] = unique_manifest_refs
    summary["suite_run_id"] = unique_suite_ids[0] if len(unique_suite_ids) == 1 else ""
    summary["replayed_from_run_id"] = (
        unique_replay_sources[0] if len(unique_replay_sources) == 1 else ""
    )
    summary["suite_profiles"] = unique_profiles
    summary["suite_environments"] = unique_environments
    summary["execution_failures"] = failures
    summary["execution_failure_count"] = len(failures)
    summary["open_failure_count"] = sum(
        int(payload.get("open_failure_count", 0) or 0) for payload in payloads
    )
    summary["failure_stage_counts"] = _count_failure_stages(failures)
    if payload_statuses and len(set(payload_statuses)) == 1:
        summary["status"] = payload_statuses[0]
    elif any(
        status in {"failed_setup", "failed_finalize", "partial"}
        for status in payload_statuses
    ):
        summary["status"] = "partial"
    elif payload_statuses:
        summary["status"] = "completed"
    else:
        summary["status"] = "partial" if failures else "completed"
    summary["failed_cell_count"] = len(failed_cell_ids)
    return summary


def _load_child_artifacts(
    child_run_dir: Path,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, list[ExecutionFailureRecord]]]:
    """Load child summaries and failure-only artifacts from one suite."""
    payloads: dict[str, list[dict[str, Any]]] = {}
    failure_only: dict[str, list[ExecutionFailureRecord]] = {}
    if not child_run_dir.exists():
        return payloads, failure_only

    for child_dir in sorted(path for path in child_run_dir.iterdir() if path.is_dir()):
        result_files = sorted(child_dir.glob("*_result.json"))
        if result_files:
            for result_file in result_files:
                scenario = result_file.stem.replace("_result", "").upper()
                with open(result_file, "r", encoding="utf-8") as file:
                    payload = json.load(file)
                payloads.setdefault(scenario, []).append(payload)
            continue

        for failure_file in sorted(child_dir.glob("*_failures.json")):
            scenario = failure_file.stem.replace("_failures", "").upper()
            with open(failure_file, "r", encoding="utf-8") as file:
                payload = json.load(file)
            failure_only.setdefault(scenario, []).extend(
                _deserialize_execution_failure(item)
                for item in payload.get("failures", [])
            )

    return payloads, failure_only


def _create_child_experiment_manager(
    config: dict[str, Any], child_results_root: Path
) -> Any:
    """Create an ExperimentManager that stores under the suite child-run root."""
    from rag.utils.experiment import ExperimentManager

    return ExperimentManager(config, results_dir_override=child_results_root)


def _apply_index_context(
    result: AttackResult,
    *,
    index_manifest: dict[str, Any],
    index_manifest_ref: str,
) -> None:
    """Stamp dataset/index metadata onto one AttackResult."""
    result.scenario_scope = str(index_manifest.get("scenario_scope", ""))
    result.dataset_scope = str(index_manifest.get("dataset_scope", ""))
    result.dataset_selection_mode = str(
        index_manifest.get("dataset_selection_mode", "")
    )
    result.index_manifest_ref = index_manifest_ref
    result.metadata["scenario_scope"] = result.scenario_scope
    result.metadata["dataset_scope"] = result.dataset_scope
    result.metadata["dataset_selection_mode"] = result.dataset_selection_mode
    result.metadata["index_manifest_ref"] = index_manifest_ref


def _apply_suite_context(
    result: AttackResult,
    *,
    suite_context: dict[str, str] | None,
    env: str,
    profile: str,
) -> None:
    """Stamp suite metadata onto a single AttackResult."""
    if not suite_context:
        return

    result.suite_run_id = suite_context.get("suite_run_id", "")
    result.suite_cell_id = suite_context.get("suite_cell_id", "")
    result.cell_environment = suite_context.get("cell_environment", env)
    result.cell_profile_name = suite_context.get("cell_profile_name", profile)
    result.metadata["suite_run_id"] = result.suite_run_id
    result.metadata["suite_cell_id"] = result.suite_cell_id
    result.metadata["cell_environment"] = result.cell_environment
    result.metadata["cell_profile_name"] = result.cell_profile_name


def _apply_replay_context(
    result: AttackResult,
    *,
    replay_context: dict[str, Any] | None,
) -> None:
    """Stamp replay metadata onto a single AttackResult."""
    if not replay_context:
        return

    result.replayed_from_run_id = str(replay_context.get("replayed_from_run_id", ""))
    result.metadata["replayed_from_run_id"] = result.replayed_from_run_id
    if "compatibility_mode" in replay_context:
        result.metadata["compatibility_mode"] = bool(
            replay_context["compatibility_mode"]
        )


def _resolve_replay_config(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return the resolved config embedded in a saved snapshot."""
    config = snapshot.get("config")
    if not isinstance(config, dict) or not config:
        raise ValueError("Replay requires a saved config block in snapshot.yaml.")
    return copy.deepcopy(config)


def _infer_single_run_scenario(run_dir: Path) -> str:
    """Fallback to result filenames when legacy snapshots miss runtime.scenario."""
    for pattern in ("*_result.json", "*_partial.json"):
        for artifact in sorted(run_dir.glob(pattern)):
            scenario = artifact.stem.split("_", 1)[0].upper()
            if scenario in {"R2", "R4", "R9"}:
                return scenario
    return ""


def _validate_replay_index_artifact(snapshot: dict[str, Any]) -> bool:
    """Verify that the persisted index manifest still matches the saved snapshot."""
    from rag.utils.experiment import fingerprint_payload

    manifest_ref = str(
        snapshot.get("index_manifest_ref")
        or snapshot.get("provenance", {}).get("index_manifest_ref")
        or ""
    )
    if not manifest_ref:
        raise ValueError("Replay requires index_manifest_ref in snapshot.yaml.")

    manifest_path = _resolve_existing_path(
        manifest_ref, label="Persisted index manifest"
    )
    with open(manifest_path, "r", encoding="utf-8") as file:
        current_manifest = json.load(file)

    expected_hash = str(snapshot.get("provenance", {}).get("index_manifest_hash") or "")
    if not expected_hash:
        saved_manifest = snapshot.get("index_manifest")
        if isinstance(saved_manifest, dict) and saved_manifest:
            expected_hash = fingerprint_payload(saved_manifest)
    if not expected_hash:
        raise ValueError(
            "Replay requires a saved index_manifest or provenance.index_manifest_hash."
        )

    current_hash = fingerprint_payload(current_manifest)
    if current_hash != expected_hash:
        raise ValueError(
            "Replay index manifest does not match the saved snapshot "
            f"for {manifest_path}."
        )
    return True


def _resolve_existing_path(path_value: str, *, label: str) -> Path:
    """Resolve a local path and require that it exists."""
    candidate = Path(path_value).expanduser()
    if not candidate.is_absolute():
        candidate = Path(__file__).resolve().parents[3] / candidate
    candidate = candidate.resolve()
    if not candidate.exists():
        raise FileNotFoundError(f"{label} not found: {candidate}")
    return candidate


def _deserialize_suite_cell(payload: dict[str, Any]) -> SuiteCell:
    """Hydrate a SuiteCell from saved JSON."""
    return SuiteCell(
        scenario=str(payload.get("scenario", "")).upper(),
        environment_type=str(payload.get("environment_type", "")),
        profile_name=str(payload.get("profile_name", "")),
    )


def _create_evaluator(scenario: str, config: dict[str, Any]) -> Any:
    """Instantiate the scenario-specific evaluator."""
    scenario_upper = scenario.upper()
    if scenario_upper == "R2":
        from rag.evaluator.r2_evaluator import R2Evaluator

        return R2Evaluator(config)
    if scenario_upper == "R4":
        from rag.evaluator.r4_evaluator import R4Evaluator

        return R4Evaluator(config)
    if scenario_upper == "R9":
        from rag.evaluator.r9_evaluator import R9Evaluator

        return R9Evaluator(config)
    raise ValueError(f"Unsupported scenario: {scenario}")


def _deserialize_execution_failure(payload: dict[str, Any]) -> ExecutionFailureRecord:
    """Hydrate one execution failure dataclass from stored JSON."""
    return ExecutionFailureRecord(**payload)


def _serialize_value(value: Any) -> Any:
    """Recursively convert dataclasses into plain JSON-safe objects."""
    if is_dataclass(value):
        return {key: _serialize_value(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {key: _serialize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    return value


def _count_failure_stages(
    failures: list[ExecutionFailureRecord],
) -> dict[str, int]:
    """Count failures by execution stage."""
    counts: dict[str, int] = {}
    for failure in failures:
        stage = str(failure.stage or "unknown")
        counts[stage] = counts.get(stage, 0) + 1
    return counts


def _compute_open_failure_count(
    *,
    failed_query_ids: set[str] | list[str],
    status: str,
) -> int:
    """Return unresolved failure count without mutating failure history."""
    open_failures = len(set(failed_query_ids))
    if status in {"failed_setup", "failed_finalize"}:
        open_failures += 1
    return open_failures


def _next_failure_attempt_index(
    failures: list[ExecutionFailureRecord],
    *,
    query_id: str,
    stage: str,
) -> int:
    """Return the next append-only attempt index for one query/stage tuple."""
    return (
        sum(
            1
            for failure in failures
            if failure.query_id == query_id and failure.stage == stage
        )
        + 1
    )


def _update_checkpoint_failure_state(
    checkpoint: dict[str, Any],
    *,
    failures: list[ExecutionFailureRecord],
    last_error_stage: str = "",
    status: str | None = None,
) -> None:
    """Refresh checkpoint failure bookkeeping fields."""
    checkpoint["failure_attempt_count"] = len(failures)
    checkpoint["failure_stage_counts"] = _count_failure_stages(failures)
    checkpoint["last_error_stage"] = last_error_stage or checkpoint.get(
        "last_error_stage", ""
    )
    if status is not None:
        checkpoint["status"] = status


def _build_failure_record(
    *,
    scenario: str,
    query_id: str,
    query_text: str,
    stage: str,
    error: Exception,
    attempt_index: int,
    environment_type: str,
    profile_name: str,
    scenario_scope: str,
    dataset_scope: str,
    index_manifest_ref: str,
    suite_context: dict[str, str] | None,
    replay_context: dict[str, Any] | None,
    storage_sanitizer: Any,
    metadata: dict[str, Any] | None = None,
) -> ExecutionFailureRecord:
    """Create one masked execution failure record."""
    failure = ExecutionFailureRecord(
        scenario=scenario.upper(),
        query_id=query_id,
        query_masked=query_text,
        stage=stage,
        error_type=type(error).__name__,
        error_message_masked=str(error),
        attempt_index=attempt_index,
        environment_type=environment_type,
        profile_name=profile_name,
        scenario_scope=scenario_scope,
        dataset_scope=dataset_scope,
        index_manifest_ref=index_manifest_ref,
        suite_run_id=(suite_context or {}).get("suite_run_id", ""),
        suite_cell_id=(suite_context or {}).get("suite_cell_id", ""),
        replayed_from_run_id=str(
            (replay_context or {}).get("replayed_from_run_id", "")
        ),
        failed_at=datetime.now().isoformat(),
        metadata=dict(metadata or {}),
    )
    return storage_sanitizer.sanitize_failure(failure)


def _append_failure_record(
    *,
    exp_manager: Any,
    run_id: str,
    scenario: str,
    failures: list[ExecutionFailureRecord],
    failure: ExecutionFailureRecord,
    checkpoint: dict[str, Any],
    checkpoint_status: str,
) -> None:
    """Append, persist, and checkpoint one failure record."""
    failures.append(failure)
    checkpoint["last_error"] = (
        f"{failure.query_id or failure.stage}: {failure.error_type} - "
        f"{failure.error_message_masked}"
    )
    _update_checkpoint_failure_state(
        checkpoint,
        failures=failures,
        last_error_stage=failure.stage,
        status=checkpoint_status,
    )
    exp_manager.save_partial_failures(
        run_id,
        scenario,
        [_serialize_value(item) for item in failures],
    )
    exp_manager.save_checkpoint(run_id, checkpoint)


def _build_single_run_summary(
    *,
    scenario: str,
    config: dict[str, Any],
    evaluated_results: list[AttackResult],
    stored_results: list[AttackResult],
    failures: list[ExecutionFailureRecord],
    checkpoint: dict[str, Any],
    profile_name: str,
    index_manifest: dict[str, Any] | None,
    index_manifest_ref: str,
    planned_query_count: int,
    completed_query_ids: set[str],
    failed_query_ids: set[str],
    suite_context: dict[str, str] | None,
    replay_context: dict[str, Any] | None,
) -> dict[str, Any]:
    """Build one final or failure-only single-run summary payload."""
    from rag.evaluator.summary import summarize_evaluated_results

    manifest = index_manifest or {}
    summary = summarize_evaluated_results(scenario, config, evaluated_results)
    summary["results"] = stored_results
    summary["profile_name"] = profile_name
    summary["retrieval_config"] = config.get("retrieval_config", {})
    summary["reranker_state"] = (
        "on"
        if config.get("retrieval_config", {}).get("reranker", {}).get("enabled")
        else "off"
    )
    summary["scenario_scope"] = manifest.get(
        "scenario_scope", checkpoint.get("scenario_scope", "")
    )
    summary["dataset_scope"] = manifest.get(
        "dataset_scope", checkpoint.get("dataset_scope", "")
    )
    summary["dataset_selection_mode"] = manifest.get("dataset_selection_mode", "")
    summary["doc_selection_summary"] = manifest.get("doc_selection_summary", {})
    summary["index_manifest_ref"] = index_manifest_ref
    summary["completed_query_ids"] = sorted(completed_query_ids)
    summary["failed_query_ids"] = sorted(failed_query_ids)
    summary["planned_query_count"] = planned_query_count
    summary["execution_failures"] = failures
    summary["execution_failure_count"] = len(failures)
    summary["open_failure_count"] = _compute_open_failure_count(
        failed_query_ids=failed_query_ids,
        status=str(checkpoint.get("status", "")),
    )
    summary["failure_stage_counts"] = _count_failure_stages(failures)
    summary["status"] = str(checkpoint.get("status", "running"))
    if suite_context:
        summary.update(suite_context)
    if replay_context:
        summary.update(replay_context)
    return summary


def _deserialize_attack_result(payload: dict[str, Any]) -> AttackResult:
    """Hydrate an AttackResult dataclass from stored JSON."""
    return AttackResult(**payload)


def _validate_resume_request(
    *,
    checkpoint: dict[str, Any],
    snapshot: dict[str, Any],
    scenario: str,
    attacker: str,
    env: str,
    profile_name: str,
) -> None:
    """Validate that the resume request matches the saved run context."""
    mismatches: list[str] = []

    if checkpoint.get("scenario") != scenario.upper():
        mismatches.append("scenario")
    if checkpoint.get("attacker") != attacker:
        mismatches.append("attacker")
    if checkpoint.get("environment_type") != env:
        mismatches.append("environment_type")
    if checkpoint.get("profile_name") != profile_name:
        mismatches.append("profile_name")
    if checkpoint.get("scenario_scope") not in (None, "", scenario.upper(), "base"):
        # Older checkpoints may not store scenario_scope, and clean runs resolve to base.
        expected_scope = "base" if env == "clean" else scenario.upper()
        if checkpoint.get("scenario_scope") != expected_scope:
            mismatches.append("scenario_scope")

    snapshot_profile = snapshot.get("config", {}).get("profile_name")
    if snapshot_profile and snapshot_profile != profile_name:
        mismatches.append("snapshot.profile_name")

    if mismatches:
        mismatch_list = ", ".join(mismatches)
        raise ValueError(
            f"Resume request does not match the saved run context: {mismatch_list}"
        )


def _infer_environment_from_doc_path(doc_path: str) -> str:
    """Infer the environment for rag query when the CLI does not receive --env."""
    resolved = Path(doc_path)
    name = resolved.name.lower()
    if name in {"clean", "poisoned"}:
        return name
    if (resolved / "clean").exists():
        return "clean"
    if (resolved / "poisoned").exists():
        return "poisoned"
    return "clean"


def _require_scenario_for_poisoned(env: str, scenario: str | None) -> None:
    """Enforce explicit poisoned scenario selection at the CLI layer."""
    if str(env).lower() == "poisoned" and not scenario:
        raise ValueError(
            "`--scenario R2|R4|R9` is required when `--env poisoned` is used."
        )


def _resolve_cli_scenario_scope(env: str, scenario: str | None) -> str:
    """Render the effective scenario scope shown in the CLI."""
    return "base" if str(env).lower() == "clean" else str(scenario or "").upper()


def _show_evaluation_result(scenario: str, summary: dict[str, Any]) -> None:
    """Render a compact evaluation summary in the terminal."""
    scenario_upper = scenario.upper()

    table = Table(title=f"{scenario_upper} Evaluation", show_header=True)
    table.add_column("Metric", style="cyan", width=24)
    table.add_column("Value", style="green")
    table.add_row("Total executions", str(summary.get("total", 0)))
    table.add_row("Completed queries", str(len(summary.get("completed_query_ids", []))))
    table.add_row("Failed queries", str(len(summary.get("failed_query_ids", []))))
    table.add_row("Execution failures", str(summary.get("execution_failure_count", 0)))
    table.add_row("Open failures", str(summary.get("open_failure_count", 0)))
    table.add_row("Run status", str(summary.get("status", "unknown")))

    if scenario_upper == "R2":
        table.add_row("Success count", str(summary.get("success_count", 0)))
        table.add_row("Success rate", f"{summary.get('success_rate', 0):.2%}")
        table.add_row("Average ROUGE-L", f"{summary.get('avg_score', 0):.4f}")
        table.add_row("Max ROUGE-L", f"{summary.get('max_score', 0):.4f}")
        table.add_row("Threshold", str(summary.get("threshold", "N/A")))
    elif scenario_upper == "R4":
        table.add_row("Hit count", str(summary.get("hit_count", 0)))
        table.add_row("Hit rate", f"{summary.get('hit_rate', 0):.2%}")
        table.add_row("Member hit rate", f"{summary.get('member_hit_rate', 0):.2%}")
        table.add_row(
            "Non-member hit rate",
            f"{summary.get('non_member_hit_rate', 0):.2%}",
        )
        table.add_row(
            "Inference success",
            "yes" if summary.get("is_inference_successful", False) else "no",
        )
    elif scenario_upper == "R9":
        table.add_row("Success count", str(summary.get("success_count", 0)))
        table.add_row("Success rate", f"{summary.get('success_rate', 0):.2%}")
        for trigger, stats in summary.get("by_trigger", {}).items():
            table.add_row(
                f"Trigger {trigger[:20]}",
                f"{stats.get('success', 0)}/{stats.get('total', 0)} ({stats.get('rate', 0):.2%})",
            )

    console.print()
    console.print(Panel(table, title="[bold blue]Evaluation Summary[/bold blue]"))


def _serialize_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Convert dataclass results into JSON-serializable dictionaries."""
    return _serialize_value(summary)


def _show_run_info(
    scenario: str,
    attacker: str,
    env: str,
    profile: str,
    *,
    resume: str | None = None,
) -> None:
    """Render the selected run configuration before execution starts."""
    table = Table(title="Run Configuration", show_header=True)
    table.add_column("Field", style="cyan", width=16)
    table.add_column("Value", style="green")
    table.add_row("Scenario", scenario.upper())
    table.add_row("Attacker", attacker)
    table.add_row("Environment", env)
    table.add_row("Profile", profile)
    table.add_row("Resume", resume or "new run")

    console.print()
    console.print(Panel(table, title="[bold blue]RAG Run[/bold blue]"))


def _show_suite_run_info(
    *,
    scenario: str | None,
    attacker: str,
    env: str,
    profile: str,
    all_envs: bool,
    all_profiles: bool,
    all_scenarios: bool,
    resume: str | None,
) -> None:
    """Render suite-mode configuration before execution starts."""
    table = Table(title="Suite Configuration", show_header=True)
    table.add_column("Field", style="cyan", width=18)
    table.add_column("Value", style="green")
    table.add_row("Scenario", "ALL" if all_scenarios else (scenario or "N/A"))
    table.add_row("Attacker", attacker)
    table.add_row("Environment", "ALL" if all_envs else env)
    table.add_row("Profile", "ALL" if all_profiles else profile)
    table.add_row("Resume", resume or "new suite")

    console.print()
    console.print(Panel(table, title="[bold blue]RAG Suite[/bold blue]"))


def _run_auto_report(run_id: str, config: dict[str, Any]) -> None:
    """실험 완료 후 자동으로 리포트를 생성하는 내부 헬퍼 함수.

    Args:
      run_id: 리포트를 생성할 실험 실행 ID
      config: 현재 실험 설정 딕셔너리 (ReportGenerator에 전달됨)
    """
    from rag.report.generator import ReportGenerator

    console.print(
        Panel(
            f"[bold]Auto Report 생성 중...[/bold]\nRun ID: {run_id}",
            title="[blue]RAG Report[/blue]",
        )
    )

    report_gen = ReportGenerator(config)
    try:
        generated_files = report_gen.generate(run_id)
    except FileNotFoundError as error:
        console.print(
            f"\n[yellow]Auto report 생성 실패 (실험 결과는 저장됨): {error}[/yellow]"
        )
        return

    table = Table(title="Generated Files", show_header=True)
    table.add_column("Format", style="cyan", width=10)
    table.add_column("Path", style="green")

    for fmt, path in generated_files.items():
        table.add_row(fmt.upper(), str(path))

    console.print()
    console.print(table)
    console.print(
        f"\n[green]리포트 자동 생성 완료.[/green] "
        f"[bold]{len(generated_files)}[/bold]개 파일이 생성되었습니다."
    )


if __name__ == "__main__":
    app()
