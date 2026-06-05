from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table

from mylilpwny.config import Config
from mylilpwny.core.deps import check_all, missing_required
from mylilpwny.core.orchestrator import Orchestrator
from mylilpwny.core.scope import ScopeValidator
from mylilpwny.logging import get_logger, setup_logging, setup_run_logging
from mylilpwny.persistence.db import setup_database
from mylilpwny.persistence.session import SessionManager
from mylilpwny.reporting.report import build_report_data, console_summary, to_json, to_markdown

app = typer.Typer(
    name="mylilpwny",
    help="Autonomous pentest and bug bounty agent.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

console = Console()

_VERSION = "0.1.0"


class AppContext:
    def __init__(
        self,
        target: str | None,
        scope_file: Path | None,
        config: Config,
        dry_run: bool,
        output: Path,
        scope: ScopeValidator,
        session_manager: SessionManager,
        verbose: bool,
    ) -> None:
        self.target = target
        self.scope_file = scope_file
        self.config = config
        self.dry_run = dry_run
        self.output = output
        self.scope = scope
        self.session_manager = session_manager
        self.verbose = verbose


@app.callback()
def main(
    ctx: typer.Context,
    target: Annotated[Optional[str], typer.Option("--target", "-t", help="Target IP, hostname, or CIDR")] = None,
    scope_file: Annotated[Optional[Path], typer.Option("--scope-file", help="Path to scope file")] = None,
    config_path: Annotated[Path, typer.Option("--config", "-c", help="Path to config.yaml")] = Path("config.yaml"),
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Plan actions without executing them")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Show detailed logs in terminal")] = False,
) -> None:
    ctx.ensure_object(dict)
    try:
        cfg = Config.load(config_path)
    except FileNotFoundError:
        cfg = Config()

    if output:
        cfg.output_dir = str(output)
    if scope_file:
        cfg.scope_file = str(scope_file)

    # Console log level: WARNING by default, DEBUG with --verbose
    setup_logging(verbose=verbose)

    if scope_file:
        scope = ScopeValidator.from_file(scope_file)
    elif target:
        scope = ScopeValidator.from_target(target)
    else:
        scope = ScopeValidator([])

    _, factory = setup_database(Path(cfg.output_dir) / "mylilpwny.db")
    sm = SessionManager(factory)

    ctx.obj = AppContext(
        target=target,
        scope_file=scope_file,
        config=cfg,
        dry_run=dry_run,
        output=Path(cfg.output_dir),
        scope=scope,
        session_manager=sm,
        verbose=verbose,
    )


@app.command()
def run(
    ctx: typer.Context,
    target: Annotated[Optional[str], typer.Option("--target", "-t", help="Override global target")] = None,
    skip: Annotated[Optional[str], typer.Option("--skip", help="Comma-separated stages to skip")] = None,
    stages: Annotated[Optional[str], typer.Option("--stages", help="Comma-separated stages to run (default: all)")] = None,
    objective: Annotated[Optional[str], typer.Option("--objective", help="Session objective label (e.g. vuln-scan, full-recon)")] = None,
    resume: Annotated[Optional[str], typer.Option("--resume", help="Resume a previous session by ID")] = None,
    dry_run: Annotated[Optional[bool], typer.Option("--dry-run/--no-dry-run", help="Override global dry-run flag")] = None,
) -> None:
    """Run the full recon → scan → enum → analysis pipeline."""
    obj: AppContext = ctx.obj
    # Local --dry-run overrides global if explicitly set
    effective_dry_run = dry_run if dry_run is not None else obj.dry_run
    effective_target = target or obj.target

    if not effective_target and not resume:
        console.print("[red]Error:[/red] --target is required for run.")
        raise typer.Exit(1)

    # Add file handler for this run without reconfiguring structlog
    run_dir = setup_run_logging(obj.output, verbose=obj.verbose)

    lg = get_logger("run")

    # Resolve session: resume existing or create new
    session_id: str
    if resume:
        existing = obj.session_manager.get_session(resume)
        if existing is None:
            console.print(f"[red]Error:[/red] Session [cyan]{resume}[/cyan] not found.")
            raise typer.Exit(1)
        session_id = resume
        if not effective_target:
            targets_db = obj.session_manager.get_targets(session_id)
            if targets_db:
                effective_target = ",".join(t.input for t in targets_db)
            else:
                console.print("[red]Error:[/red] Cannot resume: no targets found in session.")
                raise typer.Exit(1)
        console.print(f"[yellow]Resuming session[/yellow] [cyan]{session_id}[/cyan]")
    else:
        session_id = obj.session_manager.create_session(
            scope=obj.scope.entries,
            config_snapshot=obj.config.model_dump(),
            objective=objective,
        )

    lg.info("run started", target=effective_target, dry_run=effective_dry_run,
            session_id=session_id, run_dir=str(run_dir))

    border = "yellow" if effective_dry_run else "green"
    label = "DRY RUN\n\n" if effective_dry_run else ""
    console.print(Panel(
        Text.from_markup(
            f"[bold]{label}[/bold]"
            f"Target  : [cyan]{effective_target}[/cyan]\n"
            f"Session : [dim]{session_id}[/dim]\n"
            f"Mode    : [yellow]{obj.config.mode}[/yellow]\n"
            f"Output  : {obj.output}"
            + ("\n\n[dim]No tools will be executed.[/dim]" if effective_dry_run else "")
        ),
        title="mylilpwny run",
        border_style=border,
    ))

    skip_list = [s.strip() for s in skip.split(",")] if skip else None
    stages_list = [s.strip() for s in stages.split(",")] if stages else None

    orchestrator = Orchestrator(obj.config, obj.scope, session_manager=obj.session_manager)
    results = asyncio.run(orchestrator.run(
        effective_target,  # type: ignore[arg-type]
        stages=stages_list,
        skip=skip_list,
        dry_run=effective_dry_run,
        session_id=session_id,
    ))

    success = sum(1 for r in results if r.success)
    final_status = "complete" if success == len(results) else "partial"
    obj.session_manager.update_status(session_id, final_status)

    try:
        report_data = build_report_data(obj.session_manager, session_id)
        summary = console_summary(report_data)
        console.print(Panel(
            summary,
            title=f"[bold]Run complete[/bold] — {success}/{len(results)} targets",
            border_style="green" if success == len(results) else "yellow",
        ))
    except Exception:
        console.print(f"\n[bold]Done.[/bold] {success}/{len(results)} targets completed.")

    console.print(f"Session: [cyan]{session_id}[/cyan]")


@app.command()
def scan(
    ctx: typer.Context,
    target: Annotated[Optional[str], typer.Option("--target", "-t", help="Override global target")] = None,
    module: Annotated[str, typer.Option("--module", "-m", help="Module to run (recon, portscan, servicenum, vulnanalysis)")] = "recon",
) -> None:
    """Run a single scan module against a target."""
    obj: AppContext = ctx.obj
    effective_target = target or obj.target

    if not effective_target:
        console.print("[red]Error:[/red] --target is required for scan.")
        raise typer.Exit(1)

    prefix = "[yellow]DRY RUN[/yellow] " if obj.dry_run else ""
    console.print(f"{prefix}Running module [bold]{module}[/bold] against [cyan]{effective_target}[/cyan]")

    if obj.dry_run:
        console.print("[dim]No tools will be executed.[/dim]")
    else:
        console.print("[dim]Use 'run' to execute the full pipeline.[/dim]")


@app.command()
def exploit(
    ctx: typer.Context,
    target: Annotated[Optional[str], typer.Option("--target", "-t", help="Override global target")] = None,
    module: Annotated[Optional[str], typer.Option("--module", "-m", help="MSF module path (e.g. exploit/multi/handler)")] = None,
    port: Annotated[int, typer.Option("--port", "-p", help="Target port")] = 0,
    service: Annotated[Optional[str], typer.Option("--service", help="Service keyword to search MSF modules")] = None,
    confirm: Annotated[bool, typer.Option("--confirm", help="Required to actually execute an exploit")] = False,
    msf_password: Annotated[str, typer.Option("--msf-password", help="msfrpcd password", envvar="MSF_PASSWORD")] = "",
) -> None:
    """List or execute Metasploit exploit modules. Execution requires --confirm."""
    obj: AppContext = ctx.obj
    effective_target = target or obj.target

    if not effective_target:
        console.print("[red]Error:[/red] --target is required.")
        raise typer.Exit(1)

    if module and not confirm:
        console.print("[red]Error:[/red] --confirm is required to execute an exploit.")
        console.print("[dim]Use --confirm only against targets you own or have explicit written permission to test.[/dim]")
        raise typer.Exit(1)

    if obj.dry_run:
        console.print(f"[yellow]DRY RUN[/yellow] exploit module={module or '(list)'} target={effective_target}")
        return

    get_logger("exploit").warning("exploit command invoked",
                                  target=effective_target, module=module, confirmed=confirm)
    console.print("[dim]Exploit module not yet wired to pipeline — use the module API directly.[/dim]")


@app.command()
def report(
    ctx: typer.Context,
    session_id: Annotated[Optional[str], typer.Option("--session", "-s", help="Session ID to report on")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="Output format: json, markdown")] = "markdown",
    save: Annotated[bool, typer.Option("--save/--no-save", help="Save report to output/reports/")] = True,
) -> None:
    """Generate a report for a session."""
    obj: AppContext = ctx.obj

    if not session_id:
        # Default to most recent session
        rows = obj.session_manager.list_sessions(limit=1)
        if not rows:
            console.print("[red]Error:[/red] No sessions found. Run a scan first.")
            raise typer.Exit(1)
        session_id = rows[0].id
        console.print(f"[dim]Using most recent session: {session_id}[/dim]")

    try:
        data = build_report_data(obj.session_manager, session_id)
    except ValueError as e:
        console.print(f"[red]Error:[/red] {e}")
        raise typer.Exit(1)

    if fmt == "json":
        output_text = to_json(data)
    elif fmt in ("markdown", "md"):
        output_text = to_markdown(data)
    else:
        console.print(f"[red]Error:[/red] Unknown format '{fmt}'. Use json or markdown.")
        raise typer.Exit(1)

    console.print(output_text)

    if save:
        ext = "json" if fmt == "json" else "md"
        out_file = obj.output / "reports" / f"{session_id}.{ext}"
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(output_text)
        console.print(f"\n[dim]Saved to {out_file}[/dim]")


@app.command("check-deps")
def check_deps() -> None:
    """Check which external tools are installed."""
    statuses = check_all()

    table = Table(title="External tool dependencies", show_lines=False)
    table.add_column("Tool", style="bold")
    table.add_column("Status")
    table.add_column("Type")
    table.add_column("Path / Hint")

    for s in statuses:
        if s.installed:
            status = "[green]✓ installed[/green]"
            detail = f"[dim]{s.path}[/dim]"
        else:
            status = "[red]✗ missing[/red]"
            detail = f"[yellow]{s.spec.install_hint}[/yellow]"

        kind = "[red]required[/red]" if s.spec.required else "[dim]optional[/dim]"
        table.add_row(s.spec.name, status, kind, detail)

    console.print(table)

    absent = missing_required(statuses)
    if absent:
        names = ", ".join(s.spec.name for s in absent)
        console.print(f"\n[red]Error:[/red] required tools missing: {names}")
        raise typer.Exit(1)
    else:
        console.print("\n[green]All required tools are installed.[/green]")


@app.command("sessions")
def list_sessions(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max sessions to show")] = 20,
) -> None:
    """List recent pentest sessions."""
    obj: AppContext = ctx.obj
    rows = obj.session_manager.list_sessions_with_counts(limit=limit)
    if not rows:
        console.print("[dim]No sessions found.[/dim]")
        return

    table = Table(title="Sessions", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Created", style="dim")
    table.add_column("Status")
    table.add_column("Objective")
    table.add_column("Targets", justify="right")

    for s, count in rows:
        status_style = {"running": "yellow", "complete": "green", "partial": "blue"}.get(
            s.status, "dim"
        )
        table.add_row(
            s.id,
            s.created_at.strftime("%Y-%m-%d %H:%M") if s.created_at else "—",
            f"[{status_style}]{s.status}[/{status_style}]",
            s.objective or "—",
            str(count),
        )
    console.print(table)


@app.command("log")
def audit_log(
    ctx: typer.Context,
    session_id: Annotated[str, typer.Argument(help="Session ID")],
) -> None:
    """Show the audit log for a session."""
    obj: AppContext = ctx.obj
    entries = obj.session_manager.get_audit_log(session_id)
    if not entries:
        console.print(f"[dim]No audit entries for session {session_id}.[/dim]")
        return

    table = Table(title=f"Audit log — {session_id}", show_lines=False)
    table.add_column("Timestamp", style="dim", no_wrap=True)
    table.add_column("Event", style="bold")
    table.add_column("Target")
    table.add_column("Module")
    table.add_column("Detail")

    for e in entries:
        table.add_row(
            e.timestamp.strftime("%H:%M:%S") if e.timestamp else "—",
            e.event_type,
            e.target or "—",
            e.module or "—",
            str(e.detail) if e.detail else "—",
        )
    console.print(table)


@app.command()
def version() -> None:
    """Show version and exit."""
    console.print(f"[bold]mylilpwny[/bold] v{_VERSION}")


if __name__ == "__main__":
    app()
