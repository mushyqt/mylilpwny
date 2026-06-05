from __future__ import annotations

from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from mylilpwny.config import Config
from mylilpwny.core.scope import ScopeValidator
from mylilpwny.logging import get_logger, setup_logging

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
    ) -> None:
        self.target = target
        self.scope_file = scope_file
        self.config = config
        self.dry_run = dry_run
        self.output = output
        self.scope = scope


@app.callback()
def main(
    ctx: typer.Context,
    target: Annotated[Optional[str], typer.Option("--target", "-t", help="Target IP, hostname, or CIDR")] = None,
    scope_file: Annotated[Optional[Path], typer.Option("--scope-file", help="Path to scope file")] = None,
    config_path: Annotated[Path, typer.Option("--config", "-c", help="Path to config.yaml")] = Path("config.yaml"),
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Plan actions without executing them")] = False,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable debug logging")] = False,
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

    setup_logging(level="DEBUG" if verbose else "INFO")

    if scope_file:
        scope = ScopeValidator.from_file(scope_file)
    elif target:
        scope = ScopeValidator.from_target(target)
    else:
        scope = ScopeValidator([])

    ctx.obj = AppContext(
        target=target,
        scope_file=scope_file,
        config=cfg,
        dry_run=dry_run,
        output=Path(cfg.output_dir),
        scope=scope,
    )


@app.command()
def run(
    ctx: typer.Context,
    target: Annotated[Optional[str], typer.Option("--target", "-t", help="Override global target")] = None,
) -> None:
    """Run the full recon → scan → enum → analysis pipeline."""
    obj: AppContext = ctx.obj
    log = get_logger("run")
    effective_target = target or obj.target

    if not effective_target:
        console.print("[red]Error:[/red] --target is required for run.")
        raise typer.Exit(1)

    run_dir = setup_logging(obj.output, level="DEBUG" if False else "INFO")
    log.info("run started", target=effective_target, dry_run=obj.dry_run, run_dir=str(run_dir))

    if obj.dry_run:
        console.print(Panel(
            Text.from_markup(
                f"[bold]DRY RUN[/bold]\n\n"
                f"Target : [cyan]{effective_target}[/cyan]\n"
                f"Mode   : [yellow]{obj.config.mode}[/yellow]\n"
                f"Output : {obj.output}\n\n"
                "[dim]No tools will be executed.[/dim]"
            ),
            title="mylilpwny run",
            border_style="yellow",
        ))
        log.info("dry run complete — no tools executed")
    else:
        console.print(Panel(
            Text.from_markup(
                f"Target : [cyan]{effective_target}[/cyan]\n"
                f"Mode   : [yellow]{obj.config.mode}[/yellow]\n"
                f"Output : {obj.output}"
            ),
            title="mylilpwny run",
            border_style="green",
        ))
        log.info("pipeline not yet implemented")
        console.print("[dim]Pipeline not yet implemented — coming in Sprint 2+.[/dim]")


@app.command()
def scan(
    ctx: typer.Context,
    target: Annotated[Optional[str], typer.Option("--target", "-t", help="Override global target")] = None,
    module: Annotated[str, typer.Option("--module", "-m", help="Module to run (recon, portscan, servicenum, vulnanalysis)")] = "recon",
) -> None:
    """Run a single scan module against a target."""
    obj: AppContext = ctx.obj
    log = get_logger("scan")
    effective_target = target or obj.target

    if not effective_target:
        console.print("[red]Error:[/red] --target is required for scan.")
        raise typer.Exit(1)

    log.info("scan started", module=module, target=effective_target, dry_run=obj.dry_run)
    prefix = "[yellow]DRY RUN[/yellow] " if obj.dry_run else ""
    console.print(f"{prefix}Running module [bold]{module}[/bold] against [cyan]{effective_target}[/cyan]")

    if obj.dry_run:
        console.print("[dim]No tools will be executed.[/dim]")
        log.info("dry run — skipping execution", module=module)
    else:
        console.print("[dim]Module not yet implemented — coming in Sprint 2+.[/dim]")


@app.command()
def report(
    ctx: typer.Context,
    session_id: Annotated[Optional[str], typer.Option("--session", "-s", help="Session ID to report on")] = None,
    fmt: Annotated[str, typer.Option("--format", "-f", help="Output format: json, markdown")] = "markdown",
) -> None:
    """Generate a report for a session."""
    obj: AppContext = ctx.obj
    log = get_logger("report")

    if not session_id:
        console.print("[red]Error:[/red] --session is required for report.")
        raise typer.Exit(1)

    log.info("report requested", session_id=session_id, format=fmt)
    console.print(f"Generating [bold]{fmt}[/bold] report for session [cyan]{session_id}[/cyan]")
    console.print("[dim]Reporting not yet implemented — coming in Sprint 5.[/dim]")


@app.command()
def version() -> None:
    """Show version and exit."""
    console.print(f"[bold]mylilpwny[/bold] v{_VERSION}")


if __name__ == "__main__":
    app()
