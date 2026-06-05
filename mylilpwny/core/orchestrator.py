from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn

from mylilpwny.config import Config
from mylilpwny.core.pipeline import Pipeline, StageResult
from mylilpwny.core.ratelimit import RateLimiter
from mylilpwny.core.scope import ScopeValidator
from mylilpwny.core.state import Target, TargetState
from mylilpwny.logging import get_logger

if TYPE_CHECKING:
    from mylilpwny.persistence.session import SessionManager

log = get_logger(__name__)


def expand_target(raw: str) -> list[str]:
    """Expand a raw target string into a list of individual targets.

    Accepts:
    - Single IP: "10.0.0.1"
    - CIDR: "10.0.0.0/24"
    - Hostname: "example.com"
    - Comma-separated list: "10.0.0.1,10.0.0.2"
    - File path (one target per line): "@/path/to/targets.txt"
    """
    raw = raw.strip()

    if raw.startswith("@"):
        path = Path(raw[1:])
        lines = path.read_text().splitlines()
        targets = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#"):
                targets.extend(expand_target(line))
        return targets

    if "," in raw:
        targets = []
        for part in raw.split(","):
            targets.extend(expand_target(part.strip()))
        return targets

    try:
        network = ipaddress.ip_network(raw, strict=False)
        if network.num_addresses == 1:
            return [str(network.network_address)]
        # Skip network and broadcast for /24+; include all for small ranges
        hosts = list(network.hosts())
        return [str(h) for h in hosts]
    except ValueError:
        pass

    return [raw]


@dataclass
class RunResult:
    target: Target
    stage_results: list[StageResult] = field(default_factory=list)
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None and any(r.success for r in self.stage_results)


class Orchestrator:
    """Runs the pipeline across multiple targets with concurrency control and progress display."""

    def __init__(
        self,
        config: Config,
        scope: ScopeValidator,
        session_manager: SessionManager | None = None,
    ) -> None:
        self.config = config
        self.scope = scope
        self.session_manager = session_manager
        self.rate_limiter = RateLimiter(
            global_rps=float(self.config.rate_limit.rps),
            per_target_rps=float(self.config.rate_limit.rps),
        )

    async def run(
        self,
        raw_target: str,
        stages: list[str] | None = None,
        skip: list[str] | None = None,
        dry_run: bool = False,
        extra: dict[str, Any] | None = None,
        session_id: str | None = None,
    ) -> list[RunResult]:
        targets_raw = expand_target(raw_target)
        log.info("targets expanded", count=len(targets_raw), input=raw_target)

        # On resume: load already-completed targets from DB so we can skip done stages.
        completed: dict[str, str] = {}  # target_input → last completed state
        if session_id and self.session_manager:
            for tr in self.session_manager.get_targets(session_id):
                completed[tr.input] = tr.state

        targets = []
        for t in targets_raw:
            tgt = Target(
                input=t,
                ip=t if _is_ip(t) else None,
                hostname=None if _is_ip(t) else t,
            )
            # Restore state from DB if resuming
            if t in completed:
                try:
                    tgt.state = TargetState(completed[t])
                except ValueError:
                    pass
            targets.append(tgt)

        max_concurrent = self.config.rate_limit.max_concurrent_targets
        semaphore = asyncio.Semaphore(max_concurrent)

        results: list[RunResult] = []

        with Progress(
            SpinnerColumn(),
            TextColumn("[bold]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
        ) as progress:
            overall = progress.add_task("Scanning targets", total=len(targets))

            async def _run_one(target: Target) -> RunResult:
                async with semaphore:
                    progress.update(overall, description=f"[cyan]{target.input}")
                    pipeline = Pipeline(
                        self.config, self.scope, self.rate_limiter,
                        session_manager=self.session_manager,
                        session_id=session_id,
                    )
                    try:
                        stage_results = await pipeline.run(
                            target, stages=stages, skip=skip,
                            dry_run=dry_run, extra=extra,
                        )
                        log.info("target complete", target=target.input,
                                 stages_run=len(stage_results))
                        result = RunResult(target=target, stage_results=stage_results)
                    except Exception as e:
                        log.error("target failed", target=target.input, error=str(e))
                        result = RunResult(target=target, error=str(e))
                    finally:
                        progress.advance(overall)

                    # Persist target state
                    if session_id and self.session_manager:
                        self.session_manager.upsert_target(
                            session_id,
                            target.input,
                            ip=target.ip,
                            hostname=target.hostname,
                            state=target.state.value,
                            metadata=target.metadata,
                        )
                        self.session_manager.audit(
                            session_id,
                            "target_complete" if result.error is None else "target_failed",
                            target=target.input,
                            detail={"error": result.error, "stages": len(result.stage_results)},
                        )

                    return result

            results = list(await asyncio.gather(*[_run_one(t) for t in targets]))

        log.info("orchestrator complete", total=len(results),
                 success=sum(1 for r in results if r.success))
        return results


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
