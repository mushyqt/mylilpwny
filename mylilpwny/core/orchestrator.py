from __future__ import annotations

import asyncio
import ipaddress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.progress import BarColumn, Progress, SpinnerColumn, TaskProgressColumn, TextColumn, TimeElapsedColumn

from mylilpwny.config import Config
from mylilpwny.core.pipeline import Pipeline, StageResult
from mylilpwny.core.scope import ScopeValidator
from mylilpwny.core.state import Target
from mylilpwny.logging import get_logger

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

    def __init__(self, config: Config, scope: ScopeValidator) -> None:
        self.config = config
        self.scope = scope

    async def run(
        self,
        raw_target: str,
        stages: list[str] | None = None,
        skip: list[str] | None = None,
        dry_run: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> list[RunResult]:
        targets_raw = expand_target(raw_target)
        log.info("targets expanded", count=len(targets_raw), input=raw_target)

        targets = [Target(input=t, ip=t if _is_ip(t) else None,
                          hostname=None if _is_ip(t) else t)
                   for t in targets_raw]

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
                    pipeline = Pipeline(self.config, self.scope)
                    try:
                        stage_results = await pipeline.run(
                            target, stages=stages, skip=skip,
                            dry_run=dry_run, extra=extra,
                        )
                        log.info("target complete", target=target.input,
                                 stages_run=len(stage_results))
                        return RunResult(target=target, stage_results=stage_results)
                    except Exception as e:
                        log.error("target failed", target=target.input, error=str(e))
                        return RunResult(target=target, error=str(e))
                    finally:
                        progress.advance(overall)

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
