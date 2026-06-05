from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from mylilpwny.config import Config
from mylilpwny.core.scope import OutOfScopeError, ScopeValidator
from mylilpwny.core.state import Target, TargetState
from mylilpwny.logging import get_logger
from mylilpwny.modules.base import BaseModule, ModuleResult
from mylilpwny.modules.portscan import PortScanModule
from mylilpwny.modules.recon import ReconModule
from mylilpwny.modules.servicenum import ServiceEnumModule
from mylilpwny.modules.vulnanalysis import VulnAnalysisModule

log = get_logger(__name__)

STAGE_ORDER = ["recon", "portscan", "servicenum", "vulnanalysis"]

_MODULE_MAP: dict[str, type[BaseModule]] = {
    "recon": ReconModule,
    "portscan": PortScanModule,
    "servicenum": ServiceEnumModule,
    "vulnanalysis": VulnAnalysisModule,
}

_STATE_AFTER: dict[str, TargetState] = {
    "recon": TargetState.DISCOVERED,    # recon doesn't advance state by itself
    "portscan": TargetState.SCANNED,
    "servicenum": TargetState.ENUMERATED,
    "vulnanalysis": TargetState.ANALYZED,
}


@dataclass
class StageResult:
    stage: str
    module_result: ModuleResult | None = None
    skipped: bool = False
    error: str | None = None

    @property
    def success(self) -> bool:
        return not self.skipped and self.error is None


def _build_options(stage: str, target: Target, config: Config, extra: dict[str, Any]) -> dict[str, Any]:
    """Build options dict for a stage from previous target state + config."""
    opts: dict[str, Any] = {}

    if stage == "portscan":
        opts["ports"] = extra.get("ports", "1-65535")
        opts["rate"] = config.rate_limit.rps * 100
        opts["timeout"] = config.timeouts.portscan

    elif stage == "servicenum":
        # Pass open ports discovered by portscan
        port_list = ",".join(str(p["port"]) for p in target.ports) if target.ports else "1-65535"
        opts["ports"] = port_list
        opts["timeout"] = config.timeouts.servicenum

    elif stage == "vulnanalysis":
        # Pass services discovered by servicenum
        opts["services"] = [
            {"name": s.get("name", ""), "version": s.get("version")}
            for s in target.services
        ]
        opts["use_nvd"] = extra.get("use_nvd", True)
        opts["nvd_delay"] = 6.0

    opts.update(extra.get("stage_options", {}).get(stage, {}))
    return opts


async def _run_stage_with_timeout(
    module: BaseModule,
    target: Target,
    options: dict[str, Any],
    timeout: int,
    dry_run: bool,
) -> ModuleResult:
    if dry_run:
        return ModuleResult(
            status="skipped",
            raw_output="",
            parsed_findings=[],
            duration=0.0,
            command_run=f"[dry-run] {module.name}",
        )
    return await asyncio.wait_for(module.run(target, options), timeout=timeout)


class Pipeline:
    """Async pipeline runner: recon → portscan → servicenum → vulnanalysis."""

    def __init__(self, config: Config, scope: ScopeValidator) -> None:
        self.config = config
        self.scope = scope

    async def run(
        self,
        target: Target,
        stages: list[str] | None = None,
        skip: list[str] | None = None,
        dry_run: bool = False,
        extra: dict[str, Any] | None = None,
    ) -> list[StageResult]:
        """Run the pipeline. Returns one StageResult per stage."""
        run_stages = stages or STAGE_ORDER
        skip_set = set(skip or [])
        extra = extra or {}
        results: list[StageResult] = []

        # Scope check before doing anything
        check_target = target.ip or target.hostname or target.input
        try:
            self.scope.require_in_scope(check_target)
        except OutOfScopeError as e:
            log.error("target out of scope — pipeline aborted", target=check_target)
            return [StageResult(stage="scope_check", error=str(e))]

        for stage in run_stages:
            if stage not in STAGE_ORDER:
                log.warning("unknown stage — skipping", stage=stage)
                results.append(StageResult(stage=stage, skipped=True, error="unknown stage"))
                continue

            if stage in skip_set:
                log.info("stage skipped", stage=stage)
                results.append(StageResult(stage=stage, skipped=True))
                continue

            module_cls = _MODULE_MAP[stage]
            module = module_cls()
            timeout = getattr(self.config.timeouts, stage, self.config.timeouts.default)
            options = _build_options(stage, target, self.config, extra)

            log.info("stage started", stage=stage, target=target.input, dry_run=dry_run)

            try:
                result = await _run_stage_with_timeout(module, target, options, timeout, dry_run)
                results.append(StageResult(stage=stage, module_result=result))

                # Update target with findings
                if result.status == "success" and not dry_run:
                    _apply_findings(stage, target, result)

                # Advance state machine
                next_state = _STATE_AFTER.get(stage)
                if next_state and target.state.can_transition_to(next_state):
                    target.transition(next_state)

                log.info("stage complete", stage=stage, findings=len(result.parsed_findings),
                         duration=round(result.duration, 2))

            except asyncio.TimeoutError:
                msg = f"stage '{stage}' timed out after {timeout}s"
                log.error(msg, stage=stage)
                results.append(StageResult(stage=stage, error=msg))

            except Exception as e:
                log.error("stage failed", stage=stage, error=str(e))
                results.append(StageResult(stage=stage, error=str(e)))

        return results


def _apply_findings(stage: str, target: Target, result: ModuleResult) -> None:
    """Merge module findings back into the target object."""
    if stage == "portscan":
        target.ports = result.parsed_findings
    elif stage == "servicenum":
        target.services = result.parsed_findings
    elif stage == "recon":
        if result.parsed_findings:
            recon = result.parsed_findings[0]
            target.hostname = target.hostname or (recon.get("hostnames") or [None])[0]
            target.ip = target.ip or (recon.get("ips") or [None])[0]
            target.metadata.update({k: v for k, v in recon.items() if k not in ("hostnames", "ips")})
    elif stage == "vulnanalysis":
        target.vulnerabilities = result.parsed_findings
