from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

import structlog


def setup_logging(
    output_dir: str | Path | None = None,
    *,
    verbose: bool = False,
) -> Path | None:
    """Configure structlog for console + optional file output.

    Console shows WARNING by default; DEBUG when verbose=True.
    File (when output_dir provided) always captures INFO and above.
    Returns the run log directory when output_dir is provided, None otherwise.
    """
    shared_processors: list[structlog.types.Processor] = [
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.ExceptionRenderer(),
    ]

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    console_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        foreign_pre_chain=shared_processors,
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(console_handler)
    root.setLevel(logging.DEBUG)  # let handlers decide what to show

    if output_dir is None:
        return None

    run_dir = Path(output_dir) / "runs" / datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)

    file_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=shared_processors,
    )

    file_handler = logging.FileHandler(run_dir / "run.log")
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.INFO)
    root.addHandler(file_handler)

    return run_dir


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
