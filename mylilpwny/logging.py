from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

import structlog

_SHARED_PROCESSORS: list[structlog.types.Processor] = [
    structlog.stdlib.add_log_level,
    structlog.stdlib.add_logger_name,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.ExceptionRenderer(),
]


def setup_logging(*, verbose: bool = False) -> None:
    """Configure structlog and attach a console handler.

    Console level: WARNING by default, DEBUG with verbose=True.
    Call this once at startup from the CLI callback.
    """
    structlog.configure(
        processors=_SHARED_PROCESSORS + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,  # allow reconfiguration without stale caches
    )

    console_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.dev.ConsoleRenderer(colors=True),
        ],
        foreign_pre_chain=_SHARED_PROCESSORS,
    )

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)

    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(console_handler)
    root.setLevel(logging.DEBUG)

    # Suppress noisy third-party loggers — even in verbose mode they add no signal
    for noisy in ("httpcore", "httpx", "asyncio", "urllib3", "charset_normalizer"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def setup_run_logging(output_dir: str | Path, *, verbose: bool = False) -> Path:
    """Add a JSON file handler for the current run. Returns the run log directory.

    Call this from the 'run' command after setup_logging() has been called.
    Does NOT reconfigure structlog — only adds a new stdlib file handler.
    """
    run_dir = Path(output_dir) / "runs" / datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)

    file_formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            structlog.processors.JSONRenderer(),
        ],
        foreign_pre_chain=_SHARED_PROCESSORS,
    )

    file_handler = logging.FileHandler(run_dir / "run.log")
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    logging.getLogger().addHandler(file_handler)
    return run_dir


def get_logger(name: str | None = None) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)  # type: ignore[no-any-return]
