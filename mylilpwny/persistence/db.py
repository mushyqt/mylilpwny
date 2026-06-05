from __future__ import annotations

import os
from pathlib import Path

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from mylilpwny.persistence.models import Base

_DEFAULT_DB_PATH = "output/mylilpwny.db"


def _db_url(path: str | Path | None = None) -> str:
    """Return the database URL.

    Priority: DATABASE_URL env var → explicit path argument → default SQLite path.
    Supports swapping to PostgreSQL by setting DATABASE_URL=postgresql://...
    """
    env_url = os.environ.get("DATABASE_URL")
    if env_url:
        return env_url
    db_path = Path(path) if path else Path(_DEFAULT_DB_PATH)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path.resolve()}"


def create_db_engine(db_path: str | Path | None = None) -> Engine:
    url = _db_url(db_path)
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


def init_db(engine: Engine) -> None:
    """Create all tables if they don't exist (idempotent)."""
    Base.metadata.create_all(engine)


def get_session_factory(engine: Engine) -> sessionmaker[Session]:
    return sessionmaker(bind=engine, expire_on_commit=False)


def setup_database(db_path: str | Path | None = None) -> tuple[Engine, sessionmaker[Session]]:
    """Convenience: create engine + init tables + return (engine, factory)."""
    engine = create_db_engine(db_path)
    init_db(engine)
    return engine, get_session_factory(engine)
