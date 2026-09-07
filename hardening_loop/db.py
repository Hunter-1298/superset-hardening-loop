"""Persistent SQLite via SQLModel. Single-process controller; WAL + foreign keys on."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine, select

from hardening_loop.models import tables

SCHEMA_VERSION = 2


def _set_sqlite_pragmas(dbapi_connection: object, _record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def _set_readonly_pragmas(dbapi_connection: object, _record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA query_only=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def make_engine(path: Path | str) -> Engine:
    url = "sqlite://" if str(path) == ":memory:" else f"sqlite:///{path}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    return engine


def _check_schema_version(engine: Engine, *, create_missing: bool) -> None:
    with Session(engine) as session:
        current = session.exec(
            select(tables.SchemaVersion).order_by(tables.SchemaVersion.id.desc())  # type: ignore[union-attr]
        ).first()
        if current is None:
            if not create_missing:
                raise RuntimeError("database has no schema_version row; not a controller database")
            session.add(tables.SchemaVersion(version=SCHEMA_VERSION))
            session.commit()
        elif current.version != SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {current.version} != code {SCHEMA_VERSION}; "
                "migrate or start from a fresh data dir"
            )


def init_db(engine: Engine) -> None:
    SQLModel.metadata.create_all(engine)
    _check_schema_version(engine, create_missing=True)


def open_database(path: Path | str) -> Engine:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    engine = make_engine(path)
    init_db(engine)
    return engine


def open_database_readonly(path: Path | str) -> Engine:
    """Engine for the dashboard: SQLite `mode=ro` plus `query_only`, so it can serve a
    database on a read-only mount and can never write, whatever a handler does."""
    file = Path(path)
    if not file.is_file():
        raise FileNotFoundError(f"database not found: {file}")
    engine = create_engine(
        f"sqlite:///file:{file}?mode=ro&uri=true", connect_args={"check_same_thread": False}
    )
    event.listen(engine, "connect", _set_readonly_pragmas)
    _check_schema_version(engine, create_missing=False)
    return engine


def rollback_journal_mode(path: Path | str) -> None:
    """Switch a closed SQLite file from WAL to the classic rollback journal so read-only
    consumers (e.g. a `:ro` bind mount) need no `-wal`/`-shm` sidecars."""
    conn = sqlite3.connect(str(path))
    try:
        conn.execute("PRAGMA journal_mode=DELETE")
    finally:
        conn.close()


@contextmanager
def session_scope(engine: Engine) -> Iterator[Session]:
    session = Session(engine)
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def integrity_ok(engine: Engine) -> bool:
    with engine.connect() as conn:
        result: object = conn.execute(text("PRAGMA integrity_check")).scalar_one()
        return result == "ok"
