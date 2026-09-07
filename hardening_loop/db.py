"""Persistent SQLite via SQLModel. Single-process controller; WAL + foreign keys on."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import event, text
from sqlalchemy.engine import Engine
from sqlmodel import Session, SQLModel, create_engine, select

from hardening_loop.models import tables

SCHEMA_VERSION = 1


def _set_sqlite_pragmas(dbapi_connection: object, _record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def make_engine(path: Path | str) -> Engine:
    url = "sqlite://" if str(path) == ":memory:" else f"sqlite:///{path}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    return engine


def init_db(engine: Engine) -> None:
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        current = session.exec(
            select(tables.SchemaVersion).order_by(tables.SchemaVersion.id.desc())  # type: ignore[union-attr]
        ).first()
        if current is None:
            session.add(tables.SchemaVersion(version=SCHEMA_VERSION))
            session.commit()
        elif current.version != SCHEMA_VERSION:
            raise RuntimeError(
                f"database schema version {current.version} != code {SCHEMA_VERSION}; "
                "migrate or start from a fresh data dir"
            )


def open_database(path: Path | str) -> Engine:
    if str(path) != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    engine = make_engine(path)
    init_db(engine)
    return engine


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
