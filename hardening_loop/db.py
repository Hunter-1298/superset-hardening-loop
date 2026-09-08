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

SCHEMA_VERSION = 5

# version -> SQL that brings a database at version-1 up to `version`. Only additive or renaming
# statements; `create_all` afterwards adds any brand-new table.
_MIGRATIONS: dict[int, tuple[str, ...]] = {
    3: (
        "ALTER TABLE work_items RENAME COLUMN verification_level TO lifecycle_level",
        "ALTER TABLE work_items ADD COLUMN verification_depth INTEGER",
        "ALTER TABLE pull_requests RENAME COLUMN verification_level TO lifecycle_level",
        "ALTER TABLE pull_requests ADD COLUMN verification_depth INTEGER",
        "ALTER TABLE pull_requests ADD COLUMN depth_rungs JSON NOT NULL DEFAULT '{}'",
        "ALTER TABLE pull_requests ADD COLUMN review_id VARCHAR",
        "ALTER TABLE pull_requests ADD COLUMN review_head_sha VARCHAR",
        "UPDATE events SET event = 'lifecycle_level' WHERE event = 'verification_level'",
    ),
    4: ("ALTER TABLE scan_runs ADD COLUMN workflow JSON",),
    # 5 adds the `devin_assets` table only; `create_all` builds it.
    5: (),
}


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


def _current_version(engine: Engine) -> int | None:
    with Session(engine) as session:
        current = session.exec(
            select(tables.SchemaVersion).order_by(tables.SchemaVersion.id.desc())  # type: ignore[union-attr]
        ).first()
        return None if current is None else current.version


def _check_schema_version(engine: Engine, *, create_missing: bool) -> None:
    current = _current_version(engine)
    if current is None:
        if not create_missing:
            raise RuntimeError("database has no schema_version row; not a controller database")
        with Session(engine) as session:
            session.add(tables.SchemaVersion(version=SCHEMA_VERSION))
            session.commit()
    elif current != SCHEMA_VERSION:
        raise RuntimeError(
            f"database schema version {current} != code {SCHEMA_VERSION}; "
            "migrate or start from a fresh data dir"
        )


def migrate(engine: Engine) -> list[int]:
    """Apply every pending `_MIGRATIONS` step in order and record each version. Returns the
    versions applied. Refuses a database newer than the code."""
    current = _current_version(engine)
    if current is None:
        return []
    if current > SCHEMA_VERSION:
        raise RuntimeError(f"database schema version {current} is newer than code {SCHEMA_VERSION}")
    applied: list[int] = []
    for version in range(current + 1, SCHEMA_VERSION + 1):
        with engine.begin() as conn:
            for statement in _MIGRATIONS[version]:
                conn.execute(text(statement))
        with Session(engine) as session:
            session.add(tables.SchemaVersion(version=version))
            session.commit()
        applied.append(version)
    return applied


def init_db(engine: Engine) -> None:
    current = _current_version(engine) if _has_schema_table(engine) else None
    if current is not None and current < SCHEMA_VERSION:
        migrate(engine)
    SQLModel.metadata.create_all(engine)
    _check_schema_version(engine, create_missing=True)


def _has_schema_table(engine: Engine) -> bool:
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
        ).first()
        return row is not None


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
