"""Persistent SQLite via SQLModel. One controller process plus the occasional `ingest` CLI write to
the same file; WAL + foreign keys on.

Two transaction shapes. `session_scope` opens a deferred transaction: readers never wait, and a
write that follows a read is refused (`SQLITE_BUSY_SNAPSHOT`, no busy handler) if another
connection committed in between. `write_scope` opens with `BEGIN IMMEDIATE` and so holds the single
write lock from its first statement: what it read is what it commits against, and a concurrent
writer (another process' `ingest`) either committed before it began and is visible to it, or waits
at its own `BEGIN` until it commits. Any transaction that talks to GitHub or Devin between a read
and a write must use `write_scope`, otherwise the external effect can outlive a rolled-back
transaction that never recorded it."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from sqlalchemy import event, insert, text
from sqlalchemy.engine import Connection, Engine
from sqlmodel import Session, SQLModel, create_engine, select

from hardening_loop.models import tables
from hardening_loop.models.tables import utcnow

SCHEMA_VERSION = 6

# How long a writer waits for the single write lock before failing with "database is locked".
# The polls fetch their Devin and GitHub evidence with no lock held and take a write transaction per
# work item (or finding group) for the writes and the effects that must be recorded with them, so a
# lock is held across at most three remote calls in a poll unit (a finished session's PR lookup,
# its file list and the issue comment; a pending question and its answer; a retry message and its
# issue comment; a review poll and its trigger); an operator launch holds it across five GitHub
# calls; a closing scan evaluation across two or three per issue it closes or reopens. A call is at
# most four attempts of the client timeout plus 7 s of backoff (Devin 4x60+7 = 247 s, GitHub
# 4x30+7 = 127 s), so ten minutes outlasts any poll unit or operator launch whose every attempt
# timed out; only a closing evaluation of several issues under that same total outage could still
# run longer, and the `ingest` CLI then reports the lock and exits 2 instead of failing halfway.
WRITER_BUSY_TIMEOUT_MS = 10 * 60 * 1000

_WRITE_OPTION = "hl_write"

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
    # 5 adds the `devin_assets` and `metrics_snapshots` tables only; `create_all` builds them.
    5: (),
    # Runs already in the database are owed a closing evaluation on the next tick (NULL); the
    # evaluation itself is a no-op for a run that could not close anything.
    6: ("ALTER TABLE scan_runs ADD COLUMN closure_applied_at DATETIME",),
}


def _set_sqlite_pragmas(dbapi_connection: object, _record: object) -> None:
    # pysqlite's implicit transactions skip DDL; with isolation_level=None nothing is implicit and
    # `_begin_transaction` opens every transaction explicitly, so ALTER TABLE takes part in it.
    dbapi_connection.isolation_level = None  # type: ignore[attr-defined]
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute(f"PRAGMA busy_timeout={WRITER_BUSY_TIMEOUT_MS}")
    cursor.close()


def _set_readonly_pragmas(dbapi_connection: object, _record: object) -> None:
    cursor = dbapi_connection.cursor()  # type: ignore[attr-defined]
    cursor.execute("PRAGMA query_only=ON")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def _begin_transaction(conn: Connection) -> None:
    immediate = conn.get_execution_options().get(_WRITE_OPTION, False)
    conn.exec_driver_sql("BEGIN IMMEDIATE" if immediate else "BEGIN")


def make_engine(path: Path | str) -> Engine:
    url = "sqlite://" if str(path) == ":memory:" else f"sqlite:///{path}"
    engine = create_engine(url, connect_args={"check_same_thread": False})
    event.listen(engine, "connect", _set_sqlite_pragmas)
    event.listen(engine, "begin", _begin_transaction)
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
            conn.execute(insert(tables.SchemaVersion).values(version=version, applied_at=utcnow()))
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


@contextmanager
def write_scope(engine: Engine) -> Iterator[Session]:
    """A session whose every transaction (including those after an explicit `commit()`) starts
    with `BEGIN IMMEDIATE`, for work that mutates GitHub or Devin before its first row write.
    Loaded rows are not expired by a commit: a unit that commits its reservation, then calls Devin
    with the lock released, keeps using the row it reserved without a refresh re-taking the lock."""
    with engine.connect().execution_options(**{_WRITE_OPTION: True}) as conn:
        session = Session(bind=conn, expire_on_commit=False)
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
