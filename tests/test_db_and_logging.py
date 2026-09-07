from __future__ import annotations

import logging
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from sqlmodel import select

from hardening_loop import db as dbmod
from hardening_loop.config import Settings, assert_repo_allowed
from hardening_loop.domain.enums import Kind, Layer, Trigger
from hardening_loop.logging_utils import REDACTED, RedactingFilter, configure_logging
from hardening_loop.models import tables


def test_sqlite_pragmas_and_schema_version(tmp_path: Path) -> None:
    engine = dbmod.open_database(tmp_path / "c.sqlite3")
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar_one() == "wal"
        assert conn.execute(text("PRAGMA foreign_keys")).scalar_one() == 1
    assert dbmod.integrity_ok(engine)
    with dbmod.session_scope(engine) as s:
        v = s.exec(select(tables.SchemaVersion)).one()
        assert v.version == dbmod.SCHEMA_VERSION


def test_schema_version_mismatch_refuses_to_start(tmp_path: Path) -> None:
    path = tmp_path / "c.sqlite3"
    engine = dbmod.open_database(path)
    with dbmod.session_scope(engine) as s:
        s.add(tables.SchemaVersion(version=dbmod.SCHEMA_VERSION + 1))
    with pytest.raises(RuntimeError, match="schema version"):
        dbmod.init_db(engine)


def test_foreign_keys_enforced(tmp_path: Path) -> None:
    engine = dbmod.open_database(tmp_path / "c.sqlite3")
    with pytest.raises(Exception, match="FOREIGN KEY"), dbmod.session_scope(engine) as s:
        s.add(
            tables.Finding(
                dedupe_key="k",
                vuln_id="CVE-1",
                layer=Layer.python,
                first_seen_run_id=999,
                last_seen_run_id=999,
            )
        )


def test_round_trip_enums(tmp_path: Path) -> None:
    engine = dbmod.open_database(tmp_path / "c.sqlite3")
    with dbmod.session_scope(engine) as s:
        run = tables.ScanRun(
            external_run_id="r1",
            trigger=Trigger.fixture,
            source_repo="Hunter-1298/superset",
            source_branch="main",
            source_sha="c83fb2bb",
        )
        s.add(run)
        s.flush()
        wi = tables.WorkItem(
            kind=Kind.dependency_upgrade, group_key="pypi:foo", title="t", acu_cap=5
        )
        s.add(wi)
    with dbmod.session_scope(engine) as s:
        wi2 = s.exec(select(tables.WorkItem)).one()
        assert wi2.kind is Kind.dependency_upgrade and wi2.kind.acu_cap == 5


def test_redaction() -> None:
    f = RedactingFilter(["supersecretvalue"])
    assert f.redact("token supersecretvalue here") == f"token {REDACTED} here"
    assert f.redact("cog_abcdefghijklmnop123") == REDACTED
    assert f.redact("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234") == REDACTED
    assert f.redact("Authorization: Bearer abc.def") == f"Authorization: Bearer {REDACTED}"


def test_configure_logging_redacts_records(capfd: pytest.CaptureFixture[str]) -> None:
    configure_logging(["hunter2"])
    logging.getLogger("t").info("password=%s", "hunter2")
    err = capfd.readouterr().err
    assert "hunter2" not in err and REDACTED in err
    logging.getLogger().handlers.clear()


def test_settings_secrets_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HL_DEVIN_API_KEY", "cog_secret_value_123456")
    monkeypatch.setenv("HL_GITHUB_TOKEN", "ghp_secret")
    s = Settings()
    assert "cog_secret" not in repr(s) and "ghp_secret" not in str(s.model_dump())
    assert s.secret_values == ["cog_secret_value_123456", "ghp_secret"]


def test_settings_empty_optional_env_means_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HL_ACU_COST_USD", "")
    monkeypatch.setenv("HL_UPSTREAM_MASTER_SHA", " ")
    s = Settings()
    assert s.acu_cost_usd is None and s.upstream_master_sha is None
    monkeypatch.setenv("HL_ACU_COST_USD", "2.25")
    assert Settings().acu_cost_usd == 2.25
    assert (Settings().repo_root / "fixtures" / "baseline").is_dir()


def test_repo_allowlist_blocks_upstream() -> None:
    assert_repo_allowed("Hunter-1298/superset")
    with pytest.raises(PermissionError):
        assert_repo_allowed("apache/superset")


def test_readonly_engine_rejects_writes_and_missing_files(tmp_path: Path) -> None:
    path = tmp_path / "ro.sqlite3"
    dbmod.open_database(path).dispose()
    dbmod.rollback_journal_mode(path)
    assert not (tmp_path / "ro.sqlite3-wal").exists()
    engine = dbmod.open_database_readonly(path)
    with engine.connect() as conn:
        assert conn.execute(text("PRAGMA journal_mode")).scalar_one() == "delete"
        assert conn.execute(text("PRAGMA query_only")).scalar_one() == 1
    with (
        pytest.raises(OperationalError, match=r"readonly|query_only"),
        dbmod.session_scope(engine) as db,
    ):
        db.add(tables.Event(entity_type="x", entity_id=1, event="write", actor="test"))
        db.commit()
    with pytest.raises(FileNotFoundError):
        dbmod.open_database_readonly(tmp_path / "missing.sqlite3")
