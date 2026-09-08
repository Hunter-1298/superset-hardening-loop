"""Persisted metrics snapshots: one row per operator tick / replay scenario / `metrics snapshot`,
with the headline numbers denormalized and the full payload in `body`."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlmodel import select

from hardening_loop.cli import main
from hardening_loop.config import Settings
from hardening_loop.dashboard.app import create_app
from hardening_loop.db import open_database, session_scope
from hardening_loop.metrics import compute_metrics, metrics_history, snapshot_metrics
from hardening_loop.models.tables import MetricsSnapshot
from hardening_loop.operator import OperatorContext, build_doubles_orchestrator
from hardening_loop.replay.runner import run_scenario

REPO_ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 9, 7, 3, tzinfo=UTC)


@pytest.fixture(scope="module")
def demo_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("demo")
    result = run_scenario("DEMO", out)
    assert result.passed, [c for c in result.checks if not c.ok]
    return out / "demo.sqlite3"


def test_replay_scenario_leaves_one_snapshot_matching_recomputed_metrics(demo_db: Path) -> None:
    engine = open_database(demo_db)
    rows = metrics_history(engine)
    assert [r.trigger for r in rows] == ["replay:DEMO"]
    snap = rows[0]
    live = compute_metrics(engine, acu_cost_usd=None, now=snap.taken_at)
    assert snap.open_high_critical == live.open_high_critical
    assert snap.needs_human == live.needs_human
    assert snap.verified_prs == live.cost.verified_items == 6
    assert snap.acus_total == live.cost.acu_total > 0
    assert snap.cost_usd_total is None  # HL_ACU_COST_USD unset in replay
    assert snap.body["issues_by_state"] == live.issues_by_state
    assert snap.latest_main_run_id == live.latest_main_run_id


def test_snapshot_denormalizes_cost_when_price_is_set(demo_db: Path) -> None:
    engine = open_database(demo_db)
    row = snapshot_metrics(engine, trigger="test", acu_cost_usd=2.25, now=NOW)
    assert row.id is not None and row.taken_at == NOW
    assert row.cost_usd_total == pytest.approx(row.acus_total * 2.25)
    assert row.body["cost"]["acu_cost_usd"] == 2.25
    newest = metrics_history(engine, limit=1)[0]
    assert newest.id == row.id and newest.trigger == "test"


def test_operator_tick_persists_a_snapshot_every_time(tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_file="op.sqlite3",
        operator_mode=True,
        operator_login="operator-test",
        repo_root=REPO_ROOT,
    )
    orch = build_doubles_orchestrator(settings)
    ctx = OperatorContext.for_doubles(orch, login="operator-test")
    with session_scope(orch.engine) as db:
        assert db.exec(select(MetricsSnapshot)).all() == []
    ctx.tick()
    ctx.tick()
    rows = metrics_history(orch.engine)
    assert [r.trigger for r in rows] == ["tick", "tick"]
    assert rows[0].id is not None and rows[1].id is not None and rows[0].id > rows[1].id
    assert rows[0].active_sessions == 0 and rows[0].verified_prs == 0


def test_history_api_is_newest_first_without_bodies(demo_db: Path) -> None:
    settings = Settings(
        data_dir=demo_db.parent, database_file=demo_db.name, replay_mode=True, repo_root=REPO_ROOT
    )
    engine = open_database(demo_db)
    snapshot_metrics(engine, trigger="api-test", acu_cost_usd=None, now=NOW)
    with TestClient(create_app(settings, engine=engine)) as c:
        rows = c.get("/api/metrics/history?limit=2").json()
        assert len(rows) == 2 and rows[0]["trigger"] == "api-test"
        assert "body" not in rows[0] and "open_high_critical" in rows[0]
        assert c.get("/api/metrics/history?limit=0").status_code == 422
        assert c.post("/api/metrics/history").status_code == 405


def test_cli_snapshot_and_history(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "cli.sqlite3"
    assert main(["metrics", "snapshot", "--db", str(db), "--trigger", "cron"]) == 0
    assert main(["metrics", "snapshot", "--db", str(db), "--acu-cost-usd", "2.25"]) == 0
    out = capsys.readouterr().out
    assert "metrics_snapshots.id=1" in out and "metrics_snapshots.id=2" in out
    assert main(["metrics", "history", "--db", str(db), "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["trigger"] for r in rows] == ["manual", "cron"]
    assert rows[0]["cost_usd_total"] == 0.0 and rows[1]["cost_usd_total"] is None
    assert main(["metrics", "history", "--db", str(db), "--limit", "1"]) == 0
    assert capsys.readouterr().out.count("\n") == 1
