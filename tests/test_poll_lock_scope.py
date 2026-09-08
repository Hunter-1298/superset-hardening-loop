"""A polling pass never holds SQLite's single writer lock while it waits on Devin or GitHub: the
remote evidence is fetched first, then each work item is applied in a write transaction of its own.
A CLI `ingest` running in another process while the controller is mid-call therefore lands at once
instead of waiting behind the pass (or failing on the busy timeout), and the item whose call it
landed inside is still applied exactly once."""

from __future__ import annotations

import threading
from pathlib import Path

from hardening_loop.config import BASELINE_SHA
from hardening_loop.db import open_database
from hardening_loop.domain.enums import WorkItemState
from hardening_loop.replay.synth import ingest_synthetic
from hardening_loop.replay.world import World


def _two_active_items(tmp_path: Path) -> World:
    w = World(tmp_path / "replay.sqlite3", max_concurrent_sessions=2)
    w.baseline("cryptography", "pillow")
    w.tick()
    assert [i.state for i in w.work_items()] == [WorkItemState.session_active] * 2
    assert len(w.devin.sessions) == 2
    return w


def _race(w: World, method: str) -> list[bool]:
    """Arrange a CLI ingest (its own engine, as another process would have) to start inside the
    controller's next `method` call and wait up to 30 s for it there. Returns a one-element log of
    whether the ingest was still running when that call resumed: it must not be, since the
    controller holds no lock during the call, and a held lock would park it for the busy timeout."""
    cli_engine = open_database(w.db_path)
    w.clock.advance(minutes=30)
    later = w.closing_run(BASELINE_SHA, "cryptography", "pillow")  # nothing fixed yet
    later.at = w.clock.now()
    cli = threading.Thread(target=ingest_synthetic, args=(cli_engine, later, "cli-race"))
    still_running: list[bool] = []

    def during_call() -> None:
        cli.start()
        cli.join(timeout=30)
        still_running.append(cli.is_alive())

    w.devin.before_next[method] = during_call
    return still_running


def test_a_scan_ingested_during_a_session_poll_lands_at_once(tmp_path: Path) -> None:
    w = _two_active_items(tmp_path)
    still_running = _race(w, "get_session")

    assert w.orch.poll_sessions() == 2
    assert still_running == [False], "the intake landed while the controller was inside get_session"

    runs = w.scan_runs()
    assert [r.external_run_id for r in runs][-1] == "cli-race"
    assert [r.closure_applied_at is not None for r in runs] == [True, False]
    assert [i.state for i in w.work_items()] == [WorkItemState.session_active] * 2
    assert len(w.devin.sessions) == 2
    assert {c[1] for c in w.devin.calls[-2:] if c[0] == "get_session"} == {
        s.devin_id for s in w.sessions()
    }, "each active session was polled exactly once after the race"

    report = w.tick()
    assert report.scan_apply_error is None and report.scans_applied == 1
    assert len(w.devin.sessions) == 2, "the tick after the race launches nothing new"


def test_a_scan_ingested_during_dispatch_lands_at_once(tmp_path: Path) -> None:
    """`dispatch()` commits each candidate's reservation and releases the lock before creating its
    session; the intake lands during `create_session`, and the candidate is still recorded once."""
    w = World(tmp_path / "replay.sqlite3", max_concurrent_sessions=2, auto_open_issues=True)
    w.baseline("cryptography", "pillow")
    w.orch.apply_scan_run(w.run_ids["replay-baseline"])
    w.orch.create_work_items()
    assert w.orch.open_issues() == 2
    still_running = _race(w, "create_session")

    created, adopted, _issues = w.orch.dispatch()
    assert (created, adopted) == (2, [])
    assert still_running == [False], (
        "the intake landed while the controller was inside create_session"
    )

    items = w.work_items()
    assert [i.state for i in items] == [WorkItemState.session_active] * 2
    assert len(w.devin.sessions) == 2 == len({i.active_session_id for i in items})
    assert [r.external_run_id for r in w.scan_runs()][-1] == "cli-race"
    assert len([c for c in w.devin.calls if c[0] == "create_session"]) == 2
