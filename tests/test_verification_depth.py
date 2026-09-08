"""Verification depth (L0-L6) is earned only by complete, passing check runs on the exact PR head.
It is independent of lifecycle progress and never advanced by Devin's own test claims."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from sqlalchemy import text
from sqlmodel import Session, select

from hardening_loop import verification
from hardening_loop.db import SCHEMA_VERSION, migrate, open_database
from hardening_loop.domain.enums import (
    CheckSource,
    CheckStatus,
    LifecycleLevel,
    VerificationDepth,
    WorkItemState,
)
from hardening_loop.github.protocol import CheckRun
from hardening_loop.models.tables import SchemaVersion, VerificationCheck
from hardening_loop.replay.scenarios import DEP_FILES, _dep_output
from hardening_loop.replay.world import DEFAULT_CHECKS, World

D = VerificationDepth
S = CheckStatus


def run(name: str, conclusion: str | None = "success", status: str = "completed") -> CheckRun:
    return CheckRun(
        name=name,
        status=status if conclusion is not None else "in_progress",
        conclusion=conclusion,
        url=f"https://ci.example/{name}",
    )


def all_green() -> list[CheckRun]:
    return [run(n) for n in DEFAULT_CHECKS]


# ------------------------------------------------------------------------------ evaluator


def test_ladder_titles_follow_the_brief() -> None:
    assert [d.label for d in D] == [
        "L0 requirements + pip",
        "L1 import + migrations",
        "L2 targeted + unit tests",
        "L3 immutable-image runtime",
        "L4 database subset",
        "L5 Playwright",
        "L6 canary",
    ]
    assert all(d in verification.DEFAULT_LADDER for d in D)


def test_no_checks_means_every_rung_unavailable_and_no_depth() -> None:
    ev = verification.evaluate([])
    assert ev.highest_passed is None
    assert set(ev.rungs.values()) == {S.unavailable}
    assert all(r.status is S.unavailable for r in ev.records)
    # Rungs that can never be proven on this repo are recorded with the reason.
    canary = next(r for r in ev.records if r.name == "canary")
    assert canary.source is CheckSource.ladder and "no check exists" in canary.detail


def test_all_fork_checks_green_reaches_l4_with_l3_partial_and_l5_l6_unavailable() -> None:
    ev = verification.evaluate(all_green())
    assert ev.rungs[D.requirements_pip] is S.passed
    assert ev.rungs[D.import_migrations] is S.passed
    assert ev.rungs[D.targeted_unit] is S.passed
    assert ev.rungs[D.immutable_image_runtime] is S.partial  # screenshot has no check
    assert ev.rungs[D.db_subset] is S.passed
    assert ev.rungs[D.playwright] is S.unavailable
    assert ev.rungs[D.canary] is S.unavailable
    assert ev.highest_passed is D.db_subset
    screenshot = next(r for r in ev.records if r.name == "screenshot")
    assert screenshot.status is S.unavailable
    app_runs = next(r for r in ev.records if r.name == "postgres-redis-app-runs")
    assert app_runs.status is S.passed and app_runs.url == "https://ci.example/app-runs"


def test_matrix_jobs_match_by_prefix_and_one_failure_fails_the_component() -> None:
    runs = [run("unit-tests (previous)"), run("unit-tests (current)"), run("unit-tests (next)")]
    assert [r.name for r in verification.matching_runs("unit-tests", runs)] == [
        r.name for r in runs
    ]
    assert verification.matching_runs("unit-tests", [run("unit-tests-extra")]) == []
    ok = verification.evaluate(runs)
    assert ok.rungs[D.targeted_unit] is S.passed
    red = verification.evaluate([*runs[:2], run("unit-tests (next)", "failure")])
    assert red.rungs[D.targeted_unit] is S.failed
    rec = next(r for r in red.records if r.name == "python-unit-tests")
    assert "unit-tests (next)=failure" in rec.detail


def test_pending_run_keeps_rung_pending_and_below_highest() -> None:
    runs = all_green()
    runs = [r if r.name != "app-runs" else run("app-runs", None) for r in runs]
    ev = verification.evaluate(runs)
    assert ev.rungs[D.immutable_image_runtime] is S.pending
    # L4 evidence is complete, so depth is L4 even while L3 is still running: rungs are independent.
    assert ev.highest_passed is D.db_subset


def test_skipped_or_neutral_runs_are_not_evidence() -> None:
    runs = [run("check-python-deps", "skipped"), run("build-image", "neutral")]
    ev = verification.evaluate(runs)
    assert ev.rungs[D.requirements_pip] is S.unavailable
    rec = next(r for r in ev.records if r.name == "pip-install")
    assert "no evidence" in rec.detail
    # A skipped matrix leg beside a successful one still counts as passed for that component.
    mixed = verification.evaluate([run("unit-tests (a)"), run("unit-tests (b)", "skipped")])
    assert mixed.rungs[D.targeted_unit] is S.passed


def test_failure_beats_pending_and_partial() -> None:
    runs = [run("test-postgres", "failure"), run("test-mysql", None), run("test-sqlite")]
    ev = verification.evaluate(runs)
    assert ev.rungs[D.db_subset] is S.failed
    assert ev.highest_passed is None


def test_devin_claims_are_recorded_but_never_earn_depth() -> None:
    claims = verification.claims_from_output(
        {
            "tests_run": [
                {"command": "pytest tests/unit_tests -q", "exit_code": 0},
                {"command": "superset db upgrade", "exit_code": 1},
                "garbage",
            ]
        }
    )
    assert [c.status for c in claims] == [S.passed, S.failed]
    assert all(c.source is CheckSource.devin_claim for c in claims)
    assert verification.claims_from_output(None) == ()
    assert verification.claims_from_output({"tests_run": "no"}) == ()
    assert verification.evaluate([]).highest_passed is None


# ------------------------------------------------------------------------------ orchestrator


def _world(tmp_path: Path) -> World:
    return World(tmp_path / "depth.sqlite3")


def _rows(w: World, pr_id: int) -> list[VerificationCheck]:
    with Session(w.engine) as db:
        return list(
            db.exec(select(VerificationCheck).where(VerificationCheck.pull_request_id == pr_id))
        )


def test_engine_persists_depth_records_and_keeps_lifecycle_separate(tmp_path: Path) -> None:
    w = _world(tmp_path)
    w.baseline("cryptography")
    w.tick()
    wi = w.only_wi()
    output = {
        **_dep_output("cryptography", "42.0.2", "42.0.4"),
        "tests_run": [{"command": "pytest tests/unit_tests", "exit_code": 0}],
    }
    _, number = w.devin_opens_pr(wi, output, files=DEP_FILES, acus=1.0)
    w.tick()
    wi = w.wi(wi.id or 0)
    row = w.pr_row(wi.id or 0)
    assert row is not None and row.id is not None
    head = w.gh.prs[number].head_sha

    # No check runs yet: PR is open (lifecycle L1) but depth is None and every rung is stored.
    assert wi.lifecycle_level is LifecycleLevel.pr_opened
    assert wi.verification_depth is None and row.verification_depth is None
    rows = _rows(w, row.id)
    names = {r.name for r in rows}
    assert {"requirements-regenerated", "screenshot", "canary", "devin-tests-run-1"} <= names
    assert all(r.head_sha == head for r in rows)
    claim = next(r for r in rows if r.name == "devin-tests-run-1")
    assert claim.source is CheckSource.devin_claim and claim.status is S.passed
    assert all(r.status is S.unavailable for r in rows if r.source is not CheckSource.devin_claim)

    # Full green CI: lifecycle moves to ci_green, depth to L4, L3 stays visibly partial.
    w.ci(head)
    w.tick()
    wi = w.wi(wi.id or 0)
    row = w.pr_row(wi.id or 0)
    assert row is not None and row.id is not None
    assert wi.state is WorkItemState.review_pending
    assert wi.lifecycle_level is LifecycleLevel.ci_green
    assert wi.verification_depth is D.db_subset and row.verification_depth is D.db_subset
    assert row.depth_rungs["immutable_image_runtime"] == "partial"
    assert row.depth_rungs["playwright"] == "unavailable"
    rows = _rows(w, row.id)
    # Re-polling updates rows in place: one row per (head, source, name).
    assert len(rows) == len({(r.head_sha, r.source, r.name) for r in rows})
    with Session(w.engine) as db:
        events = db.exec(
            text("SELECT to_state FROM events WHERE event='verification_depth'")  # type: ignore[call-overload]
        ).all()
    assert [e[0] for e in events] == ["db_subset"]


def test_new_head_resets_depth_and_partial_ci_only_earns_what_it_proves(tmp_path: Path) -> None:
    w = _world(tmp_path)
    w.baseline("pillow")
    w.tick()
    wi = w.only_wi()
    url, number = w.devin_opens_pr(
        wi, _dep_output("pillow", "10.2.0", "10.3.0"), files=DEP_FILES, acus=1.8
    )
    w.tick()
    head1 = w.gh.prs[number].head_sha
    w.ci(head1, failing=["app-runs"])
    w.tick()
    wi = w.wi(wi.id or 0)
    row = w.pr_row(wi.id or 0)
    assert row is not None
    assert wi.state is WorkItemState.session_active and wi.retries_used == 1
    # L0-L2 passed; L3 failed; L4 passed independently -> highest is L4 but L3 is `failed`.
    assert row.depth_rungs["immutable_image_runtime"] == "failed"
    assert wi.verification_depth is D.db_subset

    # Devin pushes a new head: depth evidence belongs to the old head, so depth resets.
    sess = w.devin.sessions[wi.active_session_id or ""]
    head2 = "b" * 40
    w.gh.push(number, head2)
    w.devin.finish(
        wi.active_session_id or "",
        {**(sess.structured_output or {}), "pr_url": url},
        acus=3.0,
        pull_requests=[url],
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    row = w.pr_row(wi.id or 0)
    assert row is not None and row.head_sha == head2
    assert wi.state is WorkItemState.checks_running
    assert wi.lifecycle_level is LifecycleLevel.pr_opened
    assert wi.verification_depth is None and row.verification_depth is None
    assert set(row.depth_rungs.values()) == {"unavailable"}

    w.ci(head2, pending=["test-postgres", "test-mysql", "test-sqlite"])
    w.tick()
    wi = w.wi(wi.id or 0)
    row = w.pr_row(wi.id or 0)
    assert row is not None
    assert wi.state is WorkItemState.checks_running  # lifecycle waits for every check
    assert wi.verification_depth is D.targeted_unit  # depth reports what is already proven
    assert row.depth_rungs["db_subset"] == "pending"


# ------------------------------------------------------------------------------ migration


def _downgrade_to_v2(path: Path) -> None:
    """Turn a fresh database into the shape a version-2 controller left behind."""
    engine = open_database(path)
    with engine.begin() as conn:
        for stmt in (
            "DROP TABLE verification_checks",
            "ALTER TABLE work_items DROP COLUMN verification_depth",
            "ALTER TABLE work_items RENAME COLUMN lifecycle_level TO verification_level",
            "ALTER TABLE pull_requests DROP COLUMN verification_depth",
            "ALTER TABLE pull_requests DROP COLUMN depth_rungs",
            "ALTER TABLE pull_requests DROP COLUMN review_id",
            "ALTER TABLE pull_requests DROP COLUMN review_head_sha",
            "ALTER TABLE pull_requests RENAME COLUMN lifecycle_level TO verification_level",
            "DELETE FROM schema_version",
        ):
            conn.execute(text(stmt))
    with Session(engine) as db:
        db.add(SchemaVersion(version=2))
        db.commit()
    engine.dispose()


def _columns(path: Path, table: str) -> set[str]:
    """Inspect without going through `open_database`, which would migrate as a side effect."""
    with sqlite3.connect(path) as conn:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


def _tables(path: Path) -> set[str]:
    with sqlite3.connect(path) as conn:
        return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def test_opening_a_v2_database_migrates_it_in_place(tmp_path: Path) -> None:
    path = tmp_path / "old.sqlite3"
    _downgrade_to_v2(path)
    assert "verification_level" in _columns(path, "work_items")
    assert "verification_checks" not in _tables(path)

    engine = open_database(path)  # init_db migrates before create_all
    with Session(engine) as db:
        versions = [v.version for v in db.exec(select(SchemaVersion).order_by(SchemaVersion.id))]  # type: ignore[arg-type]
        assert versions == [2, 3] and SCHEMA_VERSION == 3
        # Repeat open is a no-op.
        assert migrate(engine) == []
    engine.dispose()
    wi_cols = _columns(path, "work_items")
    pr_cols = _columns(path, "pull_requests")
    assert {"lifecycle_level", "verification_depth"} <= wi_cols
    assert "verification_level" not in wi_cols
    assert {"lifecycle_level", "verification_depth", "depth_rungs", "review_id"} <= pr_cols
    assert "verification_checks" in _tables(path)


def test_fresh_database_starts_at_current_version_without_migrating(tmp_path: Path) -> None:
    engine = open_database(tmp_path / "fresh.sqlite3")
    with Session(engine) as db:
        versions = [v.version for v in db.exec(select(SchemaVersion))]
    assert versions == [SCHEMA_VERSION]
    assert migrate(engine) == []
