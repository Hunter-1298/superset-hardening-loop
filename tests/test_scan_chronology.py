"""Scan state follows scan chronology, not the order the controller happened to ingest runs in.
The poller lists newest first and drains a backlog across several polls, so an older scan can
land after a newer one; it must never become the "current" run or overwrite what the newer scan
said about a finding."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest

from hardening_loop.config import BASELINE_SHA, FORK_REPO
from hardening_loop.dashboard.app import header_context
from hardening_loop.domain.enums import FindingState, Kind, Scanner, Severity
from hardening_loop.metrics import compute_metrics
from hardening_loop.replay.synth import SEEDS
from hardening_loop.replay.world import World
from hardening_loop.report.run_report import select_runs

CVE = "CVE-2024-26130"  # cryptography seed


@pytest.fixture
def w(tmp_path: Path) -> World:
    return World(tmp_path / "replay.sqlite3")


def _newer_then_older(
    w: World, newer_keys: tuple[str, ...], older_keys: tuple[str, ...]
) -> tuple[int, int]:
    """Ingest a run that finished later first, then one that finished earlier."""
    w.baseline("cryptography")
    w.clock.advance(minutes=60)
    newer = w.ingest(w.closing_run(BASELINE_SHA, *newer_keys), "newer")
    w.clock.advance(minutes=-30)
    older = w.ingest(w.closing_run(BASELINE_SHA, *older_keys), "older")
    finished = {r.id: r.finished_at for r in w.scan_runs()}
    older_finished, newer_finished = finished[older], finished[newer]
    assert older_finished is not None and newer_finished is not None
    assert older_finished < newer_finished
    return newer, older


def test_older_scan_ingested_later_does_not_overwrite_severity_or_fix_versions(w: World) -> None:
    w.baseline("cryptography")
    w.clock.advance(minutes=60)
    rescored = w.closing_run(BASELINE_SHA)
    rescored.seeds = [
        replace(SEEDS["cryptography"], vulns=((CVE, Severity.critical, ("42.0.4", "42.0.5")),))
    ]
    newer = w.ingest(rescored, "newer")
    w.clock.advance(minutes=-30)
    older = w.ingest(w.closing_run(BASELINE_SHA, "cryptography"), "older")  # high, 42.0.4

    f = w.finding_by_vuln(CVE)
    assert f.id is not None
    assert f.severity is Severity.critical, "the later scan's view wins regardless of ingest order"
    assert f.fix_versions_by_scanner["trivy"] == ["42.0.4", "42.0.5"]
    assert f.last_seen_run_id == newer
    assert f.first_seen_run_id == w.run_ids["replay-baseline"]
    assert f.state is FindingState.open
    # The older run's evidence is still recorded, it just does not describe the present.
    assert older in {s.scan_run_id for s in w.sightings(f.id)}


def test_older_scan_that_predates_first_sighting_becomes_first_seen(w: World) -> None:
    """A backlog run older than the baseline is still evidence of when the finding first existed."""
    w.baseline("cryptography")
    w.clock.advance(minutes=-120)
    older = w.ingest(w.closing_run(BASELINE_SHA, "cryptography"), "older")
    f = w.finding_by_vuln(CVE)
    assert f.first_seen_run_id == older
    assert f.last_seen_run_id == w.run_ids["replay-baseline"]


def test_older_scan_ingested_later_does_not_overwrite_classification(w: World) -> None:
    w.baseline("cryptography")
    w.clock.advance(minutes=60)
    disputed = w.closing_run(BASELINE_SHA)
    disputed.seeds = [SEEDS["cryptography"].with_reporters(Scanner.trivy)]
    newer = w.ingest(disputed, "newer")  # only trivy still reports it: scanner disagreement
    w.clock.advance(minutes=-30)
    w.ingest(w.closing_run(BASELINE_SHA, "cryptography"), "older")  # both scanners, kind 1

    f = w.finding_by_vuln(CVE)
    assert f.id is not None
    assert f.kind is Kind.scanner_disagreement
    assert f.reported_by_trivy and not f.reported_by_grype
    assert f.last_seen_run_id == newer


def test_older_scan_ingested_later_does_not_reopen_a_finding_the_newer_scan_closed(
    w: World,
) -> None:
    w.baseline("cryptography")
    w.clock.advance(minutes=60)
    newer = w.ingest(w.closing_run(BASELINE_SHA), "newer")  # absent
    assert w.orch.apply_pending_scan_runs()[newer] == {"fixed_by_drift": 1}
    assert w.finding_by_vuln(CVE).state is FindingState.fixed

    w.clock.advance(minutes=-30)
    older = w.ingest(w.closing_run(BASELINE_SHA, "cryptography"), "older")  # present, earlier
    f = w.finding_by_vuln(CVE)
    assert f.state is FindingState.fixed and f.closed_by_run_id == newer
    assert w.orch.apply_pending_scan_runs() == {older: {}}
    assert w.finding_by_vuln(CVE).state is FindingState.fixed


def test_latest_run_everywhere_is_the_one_that_finished_last(w: World) -> None:
    """Work-item creation, the dashboard header, metrics and the report all agree on which run
    is current, and none of them pick the most recently ingested one."""
    newer, older = _newer_then_older(w, ("cryptography", "pillow"), ("cryptography",))
    runs = w.scan_runs()
    assert [r.id for r in runs] == [w.run_ids["replay-baseline"], newer, older]

    # pillow was only ever reported by the newer scan; it is current and gets a work item.
    created = w.orch.create_work_items()
    assert {w.wi(i).group_key for i in created} == {"pypi:cryptography", "pypi:pillow"}

    header = header_context(w.engine, "main").latest_run
    assert header is not None and header.id == newer
    metrics = compute_metrics(w.engine, acu_cost_usd=None, now=datetime(2026, 9, 2, tzinfo=UTC))
    assert metrics.latest_main_run_id == newer
    _, latest = select_runs(runs, fork_repo=FORK_REPO, branch="main")
    assert latest is not None and latest.id == newer
