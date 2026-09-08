"""A scan run owes the controller exactly one closing evaluation, whoever persisted it and whenever
it is noticed: the CLI, the poller, a run that outlived a crash, or a backlog drained out of order.
`ScanRun.closure_applied_at` is the durable marker; the replay world stands in for every path that
writes a run without evaluating it."""

from __future__ import annotations

from pathlib import Path

import pytest

from hardening_loop.config import BASELINE_SHA
from hardening_loop.domain.enums import FindingState, WorkItemState
from hardening_loop.replay.world import APPROVER, World, sha

CVE = "CVE-2024-26130"  # cryptography seed


@pytest.fixture
def w(tmp_path: Path) -> World:
    return World(tmp_path / "replay.sqlite3")


def _applied(w: World) -> list[bool]:
    return [r.closure_applied_at is not None for r in w.scan_runs()]


def test_run_persisted_without_the_orchestrator_is_evaluated_on_the_next_tick(w: World) -> None:
    """`ingest` (CLI) and the poller both stop at persisting the run; the tick owns closure."""
    w.baseline("cryptography")
    w.clock.advance(minutes=30)
    rid = w.ingest(w.closing_run(BASELINE_SHA))  # cryptography gone from main
    assert _applied(w) == [False, False]
    assert w.finding_by_vuln(CVE).state is FindingState.open

    report = w.orch.tick(auto_dispatch=False)
    assert (report.scans_ingested, report.scans_rejected) == (0, 0), "nothing new to pull"
    assert _applied(w) == [True, True]
    f = w.finding_by_vuln(CVE)
    assert f.state is FindingState.fixed and f.closed_by_run_id == rid
    events = len(w.events("finding", f.id))

    # Idempotent: neither the tick nor a direct re-application records anything twice.
    stamps = [r.closure_applied_at for r in w.scan_runs()]
    w.orch.tick(auto_dispatch=False)
    assert w.orch.apply_scan_run(rid) == {}
    assert [r.closure_applied_at for r in w.scan_runs()] == stamps
    assert len(w.events("finding", f.id)) == events


def test_direct_application_is_idempotent(w: World) -> None:
    w.baseline("cryptography")
    w.clock.advance(minutes=30)
    rid = w.ingest(w.closing_run(BASELINE_SHA))
    assert w.apply_run(rid) == {"fixed_by_drift": 1}
    f = w.finding_by_vuln(CVE)
    events = len(w.events("finding", f.id))
    assert w.apply_run(rid) == {}
    assert w.orch.apply_pending_scan_runs() == {w.run_ids["replay-baseline"]: {}}
    assert len(w.events("finding", f.id)) == events
    assert w.finding_by_vuln(CVE).state is FindingState.fixed


def test_merge_and_post_merge_scan_noticed_in_the_same_tick_close_the_work_item(w: World) -> None:
    """GitHub merges the PR and the scan of the merge commit finishes before the controller's
    next tick. That one tick must observe the merge first and then spend the scan as closing
    evidence; consuming the scan against the pre-merge state would leave the item waiting for
    a rescan that already happened."""
    w.baseline("cryptography")
    w.tick()
    wi = w.only_wi()
    _url, number = w.devin_opens_pr(
        wi,
        {
            "packages": [{"name": "cryptography", "from": "42.0.4", "to": "42.0.5"}],
            "regenerated_with": "./scripts/uv-pip-compile.sh",
        },
        files=["pyproject.toml", "requirements/base.txt", "requirements/development.txt"],
        acus=1.5,
    )
    w.tick()
    head = w.gh.prs[number].head_sha
    w.ci(head)
    w.tick()
    w.review_done(head)
    w.tick()
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.ready_for_human
    w.gh.approve(number, APPROVER, at=w.clock.now())
    w.tick()

    # Between two ticks: the human merges and the nightly scan of main at the merge commit runs.
    merge_sha = sha("merge-before-tick")
    w.gh.merge(number, merge_sha, at=w.clock.now())
    w.clock.advance(minutes=20)
    rid = w.ingest(w.closing_run(merge_sha))
    assert w.state_of(wi.id or 0) is WorkItemState.ready_for_human
    assert _applied(w)[-1] is False

    report = w.tick()
    assert report.scans_applied >= 1
    assert _applied(w)[-1] is True
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.verified, wi.state
    f = w.finding_by_vuln(CVE)
    assert f.state is FindingState.fixed and f.closed_by_run_id == rid
    assert w.issue_state(wi) == "closed"
    assert w.gh.never_merged_or_approved()


def test_backlog_is_evaluated_in_scan_order_and_an_older_run_cannot_outvote_a_newer_one(
    w: World,
) -> None:
    """The poller lists newest first, so an older run can be persisted after a newer one. Its
    silence about a finding the newer run still reports is not evidence of a fix."""
    w.baseline("cryptography")
    w.clock.advance(minutes=60)
    newer = w.ingest(w.closing_run(BASELINE_SHA, "cryptography"), "newer")  # still present
    w.clock.advance(minutes=-30)
    older = w.ingest(w.closing_run(BASELINE_SHA), "older")  # absent, but scanned earlier
    finished = {r.id: r.finished_at for r in w.scan_runs()}
    older_at, newer_at = finished[older], finished[newer]
    assert older_at is not None and newer_at is not None and older_at < newer_at

    assert w.orch.pending_scan_runs() == [w.run_ids["replay-baseline"], older, newer]
    applied = w.orch.apply_pending_scan_runs()
    assert applied[older] == {} and applied[newer] == {}
    assert w.finding_by_vuln(CVE).state is FindingState.open
    assert _applied(w) == [True, True, True]

    # The same absence in a run that is newer than the last sighting does close it.
    w.clock.advance(minutes=90)
    latest = w.ingest(w.closing_run(BASELINE_SHA), "latest")
    assert w.orch.apply_pending_scan_runs() == {latest: {"fixed_by_drift": 1}}
    assert w.finding_by_vuln(CVE).state is FindingState.fixed
