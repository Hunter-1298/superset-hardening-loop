"""A scan run owes the controller exactly one closing evaluation, whoever persisted it and whenever
it is noticed: the CLI, the poller, a run that outlived a crash, or a backlog drained out of order.
`ScanRun.closure_applied_at` is the durable marker; the replay world stands in for every path that
writes a run without evaluating it."""

from __future__ import annotations

from pathlib import Path

import pytest

from hardening_loop.config import BASELINE_SHA
from hardening_loop.domain.enums import FindingState, WorkItemState
from hardening_loop.github.fake import FakeGitHubError
from hardening_loop.metrics import metrics_history
from hardening_loop.models.tables import WorkItem
from hardening_loop.operator import OperatorContext
from hardening_loop.replay.world import APPROVER, World, sha

CVE = "CVE-2024-26130"  # cryptography seed
MERGE_SHA = sha("merge-closure-failure")


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


def test_a_scan_that_retires_queued_work_is_spent_before_the_tick_can_dispatch_it(
    w: World,
) -> None:
    """An operator tick groups the finding and opens its issue; before anything is launched a scan
    of main shows the package is already gone. The next tick must spend that scan first: launching
    the session and then discovering the work was obsolete bills ACUs for nothing."""
    w.orch.tick(auto_dispatch=False)  # issue-only pass, one per settings.auto_open_issues
    w.baseline("cryptography")
    report = w.orch.tick(auto_dispatch=False)
    assert report.issues_created == 1 and report.sessions_created == 0
    wi = w.only_wi()
    assert wi.state is WorkItemState.issue_open
    assert w.issue_state(wi) == "open"

    w.clock.advance(minutes=30)
    rid = w.ingest(w.closing_run(BASELINE_SHA))  # cryptography gone from main

    report = w.tick()  # auto_dispatch=True: the launch the scan makes pointless
    assert report.scans_applied >= 1 and report.scan_apply_error is None
    assert report.sessions_created == 0 and report.sessions_adopted == 0
    assert w.sessions() == [] and w.devin.sessions == {}
    assert w.state_of(wi.id or 0) is WorkItemState.abandoned
    f = w.finding_by_vuln(CVE)
    assert f.state is FindingState.fixed and f.closed_by_run_id == rid
    assert w.issue_state(wi) == "closed"


def test_a_run_whose_application_failed_holds_grouping_and_dispatch_until_it_is_spent(
    w: World,
) -> None:
    """The pending run may be the very evidence that makes the queued work pointless, so a tick
    that could not apply it neither groups the new finding it carries, nor files, nor launches
    anything; the next tick that does apply it retires the stale item and only then moves on."""
    w.orch.tick(auto_dispatch=False)
    w.baseline("cryptography")
    w.orch.tick(auto_dispatch=False)
    wi = w.only_wi()
    assert wi.state is WorkItemState.issue_open
    w.clock.advance(minutes=30)
    rid = w.ingest(w.closing_run(BASELINE_SHA, "pillow"))  # cryptography gone, pillow new
    w.gh.fail_next["close_issue"] = FakeGitHubError("issues api unavailable")

    report = w.tick()  # auto_dispatch=True
    assert report.scan_apply_error == "FakeGitHubError: issues api unavailable"
    assert report.scans_applied == 0 and report.sessions_polled == 0
    assert (report.work_items_created, report.issues_created, report.sessions_created) == (0, 0, 0)
    assert w.devin.sessions == {} and w.sessions() == []
    assert [i.id for i in w.work_items()] == [wi.id], "pillow stays ungrouped"
    assert w.state_of(wi.id or 0) is WorkItemState.issue_open
    assert w.orch.pending_scan_runs() == [rid]

    report = w.tick()  # the issues api recovers
    assert report.scan_apply_error is None and report.scans_applied == 1
    assert w.state_of(wi.id or 0) is WorkItemState.abandoned
    assert w.issue_state(wi) == "closed"
    assert report.work_items_created == 1 and report.sessions_created == 1
    (pillow,) = [i for i in w.work_items() if i.id != wi.id]
    assert pillow.state is WorkItemState.session_active
    assert [s.work_item_id for s in w.sessions()] == [pillow.id], "the only session is pillow's"


def _merged_item_awaiting_its_closing_scan(w: World) -> WorkItem:
    """A dependency work item taken through to a PR merged at `MERGE_SHA`."""
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
    w.gh.approve(number, APPROVER, at=w.clock.now())
    w.tick()
    w.gh.merge(number, MERGE_SHA, at=w.clock.now())
    w.tick()
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.merged
    return wi


def test_a_github_failure_during_closure_leaves_the_run_pending_without_losing_the_tick(
    w: World,
) -> None:
    """The issue call that finishes a closure can fail. The run keeps its pending marker so the
    evaluation is retried whole, and the rest of the tick — including the operator's metrics
    snapshot — still happens instead of dying with the GitHub error."""
    wi = _merged_item_awaiting_its_closing_scan(w)
    w.clock.advance(minutes=20)
    rid = w.ingest(w.closing_run(MERGE_SHA))
    ctx = OperatorContext.for_doubles(w.orch, login=APPROVER)
    w.gh.fail_next["close_issue"] = FakeGitHubError("issues api unavailable")

    report = ctx.tick()
    assert report.scan_apply_error == "FakeGitHubError: issues api unavailable"
    assert report.scans_applied == 0
    assert [r.trigger for r in metrics_history(w.orch.engine)] == ["tick"], "metrics persisted"
    assert _applied(w)[-1] is False, "the run is still owed an evaluation"
    assert w.finding_by_vuln(CVE).state is FindingState.awaiting_rescan
    assert w.state_of(wi.id or 0) is WorkItemState.merged, "the rolled-back closure left no trace"
    assert w.orch.pending_scan_runs() == [rid]
    assert w.issue_state(wi) == "open"

    report = ctx.tick()  # the issues api recovers
    assert report.scan_apply_error is None and report.scans_applied == 1
    assert _applied(w)[-1] is True
    f = w.finding_by_vuln(CVE)
    assert f.state is FindingState.fixed and f.closed_by_run_id == rid
    assert w.state_of(wi.id or 0) is WorkItemState.verified
    assert w.issue_state(wi) == "closed"
