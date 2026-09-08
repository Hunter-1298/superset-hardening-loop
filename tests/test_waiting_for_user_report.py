"""A session that posts its completion report as a chat message ends up in `running /
waiting_for_user`, not `finished`. Its structured output still says `pr_opened`, and the PR is
real: that is a result to verify, not a question for a human. A session waiting on a genuine
question stays a human matter; a merge observed after the closing scan was already evaluated is
weighed against that scan instead of waiting for the next one."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from hardening_loop.config import BASELINE_SHA
from hardening_loop.devin.enums import DevinStatus, DevinStatusDetail
from hardening_loop.domain.enums import FindingState, HumanLabel, WorkItemState
from hardening_loop.models.tables import WorkItem
from hardening_loop.replay.world import World, sha

CVE = "CVE-2024-26130"  # cryptography seed
FILES = ["pyproject.toml", "requirements/base.txt", "requirements/development.txt"]
PINS_ONLY = ["requirements/base.txt", "requirements/development.txt"]


@pytest.fixture
def w(tmp_path: Path) -> World:
    return World(tmp_path / "replay.sqlite3")


def _report_without_finishing(
    w: World, wi: WorkItem, files: list[str] = FILES, **output: Any
) -> tuple[str, int]:
    """Devin opens the PR, updates its structured output, posts the report as a message to the
    user and idles: exactly what the live session did."""
    assert wi.active_session_id is not None
    url = w.gh.open_pr(
        title=f"fix: {wi.title}"[:100],
        head_ref=f"devin/{wi.id}-{wi.kind.value}",
        head_sha=sha(f"pr-head-{wi.id}"),
        files=files,
    )
    number = int(url.rsplit("/", 1)[1])
    out: dict[str, Any] = {
        "outcome": "pr_opened",
        "pr_url": url,
        "base_branch": "main",
        "findings_addressed": [f.vuln_id for f in w.findings(wi.id)],
        "findings_not_addressed": [],
        "tests_run": [{"command": "pytest -q tests/unit", "exit_code": 0}],
        "packages": [{"name": "cryptography", "from": "42.0.4", "to": "42.0.5"}],
        "regenerated_with": "./scripts/uv-pip-compile.sh",
    }
    out.update(output)
    w.devin.set_state(
        wi.active_session_id,
        DevinStatus.running,
        DevinStatusDetail.waiting_for_user,
        acus=1.2,
        output=out,
        pull_requests=[url],
        question=f"PR opened: {url} — cryptography 42.0.4 → 42.0.5; local unit tests passed.",
    )
    return url, number


def _launch(w: World) -> WorkItem:
    w.baseline("cryptography")
    w.tick()
    wi = w.only_wi()
    assert wi.state is WorkItemState.session_active
    return wi


def test_pr_report_posted_as_a_message_is_verified_not_escalated(w: World) -> None:
    wi = _launch(w)
    url, number = _report_without_finishing(w, wi)

    w.tick()

    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.checks_running, wi.state
    assert wi.pr_number == number and wi.pr_url == url
    row = w.pr_row(wi.id or 0)
    assert row is not None and row.head_sha == w.gh.prs[number].head_sha
    assert "pr_opened" in w.event_names(wi.id or 0)
    assert "blocked" not in w.event_names(wi.id or 0)
    assert len(w.devin.sessions) == 1, "no second session"
    assert not any(m == "send_message" for m, _ in w.devin.calls), "nothing was sent to Devin"
    assert any(f"PR opened: {url}" in c for c in w.gh.issues[wi.issue_number or 0].comments)
    sessions = w.sessions()
    assert len(sessions) == 1 and sessions[0].status_detail == "waiting_for_user"
    assert sessions[0].finished_at is None


def test_genuine_question_while_waiting_still_needs_a_human(w: World) -> None:
    wi = _launch(w)
    assert wi.active_session_id is not None
    w.devin.set_state(
        wi.active_session_id,
        DevinStatus.running,
        DevinStatusDetail.waiting_for_user,
        question="Should I also bump cryptography's upper bound in pyproject.toml?",
    )
    w.tick()
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.needs_human
    assert wi.blocked_reason is not None
    assert wi.blocked_reason.startswith("devin_question_not_whitelisted")
    assert w.pr_row(wi.id or 0) is None


def test_pr_report_whose_pr_fails_verification_still_needs_a_human(w: World) -> None:
    wi = _launch(w)
    _report_without_finishing(w, wi, pr_url="https://github.com/apache/superset/pull/999")
    w.tick()
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.needs_human
    assert wi.blocked_reason is not None
    assert wi.blocked_reason.startswith("pull_request_failed_verification")
    assert w.pr_row(wi.id or 0) is None


def test_merge_observed_after_the_closing_scan_was_applied_still_closes(w: World) -> None:
    """The scan of the merge commit is evaluated while the item is not yet `merged` (the merge
    is noticed a tick later). That run is never applied twice; the item must still be closed by
    it rather than wait for a scan that may be a day away."""
    wi = _launch(w)
    _url, number = _report_without_finishing(w, wi)
    w.tick()
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.checks_running

    merge_sha = sha("merge-observed-late")
    w.gh.merge(number, merge_sha, at=w.clock.now())
    w.clock.advance(minutes=20)
    rid = w.ingest(w.closing_run(merge_sha))  # cryptography gone from main
    assert w.apply_run(rid) == {}, "nothing to close: the merge is not known yet"
    assert w.state_of(wi.id or 0) is WorkItemState.checks_running

    w.tick()
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.verified, wi.state
    names = w.event_names(wi.id or 0)
    assert (
        names.index("human_merged") < names.index("rescan_started") < names.index("rescan_verified")
    )
    f = w.finding_by_vuln(CVE)
    assert f.state is FindingState.fixed and f.closed_by_run_id == rid
    assert w.issue_state(wi) == "closed"
    assert w.gh.never_merged_or_approved()
    assert len(w.devin.sessions) == 1


def test_report_read_late_from_a_suspended_session_after_human_retry(w: World) -> None:
    """The live sequence: the report was first mistaken for a question (item parked in
    `needs_human`), the human merged the PR, the closing scan came in, and Devin suspended the
    idle session for inactivity long after the wall-clock bound. A `retry` label re-adopts that
    same session; its verdict is verified and the item closes against the scan already applied."""
    wi = _launch(w)
    sid = wi.active_session_id
    assert sid is not None
    w.devin.set_state(sid, DevinStatus.running, DevinStatusDetail.waiting_for_user, question="?")
    w.tick()
    assert w.state_of(wi.id or 0) is WorkItemState.needs_human

    # The fix version lay inside the declared range, so only the regenerated pins changed.
    url, number = _report_without_finishing(w, wi, files=PINS_ONLY)
    w.devin.set_state(
        sid, DevinStatus.suspended, DevinStatusDetail.inactivity, acus=1.2, pull_requests=[url]
    )
    merge_sha = sha("merged-while-parked")
    w.gh.merge(number, merge_sha, at=w.clock.now())
    w.clock.advance(minutes=30)
    rid = w.ingest(w.closing_run(merge_sha))
    assert w.apply_run(rid) == {}
    w.clock.advance(hours=4)

    w.gh.label(wi.issue_number or 0, HumanLabel.retry.value)
    w.tick()
    w.tick()
    w.tick()

    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.verified, (wi.state, wi.blocked_reason)
    assert wi.pr_number == number and wi.merge_sha == merge_sha
    names = w.event_names(wi.id or 0)
    assert "session_adopted" in names
    assert names.index("human_retry") < names.index("pr_opened") < names.index("human_merged")
    assert (
        names.index("human_merged") < names.index("rescan_started") < names.index("rescan_verified")
    )
    assert len(w.devin.sessions) == 1 and len(w.devin.created_requests()) == 1
    assert not any(m == "send_message" for m, _ in w.devin.calls)
    assert w.finding_by_vuln(CVE).state is FindingState.fixed
    assert w.issue_state(wi) == "closed"
    assert w.gh.never_merged_or_approved()


def test_a_scan_that_predates_the_merge_is_not_replayed_for_it(w: World) -> None:
    wi = _launch(w)
    _url, number = _report_without_finishing(w, wi)
    w.tick()
    w.clock.advance(minutes=20)
    rid = w.ingest(w.closing_run(BASELINE_SHA, "cryptography"))  # still present, pre-merge
    assert w.apply_run(rid) == {}
    w.clock.advance(minutes=20)
    w.gh.merge(number, sha("merge-after-scan"), at=w.clock.now())
    w.tick()
    wi = w.wi(wi.id or 0)
    assert wi.state is WorkItemState.merged, wi.state
    assert "rescan_started" not in w.event_names(wi.id or 0)
