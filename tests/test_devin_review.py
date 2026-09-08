"""Devin Review through the v3 `pr-reviews` resource: triggered once per PR head, polled by the
exact `commit_sha`, `completed` is the only state that advances a work item, and everything else
(second error, cancellation, a review of a different commit that never catches up, API failure,
timeout) hands the item to a human rather than being guessed around."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
from pydantic import SecretStr

from hardening_loop.devin.fake import FakeDevin, FakeDevinError
from hardening_loop.devin.protocol import ReviewStatus
from hardening_loop.devin.rest import DevinError, DevinRest
from hardening_loop.domain.enums import LifecycleLevel, WorkItemState
from hardening_loop.replay.scenarios import DEP_FILES, _dep_output
from hardening_loop.replay.world import World, sha

PR_URL = "https://github.com/Hunter-1298/superset/pull/12"
HEAD = "a" * 40


# ------------------------------------------------------------------------- REST contract


def _review_json(status: str, commit: str = HEAD) -> dict[str, object]:
    return {
        "status": status,
        "repo_path": "Hunter-1298/superset",
        "pr_number": 12,
        "commit_sha": commit,
        "created_at": "2026-09-07T01:02:03Z",
        "extra_field_from_a_newer_api": True,
    }


def _client(handler: object) -> tuple[DevinRest, list[httpx.Request]]:
    calls: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        assert callable(handler)
        resp = handler(request)
        assert isinstance(resp, httpx.Response)
        return resp

    return (
        DevinRest(
            SecretStr("sk-super-secret"),
            "org-test",
            transport=httpx.MockTransport(wrapped),
            sleep=lambda _s: None,
        ),
        calls,
    )


def test_rest_trigger_posts_pr_url_to_pr_reviews() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/v3/organizations/org-test/pr-reviews"
        assert json.loads(request.content) == {"pr_url": PR_URL}
        return httpx.Response(200, json=_review_json("pending"))

    client, calls = _client(handler)
    snap = client.trigger_review(PR_URL)
    assert snap.status is ReviewStatus.pending
    assert snap.commit_sha == HEAD
    assert snap.pr_number == 12
    assert len(calls) == 1


def test_rest_get_scopes_by_pr_url_and_commit_sha() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        assert request.url.path == "/v3/organizations/org-test/pr-reviews"
        assert request.url.params["pr_url"] == PR_URL
        assert request.url.params["commit_sha"] == HEAD
        return httpx.Response(200, json=_review_json("completed"))

    client, _ = _client(handler)
    snap = client.get_review(PR_URL, HEAD)
    assert snap is not None and snap.status is ReviewStatus.completed


def test_rest_get_404_means_no_review_for_that_commit() -> None:
    client, _ = _client(
        lambda _r: httpx.Response(404, json={"detail": "no review for this commit"})
    )
    assert client.get_review(PR_URL, HEAD) is None


def test_rest_rejects_unknown_status_and_never_leaks_the_key() -> None:
    client, _ = _client(lambda _r: httpx.Response(200, json=_review_json("approved")))
    with pytest.raises(DevinError) as exc:
        client.get_review(PR_URL, HEAD)
    assert "sk-super-secret" not in str(exc.value)

    client2, _ = _client(lambda _r: httpx.Response(403, json={"detail": "UseReviewManual"}))
    with pytest.raises(DevinError) as exc2:
        client2.trigger_review(PR_URL)
    assert "403" in str(exc2.value) and "sk-super-secret" not in str(exc2.value)


# ------------------------------------------------------------------------- fake


def test_fake_review_lifecycle_and_head_tracking() -> None:
    fake = FakeDevin()
    with pytest.raises(FakeDevinError):
        fake.trigger_review(PR_URL)
    fake.set_pr_head(PR_URL, HEAD)
    assert fake.get_review(PR_URL, HEAD) is None
    snap = fake.trigger_review(PR_URL)
    assert snap.status is ReviewStatus.pending and snap.commit_sha == HEAD
    polled = fake.get_review(PR_URL, HEAD)
    assert polled is not None and polled.status is ReviewStatus.running
    # Re-triggering a live review is idempotent.
    assert fake.trigger_review(PR_URL).status is ReviewStatus.running
    with pytest.raises(FakeDevinError):
        fake.finish_review(PR_URL, "b" * 40)
    fake.finish_review(PR_URL, HEAD, ReviewStatus.errored)
    # A terminal review can be re-triggered; a new pending one replaces it.
    assert fake.trigger_review(PR_URL).status is ReviewStatus.pending
    # A different head is a different review.
    assert fake.get_review(PR_URL, "b" * 40) is None


# ------------------------------------------------------------------------- engine


def _to_review_pending(w: World) -> tuple[int, int, str]:
    w.baseline("cryptography")
    w.tick()
    wi = w.only_wi()
    _url, number = w.devin_opens_pr(
        wi, _dep_output("cryptography", "42.0.2", "42.0.4"), files=DEP_FILES, acus=2.0
    )
    w.tick()
    head = w.gh.prs[number].head_sha
    w.ci(head)
    w.tick()
    assert w.state_of(wi.id or 0) is WorkItemState.review_pending
    return wi.id or 0, number, head


def _review_calls(w: World, kind: str) -> list[str]:
    return [arg for name, arg in w.devin.calls if name == kind]


def test_review_triggered_once_per_head_then_completed_advances(tmp_path: Path) -> None:
    w = World(tmp_path / "r.sqlite3")
    wi_id, _number, head = _to_review_pending(w)
    assert len(_review_calls(w, "trigger_review")) == 1
    assert _review_calls(w, "get_review") and all(
        c.endswith(f"@{head}") for c in _review_calls(w, "get_review")
    )
    row = w.pr_row(wi_id)
    assert row is not None
    assert row.review_head_sha == head and row.review_status == "pending"
    w.tick()
    assert len(_review_calls(w, "trigger_review")) == 1, "polls, does not re-trigger"
    assert w.state_of(wi_id) is WorkItemState.review_pending
    row = w.pr_row(wi_id)
    assert row is not None and row.review_status == "running"
    w.review_done(head)
    w.tick()
    wi = w.wi(wi_id)
    assert wi.state is WorkItemState.ready_for_human
    assert wi.lifecycle_level == LifecycleLevel.review_completed
    row = w.pr_row(wi_id)
    assert row is not None
    assert row.review_status == "completed" and row.review_head_sha == head
    assert row.review_id is not None and head in row.review_id


def test_review_errored_is_retriggered_once_then_needs_human(tmp_path: Path) -> None:
    w = World(tmp_path / "r.sqlite3")
    wi_id, _number, head = _to_review_pending(w)
    w.review_done(head, ReviewStatus.errored)
    w.tick()
    assert len(_review_calls(w, "trigger_review")) == 2
    assert w.state_of(wi_id) is WorkItemState.review_pending
    reasons = [e.reason or "" for e in w.events("pull_request") if e.event == "review_triggered"]
    assert any(r.startswith("review errored") for r in reasons)
    w.review_done(head, ReviewStatus.errored)
    w.tick()
    wi = w.wi(wi_id)
    assert wi.state is WorkItemState.needs_human
    assert wi.blocked_reason and "errored twice" in wi.blocked_reason
    assert len(_review_calls(w, "trigger_review")) == 2, "no third attempt"


def test_review_cancelled_needs_human(tmp_path: Path) -> None:
    w = World(tmp_path / "r.sqlite3")
    wi_id, _number, head = _to_review_pending(w)
    w.review_done(head, ReviewStatus.cancelled)
    w.tick()
    wi = w.wi(wi_id)
    assert wi.state is WorkItemState.needs_human
    assert wi.blocked_reason and "cancelled" in wi.blocked_reason


def test_review_that_never_finishes_times_out_to_needs_human(tmp_path: Path) -> None:
    w = World(tmp_path / "r.sqlite3", review_timeout_minutes=30)
    wi_id, _number, _head = _to_review_pending(w)
    w.tick(minutes=10)
    w.tick(minutes=10)
    assert w.state_of(wi_id) is WorkItemState.review_pending
    w.tick(minutes=15)
    wi = w.wi(wi_id)
    assert wi.state is WorkItemState.needs_human
    assert wi.blocked_reason and "still running" in wi.blocked_reason


def test_review_api_error_waits_then_times_out(tmp_path: Path) -> None:
    w = World(tmp_path / "r.sqlite3", review_timeout_minutes=30)
    wi_id, _number, _head = _to_review_pending(w)
    w.devin.fail_next["get_review"] = RuntimeError("403 UseReviewManual missing")
    w.tick(minutes=5)
    assert w.state_of(wi_id) is WorkItemState.review_pending, "one failure is not a verdict"
    for _ in range(6):
        w.devin.fail_next["get_review"] = RuntimeError("403 UseReviewManual missing")
        w.tick(minutes=5)
    wi = w.wi(wi_id)
    assert wi.state is WorkItemState.needs_human
    assert wi.blocked_reason and "API error" in wi.blocked_reason
    assert "sk-" not in (wi.blocked_reason or "")


def test_new_push_gets_its_own_review_and_old_one_is_ignored(tmp_path: Path) -> None:
    w = World(tmp_path / "r.sqlite3")
    wi_id, number, head1 = _to_review_pending(w)
    head2 = sha("cryptography-push-2")
    w.gh.push(number, head2)
    w.ci(head2)
    w.tick()
    w.tick()
    assert w.state_of(wi_id) is WorkItemState.review_pending
    # Finishing the stale head's review must not advance the item.
    w.review_done(head1)
    w.tick()
    assert w.state_of(wi_id) is WorkItemState.review_pending
    pr_url = f"https://github.com/{w.gh.repo}/pull/{number}"
    assert w.devin.review_status(pr_url, head2) is not None
    w.review_done(head2)
    w.tick()
    wi = w.wi(wi_id)
    assert wi.state is WorkItemState.ready_for_human
    row = w.pr_row(wi_id)
    assert row is not None and row.review_head_sha == head2
