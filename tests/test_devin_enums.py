"""Exact v3 enum values, predicates and needs_human assessment over the full cross product."""

from __future__ import annotations

import itertools
from typing import Any

import pytest
from pydantic import ValidationError

from hardening_loop.devin.enums import (
    BUDGET_STOP_DETAILS,
    DevinStatus,
    DevinStatusDetail,
    Outcome,
    SessionPullRequest,
    SessionSnapshot,
)
from hardening_loop.orchestrator.assess import Decision, SessionFacts, assess

OPENAPI_STATUS = ["new", "claimed", "running", "exit", "error", "suspended", "resuming"]
OPENAPI_STATUS_DETAIL = [
    "working",
    "waiting_for_user",
    "waiting_for_approval",
    "finished",
    "inactivity",
    "user_request",
    "usage_limit_exceeded",
    "out_of_credits",
    "out_of_quota",
    "no_quota_allocation",
    "payment_declined",
    "org_usage_limit_exceeded",
    "user_usage_limit_exceeded",
    "total_session_limit_exceeded",
    "error",
]


def snap(
    status: str,
    detail: str | None,
    *,
    acus: float = 1.0,
    output: dict[str, Any] | None = None,
    prs: list[str] | None = None,
) -> SessionSnapshot:
    return SessionSnapshot(
        session_id="devin-x",
        status=DevinStatus(status),
        status_detail=DevinStatusDetail(detail) if detail else None,
        acus_consumed=acus,
        structured_output=output,
        pull_requests=[SessionPullRequest(pr_url=u) for u in (prs or [])],
    )


def test_enums_match_openapi_exactly() -> None:
    assert [s.value for s in DevinStatus] == OPENAPI_STATUS
    assert [d.value for d in DevinStatusDetail] == OPENAPI_STATUS_DETAIL


def test_unknown_values_are_rejected_not_coerced() -> None:
    with pytest.raises(ValidationError):
        SessionSnapshot(session_id="x", status="paused")
    with pytest.raises(ValidationError):
        SessionSnapshot(session_id="x", status=DevinStatus.running, status_detail="thinking")


def test_is_done_rules() -> None:
    assert snap("exit", None).is_done
    assert snap("error", None).is_done
    assert snap("running", "finished").is_done
    for detail in ("working", "waiting_for_user", "waiting_for_approval"):
        assert not snap("running", detail).is_done
    for status in ("new", "claimed", "suspended", "resuming"):
        assert not snap(status, None).is_done


def test_budget_stop_is_every_quota_credit_state() -> None:
    expected = {
        "usage_limit_exceeded",
        "out_of_credits",
        "out_of_quota",
        "no_quota_allocation",
        "payment_declined",
        "org_usage_limit_exceeded",
        "user_usage_limit_exceeded",
        "total_session_limit_exceeded",
    }
    assert {d.value for d in BUDGET_STOP_DETAILS} == expected
    for d in expected:
        assert snap("suspended", d).is_budget_stop
        assert not snap("suspended", d).is_resumable_suspension


def test_resumable_suspension() -> None:
    assert snap("suspended", "inactivity").is_resumable_suspension
    assert snap("suspended", "user_request").is_resumable_suspension
    assert snap("suspended", "inactivity").is_active
    assert not snap("running", "inactivity").is_resumable_suspension


def test_output_predicates() -> None:
    blocked = snap("exit", None, output={"outcome": "blocked", "blocked_reason": "upper bound"})
    assert blocked.output_blocked and blocked.outcome is Outcome.blocked
    assert not snap(
        "exit", None, output={"outcome": "blocked", "blocked_reason": " "}
    ).output_blocked
    assert snap("exit", None, output={"outcome": "no_change_needed"}).no_change_needed
    assert snap("exit", None, output={"outcome": "weird"}).outcome is None
    assert snap("exit", None).outcome is None


FACTS_OK = SessionFacts(acu_cap=5, schema_valid=True, pr_verified=True, diff_policy_ok=True)
FACTS_NO_OUTPUT = SessionFacts(
    acu_cap=5, schema_valid=False, pr_verified=False, diff_policy_ok=False
)
PR_OUT: dict[str, Any] = {
    "outcome": "pr_opened",
    "pr_url": "https://github.com/Hunter-1298/superset/pull/9",
}


@pytest.mark.parametrize(
    ("status", "detail"), list(itertools.product(OPENAPI_STATUS, [*OPENAPI_STATUS_DETAIL, None]))
)
def test_every_status_combination_has_a_decision(status: str, detail: str | None) -> None:
    s = snap(status, detail, output=PR_OUT, prs=[PR_OUT["pr_url"]])
    a = assess(s, FACTS_OK)
    assert isinstance(a.decision, Decision)
    if s.is_budget_stop or s.is_error or s.is_waiting_for_approval:
        assert a.decision is Decision.needs_human
    elif s.is_waiting_for_user:
        assert a.decision is Decision.needs_human  # no whitelisted question supplied
    elif s.is_done:
        assert a.decision is Decision.ready_for_verification
    else:
        assert a.decision is Decision.continue_polling


def test_done_without_valid_output_is_needs_human() -> None:
    a = assess(snap("exit", None), FACTS_NO_OUTPUT)
    assert a.is_needs_human and a.reason == "final_output_missing_or_invalid"


def test_blocked_output_surfaces_reason() -> None:
    s = snap("running", "finished", output={"outcome": "blocked", "blocked_reason": "needs VEX"})
    a = assess(s, FACTS_OK)
    assert a.is_needs_human and a.reason == "blocked_reason:needs VEX"


def test_no_change_needed_never_verifies() -> None:
    s = snap("exit", None, output={"outcome": "no_change_needed", "reason": "x", "evidence": []})
    a = assess(s, FACTS_OK)
    assert a.is_needs_human and "no_change_needed" in a.reason


def test_pr_claimed_but_missing_or_unverified() -> None:
    assert (
        assess(snap("exit", None, output=PR_OUT), FACTS_OK).reason
        == "pr_opened_claimed_but_no_pull_request"
    )
    facts = SessionFacts(acu_cap=5, schema_valid=True, pr_verified=False, diff_policy_ok=True)
    a = assess(snap("exit", None, output=PR_OUT, prs=["u"]), facts)
    assert a.reason == "pull_request_failed_verification"
    facts = SessionFacts(acu_cap=5, schema_valid=True, pr_verified=True, diff_policy_ok=False)
    assert (
        assess(snap("exit", None, output=PR_OUT, prs=["u"]), facts).reason
        == "diff_policy_violation"
    )


def test_acu_cap_and_warning() -> None:
    assert assess(snap("running", "working", acus=5.5), FACTS_OK).reason.startswith(
        "acu_cap_exceeded"
    )
    a = assess(snap("running", "working", acus=4.6), FACTS_OK)
    assert a.decision is Decision.budget_warning
    facts = SessionFacts(
        acu_cap=5,
        schema_valid=True,
        pr_verified=True,
        diff_policy_ok=True,
        budget_warning_sent=True,
    )
    assert assess(snap("running", "working", acus=4.6), facts).decision is Decision.continue_polling


def test_wall_clock() -> None:
    facts = SessionFacts(
        acu_cap=5,
        schema_valid=True,
        pr_verified=True,
        diff_policy_ok=True,
        wall_clock_exceeded=True,
    )
    assert assess(snap("running", "working"), facts).reason == "session_wall_clock_exceeded"


def test_waiting_for_user_whitelist() -> None:
    s = snap("running", "waiting_for_user")
    a = assess(s, FACTS_OK, pending_question="Which base branch should I target?")
    assert a.decision is Decision.answer_question and a.reply and "main" in a.reply
    a = assess(s, FACTS_OK, pending_question="Should I delete the production database?")
    assert a.is_needs_human and a.reason.startswith("devin_question_not_whitelisted")


def test_waiting_for_approval_is_needs_human() -> None:
    assert (
        assess(snap("running", "waiting_for_approval"), FACTS_OK).reason
        == "devin_action_approval_required"
    )
