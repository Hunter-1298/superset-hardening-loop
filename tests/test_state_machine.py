from __future__ import annotations

import pytest

from hardening_loop.domain.enums import (
    ACU_CAPS,
    CLOSING_FINDING_STATES,
    FindingState,
    Kind,
    VerificationLevel,
    WorkItemState,
)
from hardening_loop.orchestrator.state import (
    FINDING_TRANSITIONS,
    WORK_ITEM_TRANSITIONS,
    FindingEvent,
    InvalidTransitionError,
    WorkItemEvent,
    next_finding_state,
    next_work_item_state,
)

W, E = WorkItemState, WorkItemEvent
F, FE = FindingState, FindingEvent


def test_acu_caps_in_brief_order() -> None:
    assert [ACU_CAPS[k] for k in sorted(Kind)] == [5, 8, 20, 3, 6]


def test_verification_ladder() -> None:
    assert [v.label for v in VerificationLevel] == [
        "L0 none",
        "L1 pr_opened",
        "L2 ci_green",
        "L3 review_completed",
        "L4 human_approved",
        "L5 merged",
        "L6 rescan_verified",
    ]


def test_happy_path_work_item() -> None:
    path = [
        (E.issue_created, W.issue_open),
        (E.dispatch_started, W.dispatching),
        (E.session_created, W.session_active),
        (E.pr_opened, W.pr_open),
        (E.checks_started, W.checks_running),
        (E.checks_green, W.review_pending),
        (E.review_completed, W.ready_for_human),
        (E.human_merged, W.merged),
        (E.rescan_started, W.awaiting_rescan),
        (E.rescan_verified, W.verified),
    ]
    state = W.queued
    for event, expected in path:
        state = next_work_item_state(state, event)
        assert state is expected


def test_same_session_retry_loop_and_exhaustion() -> None:
    s = next_work_item_state(W.checks_running, E.checks_red)
    assert s is W.checks_failed
    assert next_work_item_state(s, E.retry_sent) is W.session_active
    assert next_work_item_state(s, E.retries_exhausted) is W.failed
    assert next_work_item_state(W.failed, E.human_retry) is W.issue_open


def test_merged_never_reaches_verified_without_rescan() -> None:
    with pytest.raises(InvalidTransitionError):
        next_work_item_state(W.merged, E.rescan_verified)
    with pytest.raises(InvalidTransitionError):
        next_work_item_state(W.ready_for_human, E.rescan_verified)


def test_rescan_present_is_needs_human_not_verified() -> None:
    assert next_work_item_state(W.awaiting_rescan, E.rescan_shows_present) is W.needs_human


def test_blocked_from_every_active_state() -> None:
    for state in (W.session_active, W.pr_open, W.checks_running, W.checks_failed, W.review_pending):
        assert next_work_item_state(state, E.blocked) is W.needs_human


def test_no_transition_out_of_verified_or_abandoned() -> None:
    for state in (W.verified, W.abandoned):
        assert not [k for k in WORK_ITEM_TRANSITIONS if k[0] is state]


def test_finding_outcomes_are_distinct_and_reachable() -> None:
    assert next_finding_state(F.awaiting_rescan, FE.closing_absent) is F.fixed
    assert next_finding_state(F.awaiting_rescan, FE.closing_vex) is F.approved_disposition
    assert (
        next_finding_state(F.in_remediation, FE.disagreement_resolved)
        is F.scanner_disagreement_resolved
    )
    assert next_finding_state(F.fixed, FE.reappeared) is F.regression
    assert next_finding_state(F.in_remediation, FE.human_blocked) is F.human_blocked
    assert next_finding_state(F.open, FE.unclassifiable) is F.unclassified
    assert {
        F.fixed,
        F.approved_disposition,
        F.scanner_disagreement_resolved,
    } == CLOSING_FINDING_STATES
    assert F.regression not in CLOSING_FINDING_STATES
    assert F.human_blocked not in CLOSING_FINDING_STATES
    assert F.unclassified not in CLOSING_FINDING_STATES


def test_unclassified_cannot_enter_remediation() -> None:
    with pytest.raises(InvalidTransitionError):
        next_finding_state(F.unclassified, FE.remediation_started)
    with pytest.raises(InvalidTransitionError):
        next_finding_state(F.unclassified, FE.grouped)


def test_transition_tables_only_reference_valid_enums() -> None:
    for (ws, we), wt in WORK_ITEM_TRANSITIONS.items():
        assert isinstance(ws, W) and isinstance(we, E) and isinstance(wt, W)
    for (fs, fe), ft in FINDING_TRANSITIONS.items():
        assert isinstance(fs, F) and isinstance(fe, FE) and isinstance(ft, F)
