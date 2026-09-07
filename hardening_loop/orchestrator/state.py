"""Table-driven lifecycle state machines for WorkItems and Findings.

`next_work_item_state` / `next_finding_state` are pure functions. Anything not in the table is an
`InvalidTransitionError`; the orchestrator turns that into `needs_human` with a `blocked_reason`,
never into a guess.
"""

from __future__ import annotations

from enum import StrEnum

from hardening_loop.domain.enums import FindingState, WorkItemState


class WorkItemEvent(StrEnum):
    dispatch_approved = "dispatch_approved"  # severity default or human label
    issue_created = "issue_created"
    dispatch_started = "dispatch_started"
    session_created = "session_created"
    session_adopted = "session_adopted"  # reconciliation found an existing session
    dispatch_failed = "dispatch_failed"
    pr_opened = "pr_opened"
    checks_started = "checks_started"
    checks_green = "checks_green"
    checks_red = "checks_red"
    retry_sent = "retry_sent"
    retries_exhausted = "retries_exhausted"
    review_completed = "review_completed"
    review_not_observed = "review_not_observed"
    human_merged = "human_merged"
    pr_closed_unmerged = "pr_closed_unmerged"
    rescan_started = "rescan_started"
    rescan_verified = "rescan_verified"
    rescan_shows_present = "rescan_shows_present"
    blocked = "blocked"  # any blocked_reason / needs_human predicate
    human_retry = "human_retry"
    human_abandoned = "human_abandoned"
    human_resolved = "human_resolved"  # e.g. disagreement:resolved, disposition:approved


class InvalidTransitionError(Exception):
    def __init__(self, state: StrEnum, event: StrEnum) -> None:
        super().__init__(f"invalid transition: {state.value} --{event.value}--> ?")
        self.state = state
        self.event = event


_W = WorkItemState
_E = WorkItemEvent

WORK_ITEM_TRANSITIONS: dict[tuple[WorkItemState, WorkItemEvent], WorkItemState] = {
    (_W.queued, _E.dispatch_approved): _W.queued,
    (_W.queued, _E.issue_created): _W.issue_open,
    (_W.queued, _E.human_abandoned): _W.abandoned,
    (_W.issue_open, _E.dispatch_started): _W.dispatching,
    (_W.issue_open, _E.human_abandoned): _W.abandoned,
    (_W.issue_open, _E.blocked): _W.needs_human,
    (_W.dispatching, _E.session_created): _W.session_active,
    (_W.dispatching, _E.session_adopted): _W.session_active,
    (_W.dispatching, _E.dispatch_failed): _W.issue_open,
    (_W.dispatching, _E.blocked): _W.needs_human,
    (_W.session_active, _E.pr_opened): _W.pr_open,
    (_W.session_active, _E.blocked): _W.needs_human,
    (_W.session_active, _E.retries_exhausted): _W.failed,
    (_W.pr_open, _E.checks_started): _W.checks_running,
    (_W.pr_open, _E.blocked): _W.needs_human,
    (_W.pr_open, _E.pr_closed_unmerged): _W.needs_human,
    (_W.checks_running, _E.checks_green): _W.review_pending,
    (_W.checks_running, _E.checks_red): _W.checks_failed,
    (_W.checks_running, _E.blocked): _W.needs_human,
    (_W.checks_running, _E.pr_closed_unmerged): _W.needs_human,
    (_W.checks_failed, _E.retry_sent): _W.session_active,
    (_W.checks_failed, _E.retries_exhausted): _W.failed,
    (_W.checks_failed, _E.blocked): _W.needs_human,
    (_W.review_pending, _E.review_completed): _W.ready_for_human,
    (_W.review_pending, _E.review_not_observed): _W.needs_human,
    (_W.review_pending, _E.checks_red): _W.checks_failed,  # new push invalidated checks
    (_W.review_pending, _E.blocked): _W.needs_human,
    (_W.review_pending, _E.pr_closed_unmerged): _W.needs_human,
    (_W.ready_for_human, _E.human_merged): _W.merged,
    (_W.ready_for_human, _E.checks_red): _W.checks_failed,
    (_W.ready_for_human, _E.pr_closed_unmerged): _W.needs_human,
    (_W.ready_for_human, _E.human_abandoned): _W.abandoned,
    (_W.ready_for_human, _E.blocked): _W.needs_human,
    (_W.merged, _E.rescan_started): _W.awaiting_rescan,
    (_W.awaiting_rescan, _E.rescan_verified): _W.verified,
    (_W.awaiting_rescan, _E.rescan_shows_present): _W.needs_human,
    (_W.awaiting_rescan, _E.rescan_started): _W.awaiting_rescan,  # another incomplete/partial run
    (_W.needs_human, _E.human_retry): _W.issue_open,
    (_W.needs_human, _E.human_abandoned): _W.abandoned,
    (_W.needs_human, _E.human_resolved): _W.awaiting_rescan,
    (_W.needs_human, _E.human_merged): _W.merged,  # human merged a PR we had flagged
    (_W.failed, _E.human_retry): _W.issue_open,
    (_W.failed, _E.human_abandoned): _W.abandoned,
}

# States that carry the `needs-human` GitHub label.
HUMAN_ATTENTION_STATES: frozenset[WorkItemState] = frozenset(
    {WorkItemState.needs_human, WorkItemState.failed}
)


def next_work_item_state(state: WorkItemState, event: WorkItemEvent) -> WorkItemState:
    try:
        return WORK_ITEM_TRANSITIONS[(state, event)]
    except KeyError as exc:
        raise InvalidTransitionError(state, event) from exc


class FindingEvent(StrEnum):
    classified = "classified"
    unclassifiable = "unclassifiable"
    grouped = "grouped"
    remediation_started = "remediation_started"
    pr_merged = "pr_merged"
    closing_absent = "closing_absent"  # valid closing run: absent in every original detector (raw)
    closing_vex = "closing_vex"  # valid closing run: raw present, policy absent via approved VEX
    disagreement_resolved = "disagreement_resolved"
    reappeared = "reappeared"
    human_blocked = "human_blocked"
    human_reopened = "human_reopened"
    reclassified = "reclassified"


_F = FindingState
_FE = FindingEvent

FINDING_TRANSITIONS: dict[tuple[FindingState, FindingEvent], FindingState] = {
    (_F.open, _FE.classified): _F.open,
    (_F.open, _FE.unclassifiable): _F.unclassified,
    (_F.open, _FE.grouped): _F.grouped,
    (_F.open, _FE.closing_absent): _F.fixed,  # disappeared without our intervention (db drift)
    (_F.unclassified, _FE.reclassified): _F.open,
    (_F.unclassified, _FE.closing_absent): _F.fixed,
    (_F.grouped, _FE.remediation_started): _F.in_remediation,
    (_F.grouped, _FE.human_blocked): _F.human_blocked,
    (_F.grouped, _FE.closing_absent): _F.fixed,
    (_F.in_remediation, _FE.pr_merged): _F.awaiting_rescan,
    (_F.in_remediation, _FE.human_blocked): _F.human_blocked,
    (_F.in_remediation, _FE.disagreement_resolved): _F.scanner_disagreement_resolved,
    (_F.in_remediation, _FE.closing_vex): _F.approved_disposition,
    (_F.awaiting_rescan, _FE.closing_absent): _F.fixed,
    (_F.awaiting_rescan, _FE.closing_vex): _F.approved_disposition,
    (_F.awaiting_rescan, _FE.human_blocked): _F.human_blocked,
    (_F.fixed, _FE.reappeared): _F.regression,
    (_F.approved_disposition, _FE.human_reopened): _F.open,
    (_F.scanner_disagreement_resolved, _FE.human_reopened): _F.open,
    (_F.regression, _FE.grouped): _F.grouped,
    (_F.regression, _FE.closing_absent): _F.fixed,
    (_F.human_blocked, _FE.human_reopened): _F.open,
    (_F.human_blocked, _FE.closing_absent): _F.fixed,
    (_F.human_blocked, _FE.closing_vex): _F.approved_disposition,
    (_F.human_blocked, _FE.disagreement_resolved): _F.scanner_disagreement_resolved,
}


def next_finding_state(state: FindingState, event: FindingEvent) -> FindingState:
    try:
        return FINDING_TRANSITIONS[(state, event)]
    except KeyError as exc:
        raise InvalidTransitionError(state, event) from exc
