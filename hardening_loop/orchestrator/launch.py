"""Operator launch: the one path from the dashboard into a Devin session.

An operator clicking "Launch Devin" is an explicit human dispatch approval for a single work item.
Everything after that decision is the ordinary `Orchestrator` dispatch code (issue creation, ACU
caps, global budget, concurrency, `wi-<id>` duplicate-session reconciliation), so a launch can
never do anything a scheduled tick could not. The preview below is a pure function so the
confirmation page and the POST handler cannot disagree about eligibility."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from hardening_loop.domain.enums import (
    ACTIVE_WORK_ITEM_STATES,
    TERMINAL_WORK_ITEM_STATES,
    Severity,
    WorkItemState,
)
from hardening_loop.orchestrator.policy import DEFAULT_DISPATCH_SEVERITIES


class LaunchAction(StrEnum):
    launch = "launch"  # queued / issue_open: dispatch now
    relaunch = "relaunch"  # needs_human / failed: human retry, then dispatch


class LaunchBlock(StrEnum):
    dispatch_in_progress = "dispatch_in_progress"
    session_in_flight = "session_in_flight"
    awaiting_human_merge = "awaiting_human_merge"
    awaiting_rescan = "awaiting_rescan"
    closed = "closed"
    at_capacity = "at_capacity"
    over_budget = "over_budget"
    scan_pending = "scan_pending"  # an ingested scan of main is still owed its evaluation


@dataclass(frozen=True)
class LaunchPreview:
    work_item_id: int
    state: WorkItemState
    action: LaunchAction | None
    block: LaunchBlock | None
    needs_issue: bool
    needs_dispatch_approval: bool
    acu_cap: float
    active_sessions: int
    max_concurrent_sessions: int
    acu_consumed: float
    acu_outstanding: float
    global_acu_budget: float
    repo: str
    branch: str
    pending_scans: int = 0

    @property
    def eligible(self) -> bool:
        return self.action is not None and self.block is None

    @property
    def acu_committed_after(self) -> float:
        return self.acu_consumed + self.acu_outstanding + self.acu_cap


@dataclass(frozen=True)
class LaunchResult:
    outcome: str  # created | adopted | failed | rejected
    work_item_id: int
    reason: str
    session_id: str | None = None
    session_url: str | None = None
    issue_url: str | None = None

    @property
    def ok(self) -> bool:
        return self.outcome in ("created", "adopted")


def action_for(state: WorkItemState) -> tuple[LaunchAction | None, LaunchBlock | None]:
    if state in (WorkItemState.queued, WorkItemState.issue_open):
        return LaunchAction.launch, None
    if state in (WorkItemState.needs_human, WorkItemState.failed):
        return LaunchAction.relaunch, None
    if state is WorkItemState.dispatching:
        return None, LaunchBlock.dispatch_in_progress
    if state in ACTIVE_WORK_ITEM_STATES:
        return None, LaunchBlock.session_in_flight
    if state is WorkItemState.ready_for_human:
        return None, LaunchBlock.awaiting_human_merge
    if state in (WorkItemState.merged, WorkItemState.awaiting_rescan):
        return None, LaunchBlock.awaiting_rescan
    if state in TERMINAL_WORK_ITEM_STATES:
        return None, LaunchBlock.closed
    return None, LaunchBlock.closed


def preview(
    *,
    work_item_id: int,
    state: WorkItemState,
    severity: Severity,
    has_issue: bool,
    acu_cap: float,
    active_sessions: int,
    max_concurrent_sessions: int,
    acu_consumed: float,
    acu_outstanding: float,
    global_acu_budget: float,
    repo: str,
    branch: str,
    pending_scans: int = 0,
) -> LaunchPreview:
    """A launch is refused while any scan run awaits its closing evaluation: that run may be the
    evidence that makes this very item obsolete, and the tick that applies it comes first."""
    action, block = action_for(state)
    if action is not None and block is None:
        if pending_scans:
            block = LaunchBlock.scan_pending
        elif active_sessions >= max_concurrent_sessions:
            block = LaunchBlock.at_capacity
        elif acu_consumed + acu_outstanding + acu_cap > global_acu_budget:
            block = LaunchBlock.over_budget
    return LaunchPreview(
        work_item_id=work_item_id,
        state=state,
        action=action,
        block=block,
        needs_issue=not has_issue,
        needs_dispatch_approval=severity not in DEFAULT_DISPATCH_SEVERITIES,
        acu_cap=acu_cap,
        active_sessions=active_sessions,
        max_concurrent_sessions=max_concurrent_sessions,
        acu_consumed=acu_consumed,
        acu_outstanding=acu_outstanding,
        global_acu_budget=global_acu_budget,
        repo=repo,
        branch=branch,
        pending_scans=pending_scans,
    )


__all__ = ["LaunchAction", "LaunchBlock", "LaunchPreview", "LaunchResult", "action_for", "preview"]


class CancelBlock(StrEnum):
    no_session = "no_session"  # nothing is running for this item
    pr_recorded = "pr_recorded"  # the session already delivered a PR; act on the PR instead
    not_active = "not_active"  # the item is not in a session-driven state


@dataclass(frozen=True)
class CancelPreview:
    """Whether "Stop Devin" applies to a work item. Only an item whose session is still working
    (`session_active`) can be stopped: once a PR is recorded the session has done its part and
    the PR, not the session, is what a person acts on."""

    work_item_id: int
    state: WorkItemState
    block: CancelBlock | None
    session_id: str | None
    session_url: str | None
    acus_consumed: float
    acu_cap: float

    @property
    def eligible(self) -> bool:
        return self.block is None


@dataclass(frozen=True)
class CancelResult:
    outcome: str  # cancelled | failed | rejected
    work_item_id: int
    reason: str
    session_id: str | None = None
    session_url: str | None = None
    acus_consumed: float | None = None

    @property
    def ok(self) -> bool:
        return self.outcome == "cancelled"


def cancel_block_for(
    state: WorkItemState, *, has_session: bool, has_pr: bool
) -> CancelBlock | None:
    if state is not WorkItemState.session_active:
        return CancelBlock.not_active
    if not has_session:
        return CancelBlock.no_session
    if has_pr:
        return CancelBlock.pr_recorded
    return None
