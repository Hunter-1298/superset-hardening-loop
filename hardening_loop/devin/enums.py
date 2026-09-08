"""Exact Devin v3 session enums (OpenAPI `SessionResponse`) and derived predicates.

Source: https://docs.devin.ai/api-reference/v3/sessions/organizations-sessions (components.schemas
SessionResponse.status / status_detail). Unknown values are rejected at parse time so that any API
change surfaces as a `needs_human` condition instead of being silently coerced.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DevinStatus(StrEnum):
    new = "new"
    claimed = "claimed"
    running = "running"
    exit = "exit"
    error = "error"
    suspended = "suspended"
    resuming = "resuming"


class DevinStatusDetail(StrEnum):
    # status == running
    working = "working"
    waiting_for_user = "waiting_for_user"
    waiting_for_approval = "waiting_for_approval"
    finished = "finished"
    # status == suspended
    inactivity = "inactivity"
    user_request = "user_request"
    usage_limit_exceeded = "usage_limit_exceeded"
    out_of_credits = "out_of_credits"
    out_of_quota = "out_of_quota"
    no_quota_allocation = "no_quota_allocation"
    payment_declined = "payment_declined"
    org_usage_limit_exceeded = "org_usage_limit_exceeded"
    user_usage_limit_exceeded = "user_usage_limit_exceeded"
    total_session_limit_exceeded = "total_session_limit_exceeded"
    error = "error"


BUDGET_STOP_DETAILS: frozenset[DevinStatusDetail] = frozenset(
    {
        DevinStatusDetail.usage_limit_exceeded,
        DevinStatusDetail.out_of_credits,
        DevinStatusDetail.out_of_quota,
        DevinStatusDetail.no_quota_allocation,
        DevinStatusDetail.payment_declined,
        DevinStatusDetail.org_usage_limit_exceeded,
        DevinStatusDetail.user_usage_limit_exceeded,
        DevinStatusDetail.total_session_limit_exceeded,
    }
)

RESUMABLE_SUSPENSION_DETAILS: frozenset[DevinStatusDetail] = frozenset(
    {DevinStatusDetail.inactivity, DevinStatusDetail.user_request}
)


class Outcome(StrEnum):
    """`outcome` field shared by all five structured-output schemas."""

    pr_opened = "pr_opened"
    blocked = "blocked"
    no_change_needed = "no_change_needed"


class SessionPullRequest(BaseModel):
    model_config = ConfigDict(extra="ignore")

    pr_url: str
    pr_state: str | None = None


class SessionSnapshot(BaseModel):
    """The subset of `SessionResponse` the orchestrator reasons about."""

    model_config = ConfigDict(extra="ignore", frozen=True)

    session_id: str
    url: str = ""
    status: DevinStatus
    status_detail: DevinStatusDetail | None = None
    acus_consumed: float = 0.0
    pull_requests: list[SessionPullRequest] = Field(default_factory=list)
    structured_output: dict[str, Any] | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: int = 0
    updated_at: int = 0

    # ---- predicates (pure functions of the snapshot) ----

    @property
    def is_done(self) -> bool:
        return self.status in (DevinStatus.exit, DevinStatus.error) or (
            self.status is DevinStatus.running and self.status_detail is DevinStatusDetail.finished
        )

    @property
    def is_final_report(self) -> bool:
        """The session has delivered its verdict: it finished, or it declared `pr_opened` in its
        structured output and is idle after posting the report (`waiting_for_user`, or suspended
        for inactivity once that idling outlasted Devin's timeout). Only the PR outcome counts
        here because it is checked against GitHub rather than trusted."""
        return self.is_done or (
            (self.is_waiting_for_user or self.is_inactivity_suspension)
            and self.outcome is Outcome.pr_opened
        )

    @property
    def is_budget_stop(self) -> bool:
        return self.status_detail in BUDGET_STOP_DETAILS

    @property
    def is_resumable_suspension(self) -> bool:
        return (
            self.status is DevinStatus.suspended
            and self.status_detail in RESUMABLE_SUSPENSION_DETAILS
        )

    @property
    def is_inactivity_suspension(self) -> bool:
        return (
            self.status is DevinStatus.suspended
            and self.status_detail is DevinStatusDetail.inactivity
        )

    @property
    def is_waiting_for_user(self) -> bool:
        return (
            self.status is DevinStatus.running
            and self.status_detail is DevinStatusDetail.waiting_for_user
        )

    @property
    def is_waiting_for_approval(self) -> bool:
        return (
            self.status is DevinStatus.running
            and self.status_detail is DevinStatusDetail.waiting_for_approval
        )

    @property
    def is_error(self) -> bool:
        return self.status is DevinStatus.error or self.status_detail is DevinStatusDetail.error

    @property
    def is_active(self) -> bool:
        """Session may still produce work (controller keeps polling, no new session allowed)."""
        return (
            self.status
            in (
                DevinStatus.new,
                DevinStatus.claimed,
                DevinStatus.running,
                DevinStatus.resuming,
            )
            or self.is_resumable_suspension
        )

    @property
    def outcome(self) -> Outcome | None:
        if not self.structured_output:
            return None
        raw = self.structured_output.get("outcome")
        if not isinstance(raw, str):
            return None
        try:
            return Outcome(raw)
        except ValueError:
            return None

    @property
    def blocked_reason(self) -> str | None:
        if not self.structured_output:
            return None
        value = self.structured_output.get("blocked_reason")
        return value if isinstance(value, str) and value.strip() else None

    @property
    def output_blocked(self) -> bool:
        return self.outcome is Outcome.blocked and self.blocked_reason is not None

    @property
    def no_change_needed(self) -> bool:
        return self.outcome is Outcome.no_change_needed
