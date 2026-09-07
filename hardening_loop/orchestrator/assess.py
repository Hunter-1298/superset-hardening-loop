"""Decide what the controller does with a polled Devin session snapshot.

Pure function of the snapshot plus a few facts the caller already knows (schema validity, PR
verification, budget, wall clock). Every branch is covered by tests over the full
status x status_detail x output cross product.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from hardening_loop.devin.enums import Outcome, SessionSnapshot


class Decision(StrEnum):
    continue_polling = "continue_polling"
    answer_question = "answer_question"
    budget_warning = "budget_warning"
    ready_for_verification = "ready_for_verification"
    needs_human = "needs_human"


@dataclass(frozen=True)
class Assessment:
    decision: Decision
    reason: str
    reply: str | None = None

    @property
    def is_needs_human(self) -> bool:
        return self.decision is Decision.needs_human


@dataclass(frozen=True)
class SessionFacts:
    """Facts about the session the snapshot alone cannot tell us."""

    acu_cap: float
    schema_valid: bool  # structured_output validates against the kind's schema (False if absent)
    pr_verified: bool  # exactly one PR, base==main, repo in allowlist, matches GitHub
    diff_policy_ok: bool
    wall_clock_exceeded: bool = False
    budget_warning_sent: bool = False


# Fixed whitelist of questions the controller may answer on a human's behalf. Anything else is
# escalated verbatim.
QUESTION_WHITELIST: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"which (base )?branch", re.I),
        "Use `main` (the 6.1.0 remediation branch) as the base branch.",
    ),
    (
        re.compile(r"(may|can|should) i (open|create) (the|a) (pull request|pr)", re.I),
        "Yes. Open the PR against `main` in Hunter-1298/superset only.",
    ),
    (
        re.compile(r"(may|can|should) i (run|execute) (the )?tests", re.I),
        "Yes. Run the tests and attach the logs; never report tests you did not run.",
    ),
)

BUDGET_WARNING_FRACTION = 0.9


def whitelisted_reply(question: str | None) -> str | None:
    if not question:
        return None
    for pattern, reply in QUESTION_WHITELIST:
        if pattern.search(question):
            return reply
    return None


def assess(
    snapshot: SessionSnapshot, facts: SessionFacts, *, pending_question: str | None = None
) -> Assessment:
    # Hard stops first.
    if snapshot.is_budget_stop:
        return Assessment(Decision.needs_human, f"devin_budget_stop:{snapshot.status_detail}")
    if snapshot.is_error:
        return Assessment(Decision.needs_human, "devin_error")
    if snapshot.acus_consumed > facts.acu_cap:
        return Assessment(
            Decision.needs_human,
            f"acu_cap_exceeded:{snapshot.acus_consumed:.2f}>{facts.acu_cap:.2f}",
        )
    if facts.wall_clock_exceeded:
        return Assessment(Decision.needs_human, "session_wall_clock_exceeded")
    if snapshot.is_waiting_for_approval:
        return Assessment(Decision.needs_human, "devin_action_approval_required")

    if snapshot.is_waiting_for_user:
        reply = whitelisted_reply(pending_question)
        if reply is None:
            return Assessment(
                Decision.needs_human,
                f"devin_question_not_whitelisted:{(pending_question or '')[:200]}",
            )
        return Assessment(Decision.answer_question, "whitelisted_question", reply=reply)

    if snapshot.is_done:
        if not facts.schema_valid:
            return Assessment(Decision.needs_human, "final_output_missing_or_invalid")
        outcome = snapshot.outcome
        if outcome is Outcome.blocked:
            return Assessment(
                Decision.needs_human, f"blocked_reason:{snapshot.blocked_reason or 'missing'}"
            )
        if outcome is Outcome.no_change_needed:
            return Assessment(Decision.needs_human, "no_change_needed_requires_human_verification")
        if outcome is Outcome.pr_opened:
            if not snapshot.pull_requests:
                return Assessment(Decision.needs_human, "pr_opened_claimed_but_no_pull_request")
            if not facts.pr_verified:
                return Assessment(Decision.needs_human, "pull_request_failed_verification")
            if not facts.diff_policy_ok:
                return Assessment(Decision.needs_human, "diff_policy_violation")
            return Assessment(Decision.ready_for_verification, "pr_opened")
        return Assessment(Decision.needs_human, "unknown_outcome")

    # Still working (running/working, new, claimed, resuming, resumable suspension).
    if (
        not facts.budget_warning_sent
        and snapshot.acus_consumed >= BUDGET_WARNING_FRACTION * facts.acu_cap
    ):
        return Assessment(Decision.budget_warning, "acu_budget_90pct")
    return Assessment(Decision.continue_polling, f"{snapshot.status}:{snapshot.status_detail}")
