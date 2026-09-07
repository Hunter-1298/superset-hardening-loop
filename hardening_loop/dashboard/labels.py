"""Human-readable labels and badge tones for the raw domain enums shown on the dashboard.

The database and APIs keep the exact enum values; only the HTML layer goes through these maps, so
every label is derived from the enum and none of the pages hardcode a state name."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from hardening_loop.domain.enums import (
    FindingState,
    Kind,
    Risk,
    ScanRunStatus,
    Severity,
    Trigger,
    VerificationLevel,
    WorkItemState,
)


class Tone(StrEnum):
    """Visual weight of a badge. Every tone also carries a text label, never colour alone."""

    neutral = "neutral"
    info = "info"
    success = "success"
    warning = "warning"
    danger = "danger"


@dataclass(frozen=True)
class Label:
    text: str
    tone: Tone
    hint: str = ""


WORK_ITEM_STATE_LABELS: dict[WorkItemState, Label] = {
    WorkItemState.queued: Label("Queued", Tone.neutral, "Waiting for dispatch"),
    WorkItemState.issue_open: Label("Issue open", Tone.neutral, "GitHub issue created"),
    WorkItemState.dispatching: Label("Dispatching", Tone.info, "Starting a Devin session"),
    WorkItemState.session_active: Label("Devin working", Tone.info, "Session in progress"),
    WorkItemState.pr_open: Label("PR open", Tone.info, "Pull request opened"),
    WorkItemState.checks_running: Label("Checks running", Tone.info, "CI in progress"),
    WorkItemState.checks_failed: Label("Checks failed", Tone.warning, "Retrying in session"),
    WorkItemState.review_pending: Label("Review pending", Tone.info, "Waiting for Devin Review"),
    WorkItemState.ready_for_human: Label(
        "Ready for review", Tone.warning, "Needs a human approval and merge in GitHub"
    ),
    WorkItemState.merged: Label("Merged", Tone.info, "Waiting for a confirming scan"),
    WorkItemState.awaiting_rescan: Label(
        "Awaiting rescan", Tone.info, "Merged; waiting for the next scan of the branch"
    ),
    WorkItemState.verified: Label("Verified", Tone.success, "Absent from a later successful scan"),
    WorkItemState.needs_human: Label("Needs attention", Tone.danger, "Blocked on a person"),
    WorkItemState.abandoned: Label("Abandoned", Tone.neutral, "Closed without remediation"),
    WorkItemState.failed: Label("Failed", Tone.danger, "Remediation failed"),
}

# States where a person must do something before the loop can continue.
HUMAN_ACTION_STATES: frozenset[WorkItemState] = frozenset(
    {WorkItemState.needs_human, WorkItemState.ready_for_human, WorkItemState.failed}
)

FINDING_STATE_LABELS: dict[FindingState, Label] = {
    FindingState.open: Label("Open", Tone.neutral),
    FindingState.unclassified: Label("Unclassified", Tone.warning, "Not dispatched"),
    FindingState.grouped: Label("Grouped", Tone.neutral, "Attached to a work item"),
    FindingState.in_remediation: Label("In remediation", Tone.info),
    FindingState.awaiting_rescan: Label("Awaiting rescan", Tone.info),
    FindingState.fixed: Label("Fixed", Tone.success, "Confirmed absent by a later scan"),
    FindingState.approved_disposition: Label(
        "Approved disposition", Tone.success, "Human-approved OpenVEX"
    ),
    FindingState.scanner_disagreement_resolved: Label(
        "Disagreement resolved", Tone.success, "Scanner disagreement resolved by a human"
    ),
    FindingState.regression: Label("Regression", Tone.danger, "Reappeared after verification"),
    FindingState.human_blocked: Label("Blocked", Tone.danger, "Waiting on a person"),
}

KIND_LABELS: dict[Kind, Label] = {
    Kind.dependency_upgrade: Label("Dependency upgrade", Tone.neutral),
    Kind.no_fix_reachability: Label("No fix / reachability", Tone.neutral),
    Kind.container_hardening: Label("Container hardening", Tone.neutral),
    Kind.scanner_disagreement: Label("Scanner disagreement", Tone.neutral),
    Kind.helm_deploy_config: Label("Deployment config", Tone.neutral),
}
UNCLASSIFIED_LABEL = Label("Unclassified", Tone.warning, "Visible but never dispatched")

SEVERITY_LABELS: dict[Severity, Label] = {
    Severity.critical: Label("Critical", Tone.danger),
    Severity.high: Label("High", Tone.danger),
    Severity.medium: Label("Medium", Tone.warning),
    Severity.low: Label("Low", Tone.neutral),
    Severity.unknown: Label("Unknown", Tone.neutral),
}

VERIFICATION_LABELS: dict[VerificationLevel, Label] = {
    VerificationLevel.none: Label("Not started", Tone.neutral),
    VerificationLevel.pr_opened: Label("PR opened", Tone.neutral),
    VerificationLevel.ci_green: Label("CI green", Tone.info),
    VerificationLevel.review_completed: Label("Review completed", Tone.info),
    VerificationLevel.human_approved: Label("Human approved", Tone.info),
    VerificationLevel.merged: Label("Merged", Tone.info),
    VerificationLevel.rescan_verified: Label("Rescan verified", Tone.success),
}

RISK_LABELS: dict[Risk, Label] = {
    Risk.normal: Label("Normal risk", Tone.neutral),
    Risk.high: Label("High risk", Tone.warning, "Upper bound or major upgrade"),
}

RUN_STATUS_LABELS: dict[ScanRunStatus, Label] = {
    ScanRunStatus.complete: Label("Complete", Tone.success),
    ScanRunStatus.incomplete: Label("Incomplete", Tone.warning, "A detector did not finish"),
    ScanRunStatus.failed: Label("Failed", Tone.danger),
}

TRIGGER_LABELS: dict[Trigger, str] = {
    Trigger.push: "Push",
    Trigger.pull_request: "Pull request",
    Trigger.schedule: "Scheduled",
    Trigger.workflow_dispatch: "Manual",
    Trigger.replay: "Replay",
    Trigger.fixture: "Fixture",
}

PR_STATE_LABELS: dict[str, Label] = {
    "open": Label("Open", Tone.info),
    "closed": Label("Closed", Tone.neutral),
    "merged": Label("Merged", Tone.success),
}

CHECK_CONCLUSION_LABELS: dict[str, Label] = {
    "success": Label("Passed", Tone.success),
    "failure": Label("Failed", Tone.danger),
    "cancelled": Label("Cancelled", Tone.neutral),
    "timed_out": Label("Timed out", Tone.danger),
    "action_required": Label("Action required", Tone.warning),
    "neutral": Label("Neutral", Tone.neutral),
    "skipped": Label("Skipped", Tone.neutral),
}
CHECK_PENDING_LABEL = Label("Pending", Tone.info)

OUTCOME_LABELS: dict[str, str] = {
    "fixed": "Fixed",
    "approved_disposition": "Approved disposition",
    "scanner_disagreement_resolved": "Disagreement resolved",
    "regression": "Regression",
    "human_blocked": "Blocked",
}

SCANNER_GROUP_LABELS: dict[str, str] = {
    "both": "Trivy + Grype",
    "trivy_only": "Trivy only",
    "grype_only": "Grype only",
    "config": "Config scan",
}

LAYER_LABELS: dict[str, str] = {
    "python": "Python",
    "os": "OS packages",
    "binary": "Binaries",
    "dockerfile": "Dockerfile",
    "helm": "Helm",
    "compose": "Compose",
}

RELATION_LABELS: dict[str, Label] = {
    "matches": Label("Same as upstream", Tone.success, "Devin's target equals the upstream pin"),
    "above": Label("Newer than upstream", Tone.info, "Devin's target is above the upstream pin"),
    "below": Label("Older than upstream", Tone.warning, "Devin's target is below the upstream pin"),
    "upstream_unpinned": Label("Not pinned upstream", Tone.neutral),
    "no_target": Label("No target yet", Tone.neutral, "Devin has not proposed a version"),
    "unparseable": Label("Version unparseable", Tone.warning),
}


def _fallback(value: object) -> Label:
    text = str(value).replace("_", " ").strip()
    return Label(text[:1].upper() + text[1:] if text else "—", Tone.neutral)


def plain(value: object) -> Label:
    """Neutral badge for free-form values (Devin statuses, poll decisions): underscores become
    spaces and the first letter is capitalised; the raw value is kept as the hint."""
    label = _fallback(value)
    return Label(label.text, label.tone, str(value) if value is not None else "")


def work_item_state(value: object) -> Label:
    try:
        return WORK_ITEM_STATE_LABELS[WorkItemState(str(value))]
    except ValueError:
        return _fallback(value)


def finding_state(value: object) -> Label:
    try:
        return FINDING_STATE_LABELS[FindingState(str(value))]
    except ValueError:
        return _fallback(value)


def kind(value: object) -> Label:
    """Accepts the enum, its number, or its slug; anything else is `Unclassified`."""
    if value is None or value == "unclassified":
        return UNCLASSIFIED_LABEL
    if isinstance(value, Kind):
        return KIND_LABELS[value]
    raw = str(value)
    try:
        return KIND_LABELS[Kind(int(raw)) if raw.isdigit() else Kind[raw]]
    except (ValueError, KeyError):
        return _fallback(value)


def severity(value: object) -> Label:
    try:
        return SEVERITY_LABELS[Severity(str(value).upper())]
    except ValueError:
        return _fallback(value)


def verification(value: object) -> Label:
    if isinstance(value, VerificationLevel):
        return VERIFICATION_LABELS[value]
    try:
        return VERIFICATION_LABELS[VerificationLevel(int(str(value)))]
    except (ValueError, TypeError):
        return _fallback(value)


def risk(value: object) -> Label:
    try:
        return RISK_LABELS[Risk(str(value))]
    except ValueError:
        return _fallback(value)


def run_status(value: object) -> Label:
    try:
        return RUN_STATUS_LABELS[ScanRunStatus(str(value))]
    except ValueError:
        return _fallback(value)


def trigger(value: object) -> str:
    try:
        return TRIGGER_LABELS[Trigger(str(value))]
    except ValueError:
        return _fallback(value).text


def pr_state(value: object) -> Label:
    return PR_STATE_LABELS.get(str(value), _fallback(value))


def check_conclusion(value: object) -> Label:
    if value is None or value == "":
        return CHECK_PENDING_LABEL
    return CHECK_CONCLUSION_LABELS.get(str(value), _fallback(value))


def outcome(value: object) -> str:
    return OUTCOME_LABELS.get(str(value), finding_state(value).text)


def scanner_group(value: object) -> str:
    return SCANNER_GROUP_LABELS.get(str(value), _fallback(value).text)


def layer(value: object) -> str:
    return LAYER_LABELS.get(str(value), _fallback(value).text)


def relation(value: object) -> Label:
    """How a dependency upgrade target compares with the upstream-master pin."""
    return RELATION_LABELS.get(str(value), _fallback(value))


def gate(passed: object, mode: object) -> Label:
    """One badge for a gate verdict: the mode is always spelled out next to the result."""
    mode_text = str(mode)
    if passed:
        return Label(f"Gate passed ({mode_text})", Tone.success)
    return Label(f"Gate failed ({mode_text})", Tone.danger)


def yes_no(value: object) -> Label:
    if value is None:
        return Label("Not judged", Tone.neutral)
    return Label("Yes", Tone.success) if value else Label("No", Tone.danger)


EVENT_LABELS: dict[str, Label] = {
    "created": Label("Created", Tone.neutral),
    "issue_created": Label("GitHub issue opened", Tone.neutral),
    "dispatch_started": Label("Dispatch started", Tone.info),
    "dispatch_failed": Label("Dispatch failed", Tone.warning),
    "session_created": Label("Devin session started", Tone.info),
    "session_recovered": Label("Session recovered", Tone.info),
    "pr_opened": Label("Pull request opened", Tone.info),
    "checks_started": Label("CI checks started", Tone.info),
    "checks_green": Label("CI checks passed", Tone.success),
    "checks_red": Label("CI checks failed", Tone.danger),
    "retry_sent": Label("Retry sent to the same session", Tone.warning),
    "review_completed": Label("Devin Review completed", Tone.success),
    "human_approved": Label("Approved by a person", Tone.success),
    "human_merged": Label("Merged by a person", Tone.success),
    "human_resolved": Label("Resolved by a person", Tone.success),
    "rescan_started": Label("Confirming scan evaluated", Tone.info),
    "rescan_verified": Label("Verified by rescan", Tone.success),
    "blocked": Label("Blocked", Tone.danger),
    "failed": Label("Failed", Tone.danger),
    "abandoned": Label("Abandoned", Tone.neutral),
    "budget_warning": Label("ACU budget warning", Tone.warning),
    "verification_level": Label("Verification level changed", Tone.neutral),
    "head_changed": Label("PR head changed", Tone.neutral),
    "regression": Label("Regression detected", Tone.danger),
    "reappeared": Label("Finding reappeared", Tone.danger),
    "opened": Label("Finding opened", Tone.neutral),
    "grouped": Label("Finding grouped", Tone.neutral),
    "remediation_started": Label("Remediation started", Tone.info),
    "pr_merged": Label("Fix merged", Tone.success),
    "closing_absent": Label("Closed: absent from rescan", Tone.success),
    "closing_vex": Label("Closed: approved disposition", Tone.success),
    "ingested": Label("Scan ingested", Tone.neutral),
}

ACTOR_LABELS: dict[str, str] = {
    "controller": "Controller",
    "devin": "Devin",
    "ci": "CI",
    "scanner": "Scanner",
    "human": "Person",
}


def event(value: object) -> Label:
    """Readable name and tone for an append-only event; unknown names are title-cased."""
    return EVENT_LABELS.get(str(value), _fallback(value))


def actor(value: object) -> str:
    """`human:<login>` keeps the login; the fixed actor names get a readable word."""
    text = str(value)
    if text.startswith("human:"):
        return text.split(":", 1)[1]
    return ACTOR_LABELS.get(text, _fallback(text).text)


BLOCKED_REASON_PREFIXES: dict[str, str] = {
    "blocked_reason": "Devin reported a blocker",
    "invalid_transition": "The controller refused a state transition",
    "acu_cap_exceeded": "ACU cap exceeded",
    "retries_exhausted": "Retries exhausted",
}


def blocked_reason_text(value: str | None) -> str:
    """Readable form of a stored `code:detail` blocked reason. Known codes become a short
    lead-in, unknown codes become words; the raw string stays available in the technical
    sections."""
    text = (value or "").strip()
    if not text:
        return ""
    code, sep, detail = text.partition(":")
    if sep and code.replace("_", "").isalnum() and code == code.lower():
        lead = BLOCKED_REASON_PREFIXES.get(code, _fallback(code).text)
        return f"{lead}: {detail.strip()}" if detail.strip() else lead
    return _fallback(text).text if "_" in text and " " not in text else text


def next_human_action(state: object, blocked_reason: str | None, pr_url: str | None) -> str | None:
    """The single sentence shown at the top of a work item when a person must act."""
    try:
        s = WorkItemState(str(state))
    except ValueError:
        return None
    reason = blocked_reason_text(blocked_reason)
    if s is WorkItemState.needs_human:
        return reason or "Resolve the blocker in GitHub, then add the `retry` label."
    if s is WorkItemState.failed:
        return reason or "Remediation failed; review the session and decide on a retry."
    if s is WorkItemState.ready_for_human:
        if pr_url is None:
            return "Approve the disposition on the GitHub issue so the loop can continue."
        return "Review and approve the pull request in GitHub; merging lets the loop continue."
    return None
