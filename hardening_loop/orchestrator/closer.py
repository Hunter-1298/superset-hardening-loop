"""Closure rules (§8): when may a later scan run close a finding, and with which outcome.

Everything here is a pure function over ORM rows already loaded by the caller, so the exact same
code decides closure in replay and live mode. A run that is not a *valid closing run* for a finding
proves nothing about it — partial/failed scans never establish absence.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from packaging.version import InvalidVersion, Version

from hardening_loop.config import (
    FORK_REPO,
    GRYPE_VERSION,
    REMEDIATION_BRANCH,
    TRIVY_VERSION,
)
from hardening_loop.domain.enums import (
    CLOSING_TRIGGERS,
    FindingState,
    ImageTarget,
    Layer,
    ScanMode,
    Scanner,
    ScanRunStatus,
)
from hardening_loop.ingest.vex import VexEvidenceError, approval_of, validate_openvex
from hardening_loop.models.tables import Finding, ScanJob, ScanRun, Sighting

PINNED_VERSIONS: dict[Scanner, str] = {Scanner.trivy: TRIVY_VERSION, Scanner.grype: GRYPE_VERSION}
IMAGE_LAYERS: frozenset[Layer] = frozenset({Layer.python, Layer.os, Layer.binary})
CONFIG_LAYERS: frozenset[Layer] = frozenset({Layer.dockerfile, Layer.helm, Layer.compose})


class ClosingOutcome(StrEnum):
    fixed = "fixed"
    approved_disposition = "approved_disposition"
    scanner_disagreement_resolved = "scanner_disagreement_resolved"
    regression = "regression"
    human_blocked = "human_blocked"
    still_present = "still_present"  # valid run, finding still there, nothing else applies
    not_applicable = "not_applicable"  # run is not a valid closing run for this finding


@dataclass(frozen=True)
class RunValidity:
    valid: bool
    reasons: list[str] = field(default_factory=list)


AncestryFn = Callable[
    [str, str], bool
]  # (merge_sha, run_sha) -> run_sha is merge_sha or descendant


def _version_at_least(actual: str | None, pinned: str) -> bool:
    if actual is None:
        return False
    try:
        return Version(actual) >= Version(pinned)
    except InvalidVersion:
        return False


def original_detectors(finding: Finding) -> set[Scanner]:
    dets: set[Scanner] = set()
    if finding.reported_by_trivy:
        dets.add(Scanner.trivy)
    if finding.reported_by_grype:
        dets.add(Scanner.grype)
    return dets


def validate_closing_run(
    run: ScanRun,
    jobs: list[ScanJob],
    finding: Finding,
    *,
    merge_sha: str | None,
    is_ancestor: AncestryFn,
    require_policy: bool,
) -> RunValidity:
    reasons: list[str] = []
    if run.source_repo != FORK_REPO:
        reasons.append(f"repo {run.source_repo} != {FORK_REPO}")
    if run.source_branch != REMEDIATION_BRANCH:
        reasons.append(f"branch {run.source_branch} != {REMEDIATION_BRANCH}")
    if run.trigger not in CLOSING_TRIGGERS:
        reasons.append(f"trigger {run.trigger.value} cannot close findings")
    if run.status is not ScanRunStatus.complete:
        reasons.append(f"run status {run.status.value}: incomplete runs never prove absence")
    if merge_sha is not None and not is_ancestor(merge_sha, run.source_sha):
        reasons.append(f"run sha {run.source_sha[:12]} is not {merge_sha[:12]} or a descendant")
    if finding.platform != run.platform:
        reasons.append(f"platform {run.platform} != {finding.platform}")

    by_name = {j.name: j for j in jobs}
    detectors = original_detectors(finding)

    if finding.layer in CONFIG_LAYERS:
        cfg = by_name.get("config-raw")
        if cfg is None or not cfg.success:
            reasons.append("config-raw job missing or failed")
        elif finding.image_target and cfg.image_target and cfg.image_target != finding.image_target:
            reasons.append("config job image target mismatch")
    else:
        if finding.image_target is not None and run.lean_digest is None:
            reasons.append("run has no lean image digest")
        if not detectors:
            reasons.append("finding has no original detector")
        for det in detectors:
            job = by_name.get(f"{det.value}-raw")
            if job is None or not job.success:
                reasons.append(f"{det.value}-raw job missing or failed")
                continue
            if (
                job.image_target is not None
                and finding.image_target is not None
                and job.image_target != finding.image_target
            ):
                reasons.append(
                    f"{det.value} scanned {job.image_target}, need {finding.image_target}"
                )
            if not _version_at_least(job.tool_version, PINNED_VERSIONS[det]):
                reasons.append(f"{det.value} {job.tool_version} < pinned {PINNED_VERSIONS[det]}")
            if (
                finding.opening_db_built_at is not None
                and job.db_built_at is not None
                and job.db_built_at < finding.opening_db_built_at
            ):
                reasons.append(f"{det.value} db {job.db_built_at} older than opening run")
            if require_policy:
                pjob = by_name.get(f"{det.value}-policy")
                if pjob is None or not pjob.success:
                    reasons.append(f"{det.value}-policy job missing or failed")
    for j in jobs:
        if not j.success:
            reasons.append(f"job {j.name} failed")
    # dedupe while preserving order
    unique = list(dict.fromkeys(reasons))
    return RunValidity(valid=not unique, reasons=unique)


@dataclass(frozen=True)
class SightingView:
    raw_present: dict[Scanner, bool]
    policy_present: dict[Scanner, bool]


def family_key(finding: Finding) -> tuple[str, str, str | None, str]:
    """Same vulnerability against the same package in the same layer, at *any* version. An upgrade
    to a still-vulnerable version is not a fix, even though the dedupe key (which carries the
    version) changes."""
    return (finding.vuln_id, finding.ecosystem.value, finding.pkg_name, finding.layer.value)


def sightings_for(
    finding: Finding,
    run: ScanRun,
    sightings: list[Sighting],
    *,
    family_ids: frozenset[int] | None = None,
) -> SightingView:
    ids = (family_ids or frozenset()) | ({finding.id} if finding.id is not None else frozenset())
    raw: dict[Scanner, bool] = {}
    pol: dict[Scanner, bool] = {}
    for s in sightings:
        if s.finding_id not in ids or s.scan_run_id != run.id:
            continue
        if s.mode is ScanMode.raw:
            raw[s.scanner] = raw.get(s.scanner, False) or s.present
        elif s.mode is ScanMode.policy:
            pol[s.scanner] = pol.get(s.scanner, False) or s.present
    return SightingView(raw_present=raw, policy_present=pol)


def _vex_approved_for_issue(run: ScanRun, issue_url: str | None, vuln_id: str) -> bool:
    """True if the policy run applied an approved OpenVEX document whose `x-approval` names this
    issue and whose statements cover `vuln_id`; an approval for another issue never counts."""
    if issue_url is None:
        return False
    for doc in run.vex_documents:
        approval = approval_of(doc)
        if approval is None or approval.issue_url != issue_url:
            continue
        try:
            statements = validate_openvex(doc, where=doc.get("@id", "vex"))
        except VexEvidenceError:
            continue
        if any(s.vulnerability == vuln_id for s in statements):
            return True
    return False


def decide_outcome(
    finding: Finding,
    run: ScanRun,
    view: SightingView,
    *,
    validity: RunValidity,
    disagreement_resolved_by_human: bool,
    issue_url: str | None,
    finding_was_closed: bool,
) -> ClosingOutcome:
    """Outcome of `run` for `finding`, given the run has (or has not) been validated."""
    if not validity.valid:
        return ClosingOutcome.not_applicable

    if finding.layer in CONFIG_LAYERS:
        present = view.raw_present.get(Scanner.trivy, False)
        if present:
            return ClosingOutcome.regression if finding_was_closed else ClosingOutcome.still_present
        return ClosingOutcome.fixed

    detectors = original_detectors(finding)
    raw_present_any = any(view.raw_present.get(d, False) for d in detectors)
    if not raw_present_any:
        return ClosingOutcome.fixed
    if finding_was_closed:
        return ClosingOutcome.regression

    present_detectors = {d for d in detectors if view.raw_present.get(d, False)}
    policy_seen = all(d in view.policy_present for d in present_detectors)
    policy_absent_all = all(not view.policy_present.get(d, False) for d in present_detectors)
    if (
        policy_seen
        and policy_absent_all
        and _vex_approved_for_issue(run, issue_url, finding.vuln_id)
    ):
        return ClosingOutcome.approved_disposition

    if len(present_detectors) == 1 and disagreement_resolved_by_human:
        return ClosingOutcome.scanner_disagreement_resolved

    return ClosingOutcome.still_present


CLOSING_FINDING_STATES: frozenset[FindingState] = frozenset(
    {
        FindingState.fixed,
        FindingState.approved_disposition,
        FindingState.scanner_disagreement_resolved,
    }
)


def issue_may_close(states: list[FindingState]) -> bool:
    """An issue is closed only when EVERY member has a valid closing outcome."""
    return bool(states) and all(s in CLOSING_FINDING_STATES for s in states)


def newest_db(run: ScanRun) -> datetime | None:
    stamps: list[datetime] = []
    for key in ("trivy_db_updated_at", "grype_db_built_at"):
        v = run.tools.get(key)
        if isinstance(v, str):
            stamps.append(datetime.fromisoformat(v))
    return max(stamps) if stamps else None


__all__ = [
    "ClosingOutcome",
    "ImageTarget",
    "RunValidity",
    "SightingView",
    "decide_outcome",
    "issue_may_close",
    "newest_db",
    "original_detectors",
    "sightings_for",
    "validate_closing_run",
]
