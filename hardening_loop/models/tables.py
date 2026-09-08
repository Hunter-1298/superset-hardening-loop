"""SQLModel tables. SQLite only; JSON columns hold scanner records verbatim."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Column, DateTime, Index, UniqueConstraint
from sqlalchemy.types import TypeDecorator
from sqlmodel import Field, SQLModel

from hardening_loop.domain.enums import (
    Ecosystem,
    FindingState,
    GateMode,
    ImageTarget,
    Kind,
    Layer,
    Risk,
    ScanMode,
    Scanner,
    ScanRunStatus,
    Severity,
    Trigger,
    VerificationLevel,
    WorkItemState,
)


def utcnow() -> datetime:
    return datetime.now(UTC)


class UTCDateTime(TypeDecorator[datetime]):
    """SQLite drops tzinfo; store UTC and re-attach it on load so arithmetic never mixes kinds."""

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect: object) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


class SchemaVersion(SQLModel, table=True):
    __tablename__ = "schema_version"
    id: int | None = Field(default=None, primary_key=True)
    version: int
    applied_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)


class ScanRun(SQLModel, table=True):
    __tablename__ = "scan_runs"
    id: int | None = Field(default=None, primary_key=True)
    external_run_id: str = Field(index=True, unique=True)  # GitHub run id / replay id / fixture id
    run_attempt: int = 1
    trigger: Trigger
    source_repo: str
    source_branch: str
    source_sha: str = Field(index=True)
    platform: str = "linux/amd64"
    lean_digest: str | None = None
    ci_digest: str | None = None
    ci_layer_delta: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    tools: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    scan_gate_mode: GateMode = GateMode.report
    vex_documents: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    status: ScanRunStatus = ScanRunStatus.incomplete
    started_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    finished_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    ingested_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    is_baseline: bool = False


class ScanJob(SQLModel, table=True):
    __tablename__ = "scan_jobs"
    __table_args__ = (UniqueConstraint("scan_run_id", "name", name="uq_scan_job_run_name"),)
    id: int | None = Field(default=None, primary_key=True)
    scan_run_id: int = Field(foreign_key="scan_runs.id", index=True)
    name: str  # trivy-raw, grype-policy, config-scan, lean-smoke, app-runs, ...
    scanner: Scanner | None = None
    mode: ScanMode | None = None
    image_target: ImageTarget | None = None
    layer_scope: str  # "image" | "config" | "runtime"
    success: bool
    tool_version: str | None = None
    db_built_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    started_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    finished_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    artifact_path: str | None = None
    artifact_sha256: str | None = None
    counts: dict[str, int] = Field(default_factory=dict, sa_column=Column(JSON))


class Evidence(SQLModel, table=True):
    __tablename__ = "evidence"
    id: int | None = Field(default=None, primary_key=True)
    scan_run_id: int | None = Field(default=None, foreign_key="scan_runs.id", index=True)
    kind: str  # sbom | scanner_output | manifest | log | attachment | vex
    path: str
    sha256: str
    url: str | None = None
    created_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)


class Finding(SQLModel, table=True):
    """One deduplicated vulnerability or configuration finding."""

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("dedupe_key", name="uq_finding_dedupe"),
        Index("ix_finding_state_kind", "state", "kind"),
    )
    id: int | None = Field(default=None, primary_key=True)
    dedupe_key: str
    vuln_id: str  # CVE/GHSA id or config rule id
    purl: str | None = None
    pkg_name: str | None = None
    pkg_version: str | None = None
    ecosystem: Ecosystem = Ecosystem.unknown
    layer: Layer
    image_target: ImageTarget | None = None
    platform: str = "linux/amd64"
    resource: str | None = None  # config findings: file/resource
    title: str | None = None
    severity: Severity = Severity.unknown
    severity_by_scanner: dict[str, str] = Field(default_factory=dict, sa_column=Column(JSON))
    severity_disagreement: bool = False
    fix_versions_by_scanner: dict[str, list[str]] = Field(
        default_factory=dict, sa_column=Column(JSON)
    )
    reported_by_trivy: bool = False
    reported_by_grype: bool = False
    # Detectors of the run that opened the finding. Immutable: closure asks the scanners that
    # reported it originally, not whichever ones happen to report it today.
    opened_by_trivy: bool = False
    opened_by_grype: bool = False
    kind: Kind | None = None
    risk: Risk = Risk.normal
    bound_blocked: bool = False
    classification_trace: str | None = None
    unclassified_reason: str | None = None
    state: FindingState = FindingState.open
    first_seen_run_id: int = Field(foreign_key="scan_runs.id")
    last_seen_run_id: int = Field(foreign_key="scan_runs.id")
    opening_db_built_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    work_item_id: int | None = Field(default=None, foreign_key="work_items.id", index=True)
    closed_by_run_id: int | None = Field(default=None, foreign_key="scan_runs.id")
    created_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    updated_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)


class Sighting(SQLModel, table=True):
    """Presence of a finding in one (run, scanner, mode) — the raw material for closure."""

    __tablename__ = "sightings"
    __table_args__ = (
        UniqueConstraint("finding_id", "scan_run_id", "scanner", "mode", name="uq_sighting"),
    )
    id: int | None = Field(default=None, primary_key=True)
    finding_id: int = Field(foreign_key="findings.id", index=True)
    scan_run_id: int = Field(foreign_key="scan_runs.id", index=True)
    scanner: Scanner
    mode: ScanMode
    present: bool
    severity: Severity | None = None
    fixed_versions: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    record: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))


class WorkItem(SQLModel, table=True):
    __tablename__ = "work_items"
    __table_args__ = (
        UniqueConstraint("kind", "group_key", "source_branch", name="uq_work_item_group"),
        Index("ix_work_item_active_session", "active_session_id", unique=True),
    )
    id: int | None = Field(default=None, primary_key=True)
    kind: Kind
    group_key: str
    title: str
    source_branch: str = "main"
    severity: Severity = Severity.unknown
    risk: Risk = Risk.normal
    state: WorkItemState = WorkItemState.queued
    acu_cap: float
    retries_used: int = 0
    budget_warning_sent: bool = False
    active_session_id: str | None = None
    issue_number: int | None = None
    issue_url: str | None = None
    pr_number: int | None = None
    pr_url: str | None = None
    pr_head_sha: str | None = None
    merge_sha: str | None = None
    verification_level: VerificationLevel = VerificationLevel.none
    blocked_reason: str | None = None
    human_resolution: str | None = None  # disposition:approved | disagreement:resolved
    dispatch_failures: int = 0
    regression_of_work_item_id: int | None = Field(default=None, foreign_key="work_items.id")
    created_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    updated_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    issue_opened_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    pr_opened_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    merged_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    verified_at: datetime | None = Field(default=None, sa_type=UTCDateTime)


class Session(SQLModel, table=True):
    __tablename__ = "sessions"
    id: int | None = Field(default=None, primary_key=True)
    devin_id: str = Field(index=True, unique=True)
    work_item_id: int = Field(foreign_key="work_items.id", index=True)
    url: str = ""
    playbook_id: str | None = None
    max_acu_limit: float
    status: str
    status_detail: str | None = None
    acus_consumed: float = 0.0
    structured_output: dict[str, Any] | None = Field(default=None, sa_column=Column(JSON))
    pull_requests: list[dict[str, Any]] = Field(default_factory=list, sa_column=Column(JSON))
    messages_sent: int = 0
    created_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    last_polled_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    finished_at: datetime | None = Field(default=None, sa_type=UTCDateTime)


class SessionPoll(SQLModel, table=True):
    __tablename__ = "session_polls"
    id: int | None = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="sessions.id", index=True)
    polled_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    status: str
    status_detail: str | None = None
    acus_consumed: float
    decision: str
    reason: str


class PullRequest(SQLModel, table=True):
    __tablename__ = "pull_requests"
    id: int | None = Field(default=None, primary_key=True)
    work_item_id: int = Field(foreign_key="work_items.id", index=True)
    repo: str
    number: int
    url: str
    base_branch: str
    head_branch: str
    head_sha: str
    state: str  # open | closed | merged
    merge_sha: str | None = None
    first_head_sha: str | None = None
    first_head_checks_green: bool | None = None
    diff_policy_ok: bool | None = None
    diff_policy_violations: list[str] = Field(default_factory=list, sa_column=Column(JSON))
    verification_level: VerificationLevel = VerificationLevel.pr_opened
    review_status: str | None = None
    review_comment_count: int = 0
    approved_by: str | None = None
    opened_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    merged_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    updated_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)


class PRCheck(SQLModel, table=True):
    __tablename__ = "pr_checks"
    __table_args__ = (UniqueConstraint("pull_request_id", "head_sha", "name", name="uq_pr_check"),)
    id: int | None = Field(default=None, primary_key=True)
    pull_request_id: int = Field(foreign_key="pull_requests.id", index=True)
    head_sha: str
    name: str
    status: str  # queued | in_progress | completed
    conclusion: str | None = None
    url: str | None = None
    observed_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)


class Event(SQLModel, table=True):
    """Append-only transition log; every metric is computed from it."""

    __tablename__ = "events"
    id: int | None = Field(default=None, primary_key=True)
    ts: datetime = Field(default_factory=utcnow, index=True, sa_type=UTCDateTime)
    actor: str  # controller | devin | human:<login> | ci | scanner
    entity_type: str  # work_item | finding | session | pull_request | scan_run
    entity_id: int = Field(index=True)
    event: str
    from_state: str | None = None
    to_state: str | None = None
    reason: str | None = None
    evidence_ids: list[int] = Field(default_factory=list, sa_column=Column(JSON))


class NegativeRun(SQLModel, table=True):
    __tablename__ = "negative_runs"
    id: int | None = Field(default=None, primary_key=True)
    case: str
    external_run_id: str
    branch: str
    pr_url: str | None = None
    expected: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    observed: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    passed: bool
    ran_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)


class RunReport(SQLModel, table=True):
    __tablename__ = "run_reports"
    id: int | None = Field(default=None, primary_key=True)
    generated_at: datetime = Field(default_factory=utcnow, sa_type=UTCDateTime)
    baseline_run_id: int | None = Field(default=None, foreign_key="scan_runs.id")
    latest_run_id: int | None = Field(default=None, foreign_key="scan_runs.id")
    upstream_master_sha: str | None = None
    body: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    markdown: str = ""


class FixtureMeta(SQLModel, table=True):
    __tablename__ = "fixtures_meta"
    id: int | None = Field(default=None, primary_key=True)
    baseline_sha: str
    captured_at: datetime | None = Field(default=None, sa_type=UTCDateTime)
    manifest: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    sha256sums_verified: bool = False
