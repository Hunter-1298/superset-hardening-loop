"""Dashboard metrics, computed from the database only (read-only). Every number here is derived
from persisted rows so live and replay databases render identically."""

from __future__ import annotations

import statistics
from collections import Counter, defaultdict
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field
from sqlalchemy.engine import Engine
from sqlmodel import col, select

from hardening_loop.db import session_scope
from hardening_loop.domain.enums import (
    ACTIVE_WORK_ITEM_STATES,
    CheckStatus,
    FindingState,
    Kind,
    LifecycleLevel,
    ScanMode,
    ScanRunStatus,
    Severity,
    VerificationDepth,
    WorkItemState,
)
from hardening_loop.gate import GateVerdict, gate_verdict
from hardening_loop.models.tables import (
    Finding,
    MetricsSnapshot,
    PullRequest,
    ScanRun,
    Session,
    Sighting,
    WorkItem,
)
from hardening_loop.orchestrator.closer import CLOSING_FINDING_STATES

OPEN_FINDING_STATES: frozenset[FindingState] = frozenset(
    {
        FindingState.open,
        FindingState.unclassified,
        FindingState.grouped,
        FindingState.in_remediation,
        FindingState.awaiting_rescan,
        FindingState.regression,
        FindingState.human_blocked,
    }
)


class RunSummary(BaseModel):
    id: int
    external_run_id: str
    source_branch: str
    source_sha: str
    trigger: str
    status: str
    is_baseline: bool
    ingested_at: datetime
    lean_digest: str | None
    scan_gate_mode: str
    tools: dict[str, Any]
    raw_by_severity: dict[str, int]
    policy_by_severity: dict[str, int]
    raw_total: int
    policy_total: int
    gate: dict[str, Any]


class FirstTry(BaseModel):
    attempted: int
    succeeded: int

    @property
    def rate(self) -> float | None:
        return self.succeeded / self.attempted if self.attempted else None


class Timing(BaseModel):
    verified_count: int
    median_hours: float | None
    p90_hours: float | None
    samples_hours: list[float] = Field(default_factory=list)


class Cost(BaseModel):
    acu_total: float
    acu_verified_items: float
    verified_items: int
    acu_per_verified_issue: float | None
    acu_cost_usd: float | None
    estimated_cost_total_usd: float | None
    estimated_cost_per_verified_issue_usd: float | None


class PRLevel(BaseModel):
    """Lifecycle progress and verification depth of one work item's PR. `level` is how far the
    fix travelled (PR -> CI -> review -> approval -> merge -> rescan); `depth` is the highest
    L0-L6 rung its current head proved with complete check evidence, None when nothing has."""

    work_item_id: int
    kind: str
    pr_url: str
    level: int
    level_name: str
    depth: int | None
    depth_name: str | None
    depth_rungs: dict[str, str]
    first_head_checks_green: bool | None
    retries_used: int
    state: str


class DepthSummary(BaseModel):
    """Verification depth across PRs: how many PR heads hold each rung as their highest, and
    how many rungs are only `partial` or `unavailable` (evidence gaps, never counted as passed)."""

    highest_by_depth: dict[str, int]
    prs_without_depth: int
    partial_rungs: int
    unavailable_rungs: int
    failed_rungs: int


class Throughput(BaseModel):
    verified_per_day: dict[str, int]
    prs_opened_per_day: dict[str, int]
    sessions_started_per_day: dict[str, int]


class Metrics(BaseModel):
    generated_at: datetime
    runs: list[RunSummary]
    findings_by_run: dict[str, dict[str, int]]
    findings_by_kind: dict[str, int]
    findings_by_layer: dict[str, int]
    findings_by_scanner: dict[str, int]
    findings_by_state: dict[str, int]
    open_high_critical: int
    issues_by_state: dict[str, int]
    first_try_overall: FirstTry
    first_try_by_kind: dict[str, FirstTry]
    timing: Timing
    timing_by_kind: dict[str, Timing]
    cost: Cost
    pr_levels: list[PRLevel]
    depth: DepthSummary
    throughput: Throughput
    retries_total: int
    active_sessions: int
    needs_human: int
    gate_ready_for_enforce: bool | None
    latest_main_run_id: int | None


# --------------------------------------------------------------------------- per-run counts


def _counts_by_severity(engine: Engine, run_id: int, mode: ScanMode) -> dict[str, int]:
    """Findings present in `run_id` for `mode`, counted once per finding (not per scanner) at the
    highest severity any scanner recorded for it in that run. The sightings' own severities are
    used, not the finding's, so a run's totals do not change when a later run rescores it."""
    with session_scope(engine) as db:
        rows = db.exec(
            select(Sighting.finding_id, Sighting.severity).where(
                Sighting.scan_run_id == run_id, Sighting.mode == mode, col(Sighting.present)
            )
        ).all()
    highest: dict[int, Severity] = {}
    for fid, sev in rows:
        severity = Severity(sev) if sev is not None else Severity.unknown
        if fid not in highest or severity.rank > highest[fid].rank:
            highest[fid] = severity
    c: Counter[str] = Counter(s.value for s in highest.values())
    return {s.value: c.get(s.value, 0) for s in Severity}


def raw_counts_by_severity(engine: Engine, run_id: int) -> dict[str, int]:
    return _counts_by_severity(engine, run_id, ScanMode.raw)


def policy_counts_by_severity(engine: Engine, run_id: int) -> dict[str, int]:
    return _counts_by_severity(engine, run_id, ScanMode.policy)


def run_gate(engine: Engine, run: ScanRun) -> GateVerdict:
    assert run.id is not None
    return gate_verdict(run.scan_gate_mode, policy_counts_by_severity(engine, run.id))


def summarize_run(engine: Engine, run: ScanRun) -> RunSummary:
    assert run.id is not None
    raw = raw_counts_by_severity(engine, run.id)
    pol = policy_counts_by_severity(engine, run.id)
    gate = gate_verdict(run.scan_gate_mode, pol)
    return RunSummary(
        id=run.id,
        external_run_id=run.external_run_id,
        source_branch=run.source_branch,
        source_sha=run.source_sha,
        trigger=run.trigger.value,
        status=run.status.value,
        is_baseline=run.is_baseline,
        ingested_at=run.ingested_at,
        lean_digest=run.lean_digest,
        scan_gate_mode=run.scan_gate_mode.value,
        tools=run.tools,
        raw_by_severity=raw,
        policy_by_severity=pol,
        raw_total=sum(raw.values()),
        policy_total=sum(pol.values()),
        gate={
            "mode": gate.mode.value,
            "passed": gate.passed,
            "reason": gate.reason,
            "ready_for_enforce": gate.ready_for_enforce,
        },
    )


# --------------------------------------------------------------------------- aggregates


def _hours(a: datetime | None, b: datetime | None) -> float | None:
    if a is None or b is None:
        return None
    return max((b - a).total_seconds(), 0.0) / 3600.0


def _percentile(values: list[float], pct: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    k = (len(ordered) - 1) * pct
    lo, hi = int(k), min(int(k) + 1, len(ordered) - 1)
    return ordered[lo] + (ordered[hi] - ordered[lo]) * (k - lo)


def _timing(items: list[WorkItem]) -> Timing:
    samples = [
        h
        for h in (_hours(w.issue_opened_at or w.created_at, w.verified_at) for w in items)
        if h is not None
    ]
    return Timing(
        verified_count=len(samples),
        median_hours=statistics.median(samples) if samples else None,
        p90_hours=_percentile(samples, 0.9),
        samples_hours=samples,
    )


def _first_try(prs: list[PullRequest]) -> FirstTry:
    judged = [p for p in prs if p.first_head_checks_green is not None]
    return FirstTry(
        attempted=len(judged), succeeded=sum(1 for p in judged if p.first_head_checks_green)
    )


def _day(ts: datetime | None) -> str | None:
    return ts.date().isoformat() if ts else None


def compute_metrics(engine: Engine, *, acu_cost_usd: float | None, now: datetime) -> Metrics:
    with session_scope(engine) as db:
        runs = list(
            db.exec(
                select(ScanRun).order_by(
                    col(ScanRun.finished_at), col(ScanRun.ingested_at), col(ScanRun.id)
                )
            ).all()
        )
        findings = list(db.exec(select(Finding)).all())
        items = list(db.exec(select(WorkItem).order_by(col(WorkItem.id))).all())
        prs = list(db.exec(select(PullRequest)).all())
        sessions = list(db.exec(select(Session)).all())
        for group in (runs, findings, items, prs, sessions):
            for row in group:
                db.expunge(row)

    run_summaries = [summarize_run(engine, r) for r in runs]
    findings_by_run = {s.external_run_id: s.raw_by_severity for s in run_summaries}

    by_kind: Counter[str] = Counter()
    by_layer: Counter[str] = Counter()
    by_scanner: Counter[str] = Counter()
    by_state: Counter[str] = Counter()
    open_hc = 0
    for f in findings:
        by_kind[f.kind.slug if f.kind else "unclassified"] += 1
        by_layer[f.layer.value] += 1
        by_state[f.state.value] += 1
        if f.reported_by_trivy and f.reported_by_grype:
            by_scanner["both"] += 1
        elif f.reported_by_trivy:
            by_scanner["trivy_only"] += 1
        elif f.reported_by_grype:
            by_scanner["grype_only"] += 1
        else:
            by_scanner["config"] += 1
        if f.state in OPEN_FINDING_STATES and f.severity in (Severity.high, Severity.critical):
            open_hc += 1

    issues_by_state = Counter(w.state.value for w in items)
    pr_by_wi = {p.work_item_id: p for p in prs}
    prs_by_kind: dict[str, list[PullRequest]] = defaultdict(list)
    for w in items:
        p = pr_by_wi.get(w.id or -1)
        if p is not None:
            prs_by_kind[w.kind.slug].append(p)

    verified = [w for w in items if w.state is WorkItemState.verified]
    verified_by_kind: dict[str, list[WorkItem]] = defaultdict(list)
    for w in verified:
        verified_by_kind[w.kind.slug].append(w)

    acu_by_wi: dict[int, float] = defaultdict(float)
    for s in sessions:
        acu_by_wi[s.work_item_id] += s.acus_consumed
    acu_total = float(sum(acu_by_wi.values()))
    acu_verified = float(sum(acu_by_wi.get(w.id or -1, 0.0) for w in verified))
    per_verified = acu_verified / len(verified) if verified else None
    cost = Cost(
        acu_total=acu_total,
        acu_verified_items=acu_verified,
        verified_items=len(verified),
        acu_per_verified_issue=per_verified,
        acu_cost_usd=acu_cost_usd,
        estimated_cost_total_usd=acu_total * acu_cost_usd if acu_cost_usd is not None else None,
        estimated_cost_per_verified_issue_usd=(
            per_verified * acu_cost_usd
            if per_verified is not None and acu_cost_usd is not None
            else None
        ),
    )

    pr_levels = [
        PRLevel(
            work_item_id=w.id or 0,
            kind=w.kind.slug,
            pr_url=w.pr_url or "",
            level=int(w.lifecycle_level),
            level_name=LifecycleLevel(w.lifecycle_level).name,
            depth=None if w.verification_depth is None else int(w.verification_depth),
            depth_name=None if w.verification_depth is None else w.verification_depth.name,
            depth_rungs=dict(pr_by_wi[w.id or -1].depth_rungs),
            first_head_checks_green=pr_by_wi[w.id or -1].first_head_checks_green,
            retries_used=w.retries_used,
            state=w.state.value,
        )
        for w in items
        if (w.id or -1) in pr_by_wi
    ]
    rung_values = [v for lv in pr_levels for v in lv.depth_rungs.values()]
    depth = DepthSummary(
        highest_by_depth={
            d.name: sum(1 for lv in pr_levels if lv.depth_name == d.name) for d in VerificationDepth
        },
        prs_without_depth=sum(1 for lv in pr_levels if lv.depth is None),
        partial_rungs=rung_values.count(CheckStatus.partial.value),
        unavailable_rungs=rung_values.count(CheckStatus.unavailable.value),
        failed_rungs=rung_values.count(CheckStatus.failed.value),
    )

    throughput = Throughput(
        verified_per_day=dict(
            sorted(Counter(d for d in (_day(w.verified_at) for w in verified) if d).items())
        ),
        prs_opened_per_day=dict(
            sorted(Counter(d for d in (_day(p.opened_at) for p in prs) if d).items())
        ),
        sessions_started_per_day=dict(
            sorted(Counter(d for d in (_day(s.created_at) for s in sessions) if d).items())
        ),
    )

    main_runs = [
        r
        for r in runs
        if r.source_branch == "main" and r.status is ScanRunStatus.complete and not r.is_baseline
    ] or [r for r in runs if r.source_branch == "main"]
    latest_main = max(main_runs, key=ScanRun.chronology) if main_runs else None
    gate_ready = (
        next(s for s in run_summaries if s.id == latest_main.id).gate["ready_for_enforce"]
        if latest_main is not None
        else None
    )

    return Metrics(
        generated_at=now,
        runs=run_summaries,
        findings_by_run=findings_by_run,
        findings_by_kind=dict(sorted(by_kind.items())),
        findings_by_layer=dict(sorted(by_layer.items())),
        findings_by_scanner=dict(sorted(by_scanner.items())),
        findings_by_state=dict(sorted(by_state.items())),
        open_high_critical=open_hc,
        issues_by_state={s.value: issues_by_state.get(s.value, 0) for s in WorkItemState},
        first_try_overall=_first_try(prs),
        first_try_by_kind={k.slug: _first_try(prs_by_kind.get(k.slug, [])) for k in Kind},
        timing=_timing(verified),
        timing_by_kind={k.slug: _timing(verified_by_kind.get(k.slug, [])) for k in Kind},
        cost=cost,
        pr_levels=pr_levels,
        depth=depth,
        throughput=throughput,
        retries_total=sum(w.retries_used for w in items),
        active_sessions=sum(1 for w in items if w.state in ACTIVE_WORK_ITEM_STATES),
        needs_human=sum(
            1 for w in items if w.state in (WorkItemState.needs_human, WorkItemState.failed)
        ),
        gate_ready_for_enforce=bool(gate_ready) if gate_ready is not None else None,
        latest_main_run_id=latest_main.id if latest_main else None,
    )


# --------------------------------------------------------------------------- persisted snapshots


def snapshot_metrics(
    engine: Engine, *, trigger: str, acu_cost_usd: float | None, now: datetime
) -> MetricsSnapshot:
    """Compute the current metrics and persist them as one `metrics_snapshots` row. The headline
    columns are denormalized for cheap trend queries; `body` keeps the full `Metrics` payload."""
    m = compute_metrics(engine, acu_cost_usd=acu_cost_usd, now=now)
    row = MetricsSnapshot(
        taken_at=now,
        trigger=trigger,
        latest_main_run_id=m.latest_main_run_id,
        open_high_critical=m.open_high_critical,
        needs_human=m.needs_human,
        active_sessions=m.active_sessions,
        verified_prs=m.cost.verified_items,
        acus_total=m.cost.acu_total,
        cost_usd_total=m.cost.estimated_cost_total_usd,
        body=m.model_dump(mode="json"),
    )
    with session_scope(engine) as db:
        db.add(row)
        db.commit()
        db.refresh(row)
        db.expunge(row)
    return row


def metrics_history(engine: Engine, *, limit: int = 200) -> list[MetricsSnapshot]:
    """Newest-first persisted snapshots (headline columns only are meant for charts; `body` is
    the full payload of each)."""
    with session_scope(engine) as db:
        rows = db.exec(
            select(MetricsSnapshot).order_by(col(MetricsSnapshot.id).desc()).limit(limit)
        ).all()
        for r in rows:
            db.expunge(r)
        return list(rows)


__all__ = [
    "CLOSING_FINDING_STATES",
    "OPEN_FINDING_STATES",
    "Cost",
    "FirstTry",
    "Metrics",
    "PRLevel",
    "RunSummary",
    "Throughput",
    "Timing",
    "compute_metrics",
    "metrics_history",
    "policy_counts_by_severity",
    "raw_counts_by_severity",
    "run_gate",
    "snapshot_metrics",
    "summarize_run",
]
