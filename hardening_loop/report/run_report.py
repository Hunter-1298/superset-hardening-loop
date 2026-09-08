"""Database-backed run report: baseline vs latest `main` scan, raw vs policy, per
kind/layer/scanner, finding outcomes, image digests, scanner versions, vulnerability-DB ages,
gate readiness, and every dependency upgrade compared with the pin on `upstream-master`.
Read-only; nothing here mutates application state except the optional `persist_report` row."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, Field
from sqlalchemy.engine import Engine
from sqlmodel import col, select

from hardening_loop.db import session_scope
from hardening_loop.domain.enums import (
    CLOSING_TRIGGERS,
    Kind,
    LifecycleLevel,
    ScanMode,
    ScanRunStatus,
    Severity,
    VerificationDepth,
    WorkItemState,
)
from hardening_loop.ingest.evidence import load_source_file, parse_requirements_pins
from hardening_loop.metrics import (
    policy_counts_by_severity,
    raw_counts_by_severity,
    run_gate,
)
from hardening_loop.models.lineage import members_with_lineage, package_of_group_key
from hardening_loop.models.tables import (
    Finding,
    PullRequest,
    RunReport,
    ScanJob,
    ScanRun,
    Session,
    Sighting,
    WorkItem,
)

UPSTREAM_REQUIREMENTS = "requirements/base.txt"
UPSTREAM_FIXTURE_NAME = "requirements-base.txt"


class RunFacts(BaseModel):
    id: int
    external_run_id: str
    source_branch: str
    source_sha: str
    trigger: str
    status: str
    is_baseline: bool
    scan_gate_mode: str
    lean_digest: str | None
    ci_digest: str | None
    ci_layer_delta: dict[str, Any] | None
    platform: str
    tools: dict[str, Any]
    ingested_at: datetime
    jobs: list[dict[str, Any]]
    db_built_at: dict[str, datetime | None]
    raw_by_severity: dict[str, int]
    policy_by_severity: dict[str, int]
    raw_total: int
    policy_total: int
    raw_by_kind: dict[str, int]
    raw_by_layer: dict[str, int]
    raw_by_scanner: dict[str, int]
    policy_by_kind: dict[str, int]
    gate_mode: str
    gate_passed: bool
    gate_reason: str
    gate_ready_for_enforce: bool


class SeverityDelta(BaseModel):
    severity: str
    baseline_raw: int
    latest_raw: int
    raw_delta: int
    baseline_policy: int
    latest_policy: int
    policy_delta: int


class DependencyRow(BaseModel):
    work_item_id: int
    package: str
    baseline_version: str | None
    devin_target_version: str | None
    upstream_master_version: str | None
    # matches | above | below | upstream_unpinned | no_target | unparseable
    relation_to_upstream: str
    min_fixed_version: str | None
    vuln_ids: list[str]
    bound_blocked: bool
    state: str
    lifecycle_level: int
    lifecycle_label: str
    verification_depth: int | None
    depth_label: str
    outcome_states: dict[str, int]
    acus: float
    retries_used: int
    pr_url: str | None
    blocked_reason: str | None


class WorkItemRow(BaseModel):
    work_item_id: int
    kind: str
    title: str
    state: str
    lifecycle_level: int
    lifecycle_label: str
    verification_depth: int | None
    depth_label: str
    depth_rungs: dict[str, str]
    acus: float
    acu_cap: float
    estimated_cost_usd: float | None
    retries_used: int
    first_head_checks_green: bool | None
    pr_url: str | None
    issue_url: str | None
    blocked_reason: str | None
    member_findings: int
    member_outcomes: dict[str, int]


class ReportBody(BaseModel):
    generated_at: datetime
    fork_repo: str
    baseline: RunFacts | None
    latest: RunFacts | None
    latest_is_closing_candidate: bool
    severity_deltas: list[SeverityDelta]
    outcomes: dict[str, int]
    outcomes_by_kind: dict[str, dict[str, int]]
    work_items_by_state: dict[str, int]
    upstream_master_sha: str | None
    upstream_pins_source: str | None
    dependencies: list[DependencyRow]
    work_items: list[WorkItemRow]
    acu_total: float
    acu_cost_usd: float | None
    estimated_cost_total_usd: float | None
    verified_items: int
    retries_total: int
    notes: list[str] = Field(default_factory=list)


# ------------------------------------------------------------------------------ run facts


def _present_ids(engine: Engine, run_id: int, mode: ScanMode) -> set[int]:
    with session_scope(engine) as db:
        return set(
            db.exec(
                select(Sighting.finding_id).where(
                    Sighting.scan_run_id == run_id,
                    Sighting.mode == mode,
                    col(Sighting.present),
                )
            ).all()
        )


def _scanner_bucket(f: Finding) -> str:
    if f.reported_by_trivy and f.reported_by_grype:
        return "both"
    if f.reported_by_trivy:
        return "trivy_only"
    if f.reported_by_grype:
        return "grype_only"
    return "config"


def run_facts(engine: Engine, run: ScanRun, findings_by_id: dict[int, Finding]) -> RunFacts:
    assert run.id is not None
    raw_ids = _present_ids(engine, run.id, ScanMode.raw)
    pol_ids = _present_ids(engine, run.id, ScanMode.policy)
    raw_kind: Counter[str] = Counter()
    raw_layer: Counter[str] = Counter()
    raw_scanner: Counter[str] = Counter()
    pol_kind: Counter[str] = Counter()
    for fid in raw_ids:
        f = findings_by_id.get(fid)
        if f is None:
            continue
        raw_kind[f.kind.slug if f.kind else "unclassified"] += 1
        raw_layer[f.layer.value] += 1
        raw_scanner[_scanner_bucket(f)] += 1
    for fid in pol_ids:
        f = findings_by_id.get(fid)
        if f is not None:
            pol_kind[f.kind.slug if f.kind else "unclassified"] += 1
    with session_scope(engine) as db:
        jobs = list(
            db.exec(select(ScanJob).where(ScanJob.scan_run_id == run.id).order_by(col(ScanJob.id)))
        )
        for j in jobs:
            db.expunge(j)
    raw = raw_counts_by_severity(engine, run.id)
    pol = policy_counts_by_severity(engine, run.id)
    gate = run_gate(engine, run)
    return RunFacts(
        id=run.id,
        external_run_id=run.external_run_id,
        source_branch=run.source_branch,
        source_sha=run.source_sha,
        trigger=run.trigger.value,
        status=run.status.value,
        is_baseline=run.is_baseline,
        scan_gate_mode=run.scan_gate_mode.value,
        lean_digest=run.lean_digest,
        ci_digest=run.ci_digest,
        ci_layer_delta=run.ci_layer_delta,
        platform=run.platform,
        tools=run.tools,
        ingested_at=run.ingested_at,
        jobs=[
            {
                "name": j.name,
                "scanner": j.scanner.value if j.scanner else None,
                "mode": j.mode.value if j.mode else None,
                "layer_scope": j.layer_scope,
                "success": j.success,
                "tool_version": j.tool_version,
                "db_built_at": j.db_built_at.isoformat() if j.db_built_at else None,
                "counts": j.counts,
            }
            for j in jobs
        ],
        db_built_at={j.name: j.db_built_at for j in jobs if j.scanner is not None},
        raw_by_severity=raw,
        policy_by_severity=pol,
        raw_total=sum(raw.values()),
        policy_total=sum(pol.values()),
        raw_by_kind=dict(sorted(raw_kind.items())),
        raw_by_layer=dict(sorted(raw_layer.items())),
        raw_by_scanner=dict(sorted(raw_scanner.items())),
        policy_by_kind=dict(sorted(pol_kind.items())),
        gate_mode=gate.mode.value,
        gate_passed=gate.passed,
        gate_reason=gate.reason,
        gate_ready_for_enforce=gate.ready_for_enforce,
    )


def select_runs(
    runs: list[ScanRun], *, fork_repo: str, branch: str
) -> tuple[ScanRun | None, ScanRun | None]:
    """Baseline = the flagged baseline run (else the oldest run on `branch`); latest = the newest
    successful non-PR run of `branch`, falling back to the newest run of `branch` of any status."""
    on_branch = sorted(
        (r for r in runs if r.source_repo == fork_repo and r.source_branch == branch),
        key=ScanRun.chronology,
    )
    baseline = next((r for r in on_branch if r.is_baseline), on_branch[0] if on_branch else None)
    closing = [
        r for r in on_branch if r.status is ScanRunStatus.complete and r.trigger in CLOSING_TRIGGERS
    ]
    latest = closing[-1] if closing else (on_branch[-1] if on_branch else None)
    return baseline, latest


# --------------------------------------------------------------------------- dependencies


def _parse(v: str | None) -> Version | None:
    if not v:
        return None
    try:
        return Version(v)
    except InvalidVersion:
        return None


def _relation(target: str | None, upstream: str | None) -> str:
    if target is None:
        return "no_target"
    if upstream is None:
        return "upstream_unpinned"
    t, u = _parse(target), _parse(upstream)
    if t is None or u is None:
        return "unparseable"
    if t == u:
        return "matches"
    return "above" if t > u else "below"


def _min_fixed(members: list[Finding]) -> str | None:
    versions: list[Version] = []
    for f in members:
        for vs in f.fix_versions_by_scanner.values():
            versions.extend(v for v in (_parse(x) for x in vs) if v is not None)
    return str(max(versions)) if versions else None


def _target_from_sessions(sessions: list[Session], package: str) -> str | None:
    for s in reversed(sessions):
        out = s.structured_output or {}
        pkgs = out.get("packages")
        if not isinstance(pkgs, list):
            continue
        for p in pkgs:
            if isinstance(p, dict) and str(p.get("name", "")).lower() == package.lower():
                to = p.get("to")
                return str(to) if to is not None else None
    return None


def dependency_rows(
    items: list[WorkItem],
    findings_by_wi: dict[int, list[Finding]],
    sessions_by_wi: dict[int, list[Session]],
    upstream_pins: dict[str, str] | None,
) -> list[DependencyRow]:
    rows: list[DependencyRow] = []
    for w in items:
        if w.kind is not Kind.dependency_upgrade or w.id is None:
            continue
        members = findings_by_wi.get(w.id, [])
        package = package_of_group_key(w.group_key)
        baseline_versions = sorted({f.pkg_version for f in members if f.pkg_version})
        sessions = sessions_by_wi.get(w.id, [])
        target = _target_from_sessions(sessions, package)
        upstream = upstream_pins.get(package.lower()) if upstream_pins is not None else None
        rows.append(
            DependencyRow(
                work_item_id=w.id,
                package=package,
                baseline_version=", ".join(baseline_versions) or None,
                devin_target_version=target,
                upstream_master_version=upstream,
                relation_to_upstream=_relation(target, upstream),
                min_fixed_version=_min_fixed(members),
                vuln_ids=sorted({f.vuln_id for f in members}),
                bound_blocked=any(f.bound_blocked for f in members),
                state=w.state.value,
                lifecycle_level=int(w.lifecycle_level),
                lifecycle_label=LifecycleLevel(w.lifecycle_level).label,
                verification_depth=_depth_int(w.verification_depth),
                depth_label=_depth_label(w.verification_depth),
                outcome_states=dict(Counter(f.state.value for f in members)),
                acus=float(sum(s.acus_consumed for s in sessions)),
                retries_used=w.retries_used,
                pr_url=w.pr_url,
                blocked_reason=w.blocked_reason,
            )
        )
    return rows


def upstream_pins_from_fixture(root: Path, upstream_sha: str) -> dict[str, str]:
    return parse_requirements_pins(load_source_file(root, upstream_sha, UPSTREAM_FIXTURE_NAME))


# ---------------------------------------------------------------------------------- build


def build_report(
    engine: Engine,
    *,
    fork_repo: str,
    branch: str,
    acu_cost_usd: float | None,
    now: datetime,
    upstream_master_sha: str | None,
    upstream_pins: dict[str, str] | None,
    upstream_pins_source: str | None,
) -> ReportBody:
    with session_scope(engine) as db:
        runs = list(
            db.exec(
                select(ScanRun).order_by(
                    col(ScanRun.finished_at), col(ScanRun.ingested_at), col(ScanRun.id)
                )
            ).all()
        )
        findings = list(db.exec(select(Finding).order_by(col(Finding.id))).all())
        items = list(db.exec(select(WorkItem).order_by(col(WorkItem.id))).all())
        prs = list(db.exec(select(PullRequest)).all())
        sessions = list(db.exec(select(Session).order_by(col(Session.id))).all())
        for group in (runs, findings, items, prs, sessions):
            for row in group:
                db.expunge(row)

    findings_by_id = {f.id: f for f in findings if f.id is not None}
    findings_by_wi = members_with_lineage(items, findings)
    sessions_by_wi: dict[int, list[Session]] = defaultdict(list)
    for s in sessions:
        sessions_by_wi[s.work_item_id].append(s)
    pr_by_wi = {p.work_item_id: p for p in prs}

    baseline_run, latest_run = select_runs(runs, fork_repo=fork_repo, branch=branch)
    baseline = run_facts(engine, baseline_run, findings_by_id) if baseline_run else None
    latest = run_facts(engine, latest_run, findings_by_id) if latest_run else None
    notes: list[str] = []
    if baseline is None:
        notes.append("no baseline run ingested")
    if latest is not None and baseline is not None and latest.id == baseline.id:
        notes.append("latest run is the baseline run: no closing scan of main has been ingested")
    latest_is_closing = bool(
        latest_run
        and latest_run.status is ScanRunStatus.complete
        and latest_run.trigger in CLOSING_TRIGGERS
    )
    if latest is not None and not latest_is_closing:
        notes.append(f"latest run {latest.external_run_id} is not a valid closing run")

    deltas: list[SeverityDelta] = []
    for sev in Severity:
        b_raw = baseline.raw_by_severity.get(sev.value, 0) if baseline else 0
        l_raw = latest.raw_by_severity.get(sev.value, 0) if latest else 0
        b_pol = baseline.policy_by_severity.get(sev.value, 0) if baseline else 0
        l_pol = latest.policy_by_severity.get(sev.value, 0) if latest else 0
        deltas.append(
            SeverityDelta(
                severity=sev.value,
                baseline_raw=b_raw,
                latest_raw=l_raw,
                raw_delta=l_raw - b_raw,
                baseline_policy=b_pol,
                latest_policy=l_pol,
                policy_delta=l_pol - b_pol,
            )
        )

    outcomes: Counter[str] = Counter(f.state.value for f in findings)
    outcomes_by_kind: dict[str, Counter[str]] = defaultdict(Counter)
    for f in findings:
        outcomes_by_kind[f.kind.slug if f.kind else "unclassified"][f.state.value] += 1

    acu_by_wi = {wi: float(sum(s.acus_consumed for s in ss)) for wi, ss in sessions_by_wi.items()}
    acu_total = float(sum(acu_by_wi.values()))
    wi_rows = [
        WorkItemRow(
            work_item_id=w.id,
            kind=w.kind.slug,
            title=w.title,
            state=w.state.value,
            lifecycle_level=int(w.lifecycle_level),
            lifecycle_label=LifecycleLevel(w.lifecycle_level).label,
            verification_depth=_depth_int(w.verification_depth),
            depth_label=_depth_label(w.verification_depth),
            depth_rungs=dict(pr_by_wi[w.id].depth_rungs) if w.id in pr_by_wi else {},
            acus=acu_by_wi.get(w.id, 0.0),
            acu_cap=w.acu_cap,
            estimated_cost_usd=(
                acu_by_wi.get(w.id, 0.0) * acu_cost_usd if acu_cost_usd is not None else None
            ),
            retries_used=w.retries_used,
            first_head_checks_green=(
                pr_by_wi[w.id].first_head_checks_green if w.id in pr_by_wi else None
            ),
            pr_url=w.pr_url,
            issue_url=w.issue_url,
            blocked_reason=w.blocked_reason,
            member_findings=len(findings_by_wi.get(w.id, [])),
            member_outcomes=dict(Counter(f.state.value for f in findings_by_wi.get(w.id, []))),
        )
        for w in items
        if w.id is not None
    ]
    if upstream_pins is None:
        notes.append("upstream-master pins unavailable: dependency comparison is partial")

    return ReportBody(
        generated_at=now,
        fork_repo=fork_repo,
        baseline=baseline,
        latest=latest,
        latest_is_closing_candidate=latest_is_closing,
        severity_deltas=deltas,
        outcomes=dict(sorted(outcomes.items())),
        outcomes_by_kind={k: dict(sorted(v.items())) for k, v in sorted(outcomes_by_kind.items())},
        work_items_by_state=dict(sorted(Counter(w.state.value for w in items).items())),
        upstream_master_sha=upstream_master_sha,
        upstream_pins_source=upstream_pins_source,
        dependencies=dependency_rows(items, findings_by_wi, sessions_by_wi, upstream_pins),
        work_items=wi_rows,
        acu_total=acu_total,
        acu_cost_usd=acu_cost_usd,
        estimated_cost_total_usd=acu_total * acu_cost_usd if acu_cost_usd is not None else None,
        verified_items=sum(1 for w in items if w.state is WorkItemState.verified),
        retries_total=sum(w.retries_used for w in items),
        notes=notes,
    )


# ------------------------------------------------------------------------------- markdown


def _fmt(v: object) -> str:
    if v is None:
        return "-"
    if isinstance(v, float):
        return f"{v:.2f}"
    if isinstance(v, datetime):
        return v.isoformat(timespec="seconds")
    if isinstance(v, dict):
        return ", ".join(f"{k}={val}" for k, val in v.items()) or "-"
    return str(v)


def _short(sha: str | None) -> str:
    return sha[:12] if sha else "-"


def _run_block(label: str, r: RunFacts | None) -> list[str]:
    if r is None:
        return [f"**{label}:** none", ""]
    lines = [
        f"**{label}:** run `{r.external_run_id}` (db id {r.id}) - {r.source_branch}@"
        f"{_short(r.source_sha)} - trigger `{r.trigger}` - status `{r.status}` - gate mode "
        f"`{r.scan_gate_mode}`",
        "",
        f"- lean digest: `{r.lean_digest or '-'}`; platform `{r.platform}`",
        f"- ci digest: `{r.ci_digest or '-'}`; ci layer delta: {_fmt(r.ci_layer_delta)}",
        f"- tools: {_fmt(r.tools)}",
        "- vulnerability DB built at: "
        + (", ".join(f"{k}={_fmt(v)}" for k, v in r.db_built_at.items()) or "-"),
        "- jobs: " + ", ".join(f"{j['name']}={'ok' if j['success'] else 'FAILED'}" for j in r.jobs),
        f"- raw findings: {r.raw_total} ({_fmt(r.raw_by_severity)})",
        f"- policy findings: {r.policy_total} ({_fmt(r.policy_by_severity)})",
        f"- raw by kind: {_fmt(r.raw_by_kind)}",
        f"- raw by layer: {_fmt(r.raw_by_layer)}",
        f"- raw by scanner: {_fmt(r.raw_by_scanner)}",
        f"- gate: {'PASS' if r.gate_passed else 'FAIL'} - {r.gate_reason}; "
        f"ready for enforce: {'yes' if r.gate_ready_for_enforce else 'no'}",
        "",
    ]
    return lines


def render_markdown(body: ReportBody) -> str:
    out: list[str] = [
        f"# Hardening run report - {body.fork_repo}",
        "",
        f"Generated {body.generated_at.isoformat(timespec='seconds')}.",
        "",
    ]
    if body.notes:
        out += ["> " + n for n in body.notes] + [""]
    out += ["## Runs", ""]
    out += _run_block("Baseline", body.baseline)
    out += _run_block("Latest", body.latest)

    out += [
        "## Raw vs policy by severity (baseline -> latest)",
        "",
        "| Severity | Raw baseline | Raw latest | Raw delta | Policy baseline | Policy latest "
        "| Policy delta |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for d in body.severity_deltas:
        out.append(
            f"| {d.severity} | {d.baseline_raw} | {d.latest_raw} | {d.raw_delta:+d} | "
            f"{d.baseline_policy} | {d.latest_policy} | {d.policy_delta:+d} |"
        )
    out += ["", "## Finding outcomes", "", "| Outcome | Count |", "|---|---:|"]
    out += [f"| {k} | {v} |" for k, v in body.outcomes.items()]
    out += ["", "| Kind | Outcomes |", "|---|---|"]
    out += [f"| {k} | {_fmt(v)} |" for k, v in body.outcomes_by_kind.items()]
    out += ["", f"Work items by state: {_fmt(body.work_items_by_state)}", ""]

    out += [
        "## Dependency upgrades vs upstream-master",
        "",
        f"upstream-master @ `{_short(body.upstream_master_sha)}`"
        + (f" (pins from {body.upstream_pins_source})" if body.upstream_pins_source else ""),
        "",
        "| WI | Package | Baseline | Devin target | upstream-master | Relation | Min fixed | "
        "Bound blocked | State | Lifecycle | Depth | ACUs | Retries | Outcomes |",
        "|---:|---|---|---|---|---|---|---|---|---|---|---:|---:|---|",
    ]
    for dep in body.dependencies:
        out.append(
            f"| {dep.work_item_id} | {dep.package} | {_fmt(dep.baseline_version)} | "
            f"{_fmt(dep.devin_target_version)} | {_fmt(dep.upstream_master_version)} | "
            f"{dep.relation_to_upstream} | {_fmt(dep.min_fixed_version)} | "
            f"{'yes' if dep.bound_blocked else 'no'} | {dep.state} | {dep.lifecycle_label} | "
            f"{dep.depth_label} | {dep.acus:.2f} | {dep.retries_used} | "
            f"{_fmt(dep.outcome_states)} |"
        )
    if not body.dependencies:
        out.append("| - | no dependency-upgrade work items | | | | | | | | | | | | |")

    out += [
        "",
        "## Work items: ACU, cost, retries, verification",
        "",
        f"Total ACUs {body.acu_total:.2f}; ACU cost USD {_fmt(body.acu_cost_usd)}; estimated "
        f"total cost {_fmt(body.estimated_cost_total_usd)}; verified items {body.verified_items}; "
        f"retries {body.retries_total}.",
        "",
        "| WI | Kind | State | Lifecycle | Depth | Rungs | ACUs / cap | Cost USD | Retries | "
        "First-try CI | Members | Outcomes |",
        "|---:|---|---|---|---|---|---|---:|---:|---|---:|---|",
    ]
    for w in body.work_items:
        first = "-" if w.first_head_checks_green is None else str(w.first_head_checks_green)
        out.append(
            f"| {w.work_item_id} | {w.kind} | {w.state} | {w.lifecycle_label} | "
            f"{w.depth_label} | {_rungs(w.depth_rungs)} | "
            f"{w.acus:.2f} / {w.acu_cap:.0f} | {_fmt(w.estimated_cost_usd)} | {w.retries_used} | "
            f"{first} | {w.member_findings} | {_fmt(w.member_outcomes)} |"
        )
    return "\n".join(out) + "\n"


def _depth_int(depth: VerificationDepth | None) -> int | None:
    return None if depth is None else int(depth)


def _depth_label(depth: VerificationDepth | None) -> str:
    """`none` when no rung has complete passing evidence; L0 is never implied."""
    return "none" if depth is None else depth.label


def _rungs(rungs: dict[str, str]) -> str:
    """Compact `L0=passed L3=partial L6=unavailable` view so evidence gaps stay greppable."""
    if not rungs:
        return "-"
    parts = []
    for d in VerificationDepth:
        status = rungs.get(d.name)
        if status is not None:
            parts.append(f"L{int(d)}={status}")
    return " ".join(parts) or "-"


def persist_report(engine: Engine, body: ReportBody, markdown: str) -> int:
    with session_scope(engine) as db:
        row = RunReport(
            generated_at=body.generated_at,
            baseline_run_id=body.baseline.id if body.baseline else None,
            latest_run_id=body.latest.id if body.latest else None,
            upstream_master_sha=body.upstream_master_sha,
            body=body.model_dump(mode="json"),
            markdown=markdown,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        assert row.id is not None
        return row.id


def latest_persisted_report(engine: Engine) -> RunReport | None:
    with session_scope(engine) as db:
        row = db.exec(select(RunReport).order_by(col(RunReport.id).desc())).first()
        if row is not None:
            db.expunge(row)
        return row
