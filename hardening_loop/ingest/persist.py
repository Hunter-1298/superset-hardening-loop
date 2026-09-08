"""Persist verified scan evidence: ScanRun, ScanJobs, Evidence, Findings, Sightings.

Findings are *opened* from RAW-mode results only; POLICY-mode results are recorded as sightings so
that a raw-present / policy-absent finding is visibly "suppressed by approved VEX" rather than gone.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime
from operator import attrgetter
from typing import Any

from packaging.specifiers import SpecifierSet
from sqlalchemy import Engine
from sqlmodel import Session, select

from hardening_loop.classify.rules import Classification, ClassificationContext, classify
from hardening_loop.db import session_scope
from hardening_loop.domain.enums import (
    FindingState,
    GateMode,
    ImageTarget,
    Kind,
    ScanMode,
    Scanner,
    ScanRunStatus,
    Severity,
    Trigger,
)
from hardening_loop.ingest.evidence import BaselineManifest, ScanJobEvidence
from hardening_loop.ingest.normalize import NormalizedFinding, normalize
from hardening_loop.ingest.records import RawConfigFinding, RawVuln
from hardening_loop.models.tables import (
    Event,
    Evidence,
    Finding,
    ScanJob,
    ScanRun,
    Sighting,
    utcnow,
)


@dataclass
class IngestResult:
    scan_run_id: int
    created: bool
    findings_total: int = 0
    findings_new: int = 0
    findings_by_kind: dict[str, int] = field(default_factory=dict)
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    unclassified: int = 0
    policy_suppressed: int = 0

    def summary(self) -> str:
        return (
            f"run={self.scan_run_id} created={self.created} findings={self.findings_total} "
            f"new={self.findings_new} by_kind={self.findings_by_kind} "
            f"by_severity={self.findings_by_severity} unclassified={self.unclassified} "
            f"policy_suppressed={self.policy_suppressed}"
        )


@dataclass(frozen=True)
class RunMeta:
    external_run_id: str
    trigger: Trigger
    source_repo: str
    source_branch: str
    source_sha: str
    platform: str
    lean_digest: str | None
    ci_digest: str | None
    ci_layer_delta: dict[str, object] | None
    started_at: datetime | None
    finished_at: datetime | None
    is_baseline: bool = False
    run_attempt: int = 1
    scan_gate_mode: GateMode = GateMode.report
    # Findings are opened from this image only; other targets (the `ci` integration image) are
    # persisted as separate coverage and never open findings against production.
    primary_target: ImageTarget = ImageTarget.lean
    # GitHub job name -> result (`success`, `failure`, ...) for non-scanner jobs such as
    # `lean-smoke` and `app-runs`; anything but `success` keeps the run incomplete.
    job_results: dict[str, str] = field(default_factory=dict)
    workflow: dict[str, Any] | None = None


def ingest_baseline(
    engine: Engine,
    manifest: BaselineManifest,
    *,
    upper_bounds: dict[str, SpecifierSet] | None = None,
) -> IngestResult:
    meta = RunMeta(
        external_run_id=f"fixture:{manifest.source_sha}",
        trigger=Trigger(manifest.trigger),
        source_repo=manifest.source_repo,
        source_branch=manifest.source_branch,
        source_sha=manifest.source_sha,
        platform=manifest.platform,
        lean_digest=str(manifest.images["lean"]["image_id"]),
        ci_digest=str(manifest.images["ci"]["image_id"]),
        ci_layer_delta=manifest.ci_layer_delta,
        started_at=manifest.built_at,
        finished_at=manifest.captured_at,
        is_baseline=True,
        job_results=dict(manifest.run.get("job_results") or {}),
        workflow=manifest.run or None,
    )
    with session_scope(engine) as db:
        return ingest_run(db, meta, manifest.jobs, upper_bounds=upper_bounds or {})


def ingest_run(
    db: Session,
    meta: RunMeta,
    jobs: dict[str, ScanJobEvidence],
    *,
    upper_bounds: dict[str, SpecifierSet],
    now: datetime | None = None,
) -> IngestResult:
    ts = now or utcnow()
    existing = db.exec(
        select(ScanRun).where(ScanRun.external_run_id == meta.external_run_id)
    ).first()
    if existing is not None:
        assert existing.id is not None
        return IngestResult(scan_run_id=existing.id, created=False)

    primary = [j for j in jobs.values() if j.image_target is meta.primary_target]
    secondary = [j for j in jobs.values() if j.image_target is not meta.primary_target]
    raw_jobs = [j for j in primary if j.mode is ScanMode.raw]
    policy_jobs = [j for j in primary if j.mode is ScanMode.policy]
    if len(raw_jobs) != 1:
        raise ValueError(
            f"expected exactly one raw job for {meta.primary_target.value}, got {len(raw_jobs)}"
        )
    if len(policy_jobs) > 1:
        raise ValueError(f"expected at most one policy job per run, got {len(policy_jobs)}")
    if any(j.mode is not ScanMode.raw for j in secondary):
        raise ValueError("policy scans of a non-primary image target have no consumer")
    for j in secondary:
        if j.platform != meta.platform:
            raise ValueError(f"{j.image_target.value} job platform {j.platform} != {meta.platform}")
    raw = raw_jobs[0]
    policy = policy_jobs[0] if policy_jobs else None
    if raw.platform != meta.platform:
        raise ValueError(f"raw job platform {raw.platform} != run platform {meta.platform}")
    if policy is not None:
        subject = attrgetter("image_ref", "image_target", "platform", "layer_scope")
        if subject(policy) != subject(raw):
            raise ValueError(
                f"policy job scanned {subject(policy)}, raw job scanned {subject(raw)}: "
                "suppressions of one image cannot speak for another"
            )
    all_jobs_succeeded = all(j.all_jobs_succeeded for j in jobs.values()) and all(
        r == "success" for r in meta.job_results.values()
    )

    tools = {
        "syft": raw.tools.syft,
        "trivy": raw.tools.trivy,
        "grype": raw.tools.grype,
        "trivy_db_updated_at": raw.tools.trivy_db_updated_at.isoformat()
        if raw.tools.trivy_db_updated_at
        else None,
        "grype_db_built_at": raw.tools.grype_db_built_at.isoformat()
        if raw.tools.grype_db_built_at
        else None,
    }
    run = ScanRun(
        external_run_id=meta.external_run_id,
        run_attempt=meta.run_attempt,
        trigger=meta.trigger,
        source_repo=meta.source_repo,
        source_branch=meta.source_branch,
        source_sha=meta.source_sha,
        platform=meta.platform,
        lean_digest=meta.lean_digest,
        ci_digest=meta.ci_digest,
        ci_layer_delta=meta.ci_layer_delta,
        tools=tools,
        scan_gate_mode=meta.scan_gate_mode,
        vex_documents=[dict(v) for v in (policy.vex_documents if policy else [])],
        status=ScanRunStatus.complete if all_jobs_succeeded else ScanRunStatus.incomplete,
        started_at=meta.started_at,
        finished_at=meta.finished_at,
        is_baseline=meta.is_baseline,
        ingested_at=ts,
        workflow=meta.workflow,
    )
    db.add(run)
    db.flush()
    assert run.id is not None
    run_id = run.id

    for job in primary:
        _persist_job_rows(db, run_id, job)
    for job in secondary:
        _persist_job_rows(db, run_id, job, suffix=f"@{job.image_target.value}")
    for name, outcome in sorted(meta.job_results.items()):
        db.add(
            ScanJob(
                scan_run_id=run_id,
                name=name,
                layer_scope="runtime",
                success=outcome == "success",
                started_at=meta.started_at,
                finished_at=meta.finished_at,
            )
        )

    # Findings are opened from raw evidence.
    normalized = normalize(raw.vulns, raw.configs)
    ctx = ClassificationContext(
        scanner_job_success={
            Scanner.trivy: raw.job_success.get("trivy", False),
            Scanner.grype: raw.job_success.get("grype", False),
        },
        upper_bounds=upper_bounds,
    )
    policy_keys: set[str] = set()
    policy_by_key: dict[str, NormalizedFinding] = {}
    if policy is not None:
        for nf in normalize(policy.vulns, policy.configs):
            policy_keys.add(nf.dedupe_key)
            policy_by_key[nf.dedupe_key] = nf

    result = IngestResult(scan_run_id=run_id, created=True)
    by_kind: Counter[str] = Counter()
    by_sev: Counter[str] = Counter()
    for nf in normalized:
        cls = classify(nf, ctx)
        finding, is_new = _upsert_finding(db, run, raw, nf, cls, ts)
        assert finding.id is not None
        result.findings_new += int(is_new)
        by_kind[str(cls.kind.value) if cls.kind else "unclassified"] += 1
        by_sev[nf.severity.value] += 1
        if cls.kind is None:
            result.unclassified += 1
        for scanner in (Scanner.trivy, Scanner.grype):
            present_raw = scanner in nf.reported_by
            if present_raw:
                db.add(
                    Sighting(
                        finding_id=finding.id,
                        scan_run_id=run_id,
                        scanner=scanner,
                        mode=ScanMode.raw,
                        present=True,
                        severity=Severity(nf.severity_by_scanner[scanner.value]),
                        fixed_versions=nf.fix_versions_by_scanner.get(scanner.value, []),
                        record=nf.records.get(scanner.value),
                    )
                )
            if policy is not None and present_raw:
                pnf = policy_by_key.get(nf.dedupe_key)
                present_policy = pnf is not None and scanner in pnf.reported_by
                db.add(
                    Sighting(
                        finding_id=finding.id,
                        scan_run_id=run_id,
                        scanner=scanner,
                        mode=ScanMode.policy,
                        present=present_policy,
                        severity=Severity(pnf.severity_by_scanner[scanner.value])
                        if present_policy and pnf is not None
                        else None,
                        fixed_versions=pnf.fix_versions_by_scanner.get(scanner.value, [])
                        if present_policy and pnf is not None
                        else [],
                        record=None,
                    )
                )
        if policy is not None and nf.dedupe_key not in policy_keys:
            result.policy_suppressed += 1
        if is_new:
            db.add(
                Event(
                    actor="scanner",
                    entity_type="finding",
                    entity_id=finding.id,
                    event="opened",
                    from_state=None,
                    to_state=finding.state.value,
                    reason=f"first seen in run {meta.external_run_id}; {cls.trace}",
                    ts=ts,
                )
            )

    result.findings_total = len(normalized)
    result.findings_by_kind = dict(sorted(by_kind.items()))
    result.findings_by_severity = dict(sorted(by_sev.items()))
    db.add(
        Event(
            actor="controller",
            entity_type="scan_run",
            entity_id=run_id,
            event="ingested",
            to_state=run.status.value,
            reason=result.summary(),
            ts=ts,
        )
    )
    return result


def _persist_job_rows(db: Session, run_id: int, job: ScanJobEvidence, *, suffix: str = "") -> None:
    """`suffix` distinguishes jobs of a non-primary image target (`trivy-raw@ci`) from the
    production jobs the closer looks up by bare name."""
    for name, digest in job.files.items():
        db.add(
            Evidence(
                scan_run_id=run_id,
                kind="sbom"
                if name.startswith("sbom")
                else "vex"
                if name.startswith("vex/")
                else "scanner_output",
                path=str(job.path / name),
                sha256=digest,
            )
        )
    db.add(
        ScanJob(
            scan_run_id=run_id,
            name=f"trivy-{job.mode.value}{suffix}",
            scanner=Scanner.trivy,
            mode=job.mode,
            image_target=job.image_target,
            layer_scope=job.layer_scope,
            success=job.job_success.get("trivy", False),
            tool_version=job.tools.trivy,
            db_built_at=job.tools.trivy_db_updated_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            artifact_path=str(job.path / "trivy-vuln.json"),
            artifact_sha256=job.files.get("trivy-vuln.json"),
            counts=_severity_counts(job.trivy_vulns),
        )
    )
    db.add(
        ScanJob(
            scan_run_id=run_id,
            name=f"grype-{job.mode.value}{suffix}",
            scanner=Scanner.grype,
            mode=job.mode,
            image_target=job.image_target,
            layer_scope=job.layer_scope,
            success=job.job_success.get("grype", False),
            tool_version=job.tools.grype,
            db_built_at=job.tools.grype_db_built_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            artifact_path=str(job.path / "grype-vuln.json"),
            artifact_sha256=job.files.get("grype-vuln.json"),
            counts=_severity_counts(job.grype_vulns),
        )
    )
    db.add(
        ScanJob(
            scan_run_id=run_id,
            name=f"config-{job.mode.value}{suffix}",
            scanner=Scanner.trivy,
            mode=job.mode,
            image_target=job.image_target,
            layer_scope="config",
            success=job.job_success.get("config", False),
            tool_version=job.tools.trivy,
            started_at=job.started_at,
            finished_at=job.finished_at,
            artifact_path=str(job.path / "trivy-config.json"),
            artifact_sha256=job.files.get("trivy-config.json"),
            counts={
                **_severity_counts(job.configs),
                "image_config": len(job.image_config),
                "iac_config": len(job.iac_config),
            },
        )
    )


def _severity_counts(items: Sequence[RawVuln] | Sequence[RawConfigFinding]) -> dict[str, int]:
    return dict(Counter(i.severity.value for i in items))


def _upsert_finding(
    db: Session,
    run: ScanRun,
    raw: ScanJobEvidence,
    nf: NormalizedFinding,
    cls: Classification,
    ts: datetime,
) -> tuple[Finding, bool]:
    """Open or refresh the finding `nf` names. A finding's mutable description (package, version,
    severity, classification, `last_seen_run_id`, state) always reflects the run that finished
    last: a run ingested after a newer scan has already spoken for the finding only records its
    sightings and, if it finished first, becomes the finding's `first_seen_run_id`."""
    assert run.id is not None
    run_id = run.id
    finding = db.exec(select(Finding).where(Finding.dedupe_key == nf.dedupe_key)).first()
    is_new = finding is None
    if finding is not None and _finished_before(db, run, finding.first_seen_run_id):
        finding.first_seen_run_id = run_id
    if finding is not None and _finished_before(db, run, finding.last_seen_run_id):
        db.add(finding)
        db.flush()
        return finding, False
    if finding is None:
        finding = Finding(
            dedupe_key=nf.dedupe_key,
            vuln_id=nf.vuln_id,
            layer=nf.layer,
            first_seen_run_id=run_id,
            last_seen_run_id=run_id,
            created_at=ts,
            opening_db_built_at=min(
                (d for d in (raw.tools.trivy_db_updated_at, raw.tools.grype_db_built_at) if d),
                default=None,
            ),
            opened_by_trivy=Scanner.trivy in nf.reported_by,
            opened_by_grype=Scanner.grype in nf.reported_by,
        )
    finding.purl = nf.purl
    finding.pkg_name = nf.pkg_name
    finding.pkg_version = nf.pkg_version
    finding.ecosystem = nf.ecosystem
    finding.image_target = ImageTarget(raw.image_target)
    finding.platform = raw.platform
    finding.resource = nf.resource
    finding.title = nf.title
    finding.severity = nf.severity
    finding.severity_by_scanner = dict(nf.severity_by_scanner)
    finding.severity_disagreement = nf.severity_disagreement
    finding.fix_versions_by_scanner = {k: list(v) for k, v in nf.fix_versions_by_scanner.items()}
    finding.reported_by_trivy = Scanner.trivy in nf.reported_by
    finding.reported_by_grype = Scanner.grype in nf.reported_by
    finding.kind = cls.kind
    finding.risk = cls.risk
    finding.bound_blocked = cls.bound_blocked
    finding.classification_trace = cls.trace
    finding.unclassified_reason = cls.unclassified_reason
    finding.last_seen_run_id = run_id
    finding.updated_at = ts
    if finding.state in _CLOSED_STATES:
        # Seen again after closure: that is a regression, recorded by the orchestrator, not here.
        pass
    elif cls.kind is None:
        finding.state = FindingState.unclassified
    elif finding.state is FindingState.unclassified:
        finding.state = FindingState.open
    db.add(finding)
    db.flush()
    return finding, is_new


def _finished_before(db: Session, run: ScanRun, other_run_id: int) -> bool:
    """Whether `run` finished strictly before the run `other_run_id` (scan chronology, not
    ingestion order). Unknown timestamps never reorder."""
    if other_run_id == run.id or run.finished_at is None:
        return False
    other = db.get(ScanRun, other_run_id)
    return (
        other is not None and other.finished_at is not None and run.finished_at < other.finished_at
    )


_CLOSED_STATES = frozenset(
    {
        FindingState.fixed,
        FindingState.approved_disposition,
        FindingState.scanner_disagreement_resolved,
    }
)


def kind_counts(db: Session, run_id: int) -> dict[Kind | None, int]:
    findings = db.exec(select(Finding).where(Finding.last_seen_run_id == run_id)).all()
    return dict(Counter(f.kind for f in findings))
