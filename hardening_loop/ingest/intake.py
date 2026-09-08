"""Bring completed fork `security-scan` workflow runs into the controller.

The workflow uploads one `scan-evidence-<source sha>` artifact per run: the tree `scan-manifest`
aggregated (`manifest.json`, `SHA256SUMS`, one directory per scan job, gate verdicts, registry
manifests). Intake downloads that bundle, verifies every checksum and identity the manifest makes,
checks it against what the controller expects of a scan of the fork, and only then persists it as a
`ScanRun` through the same `ingest_run` path replay and the baseline fixture use.

Every run the poller looks at gets exactly one `ScanIntake` row keyed by the GitHub run id and
attempt, whether it was ingested or rejected, so a rejected bundle stays visible with its reasons
and nothing is silently retried or silently skipped. A run seen twice is a no-op.

Fail-closed rules (any one rejects the bundle; the raw files stay on disk under the intake's
`bundle_path` for inspection):

* no `manifest.json`, wrong schema, or any file whose sha256 differs from the manifest/SHA256SUMS
  (`load_baseline` also re-verifies each job directory and the image each job scanned);
* `source_repo` outside the allowlist or not the expected fork; `source_branch` not the expected
  branch; the run's GitHub-reported `head_branch` not the expected branch or its `event` not the
  manifest's trigger; `source_sha` (or the recorded PR head) not the commit GitHub says the run
  was for;
* the manifest's own `run.run_id`/`run_attempt` not matching the run the artifact was downloaded
  from;
* `source_sha` not a descendant of the 6.1.0 baseline commit (ancestry is asked of GitHub);
* platform other than the expected one; any required scan job (`lean-raw`, `lean-policy`,
  `ci-raw`) missing; a scan job whose evidence lacks either scanner;
* a required runtime job (`lean-smoke`, `app-runs`) with no recorded result, or without its
  attached, checksummed verdict (`runtime/<job>/<job>.json`), or whose verdict is malformed, names
  an image other than the manifest's digest for that target, or reports a failure while
  `run.job_results` claims `success`. The job-result string alone never proves a runtime job.

A run whose runtime jobs *failed* (result recorded, not `success`) or whose workflow conclusion is
not `success` is ingested with its raw evidence and persisted `incomplete`; the closer never
accepts an incomplete run as proof of absence.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from packaging.specifiers import SpecifierSet
from sqlalchemy import Engine
from sqlmodel import Session, select

from hardening_loop.ci import DEFAULT_EXPECTED_JOBS, REQUIRED_RUNTIME_JOBS
from hardening_loop.classify.rules import parse_upper_bounds
from hardening_loop.config import BASELINE_SHA, FORK_REPO, REMEDIATION_BRANCH, REPO_ALLOWLIST
from hardening_loop.db import session_scope, write_scope
from hardening_loop.domain.enums import GateMode, IntakeStatus, Scanner, Trigger
from hardening_loop.github.artifacts import ArtifactError
from hardening_loop.github.protocol import ArtifactInfo, GitHubClient, WorkflowRunInfo
from hardening_loop.ingest.evidence import (
    RUNTIME_RECORDS,
    SCAN_MANIFEST_SCHEMA,
    BaselineManifest,
    EvidenceError,
    RuntimeRecord,
    load_baseline,
    load_source_pyproject,
)
from hardening_loop.ingest.persist import IngestResult, RunMeta, ingest_run
from hardening_loop.models.tables import ScanIntake

log = logging.getLogger(__name__)

SECURITY_SCAN_WORKFLOW = "security-scan.yml"
EVIDENCE_ARTIFACT_PREFIX = "scan-evidence-"
DEFAULT_PLATFORM = "linux/amd64"

AncestryFn = Callable[[str, str], bool]  # (base, head) -> head descends from base


@dataclass(frozen=True)
class IntakeExpectation:
    """What a bundle must prove before it may become a `ScanRun`."""

    source_repo: str = FORK_REPO
    source_branch: str = REMEDIATION_BRANCH
    baseline_sha: str = BASELINE_SHA
    platform: str = DEFAULT_PLATFORM
    required_jobs: tuple[str, ...] = DEFAULT_EXPECTED_JOBS
    required_runtime_jobs: tuple[str, ...] = REQUIRED_RUNTIME_JOBS
    scanners: frozenset[Scanner] = frozenset({Scanner.trivy, Scanner.grype})


@dataclass
class IntakeOutcome:
    external_run_id: str
    status: IntakeStatus
    reasons: list[str] = field(default_factory=list)
    scan_run_id: int | None = None
    created: bool = False
    seen_before: bool = False
    ingest: IngestResult | None = None


def external_run_id(repo: str, run: WorkflowRunInfo) -> str:
    return f"gha:{repo}:{run.id}:{run.run_attempt}"


def find_evidence_artifact(artifacts: list[ArtifactInfo]) -> ArtifactInfo | None:
    matches = [
        a for a in artifacts if a.name.startswith(EVIDENCE_ARTIFACT_PREFIX) and not a.expired
    ]
    return matches[0] if len(matches) == 1 else None


def validate_bundle(
    root: Path,
    run: WorkflowRunInfo,
    expect: IntakeExpectation,
    *,
    is_ancestor: AncestryFn,
) -> tuple[BaselineManifest | None, list[str]]:
    """Load and cross-check one downloaded bundle. Returns the parsed manifest (None when it could
    not even be parsed) and every reason it must be rejected; an empty list means acceptable."""
    reasons: list[str] = []
    if not (root / "manifest.json").is_file():
        return None, ["bundle has no manifest.json (scan-manifest job did not complete)"]
    try:
        manifest = load_baseline(root)
    except (EvidenceError, KeyError, ValueError, OSError) as exc:
        return None, [f"evidence failed verification: {exc}"]

    run_meta = manifest.run
    schema = json.loads((root / "manifest.json").read_text()).get("schema")
    if schema != SCAN_MANIFEST_SCHEMA:
        reasons.append(f"manifest schema {schema!r} is not a workflow scan manifest")

    if manifest.source_repo not in REPO_ALLOWLIST:
        reasons.append(f"source_repo {manifest.source_repo!r} is outside the allowlist")
    elif manifest.source_repo != expect.source_repo:
        reasons.append(f"source_repo {manifest.source_repo!r} != {expect.source_repo!r}")
    if manifest.source_branch != expect.source_branch:
        reasons.append(f"source_branch {manifest.source_branch!r} != {expect.source_branch!r}")
    # The manifest is written by the workflow under scan, so a feature branch could claim to be
    # `main`; the run's own branch and event come from GitHub and must agree.
    if run.head_branch != expect.source_branch:
        reasons.append(
            f"workflow run is for branch {run.head_branch!r}, expected {expect.source_branch!r}"
        )
    if manifest.trigger != run.event:
        reasons.append(f"manifest trigger {manifest.trigger!r} != workflow event {run.event!r}")

    recorded_head = str(run_meta.get("head_sha") or manifest.source_sha)
    if run.head_sha not in (manifest.source_sha, recorded_head):
        reasons.append(
            f"evidence is for {manifest.source_sha[:12]} (head {recorded_head[:12]}), "
            f"workflow run was for {run.head_sha[:12]}"
        )
    if str(run_meta.get("run_id")) != str(run.id):
        reasons.append(f"manifest run_id {run_meta.get('run_id')!r} != workflow run {run.id}")
    if int(run_meta.get("run_attempt") or 0) != run.run_attempt:
        reasons.append(
            f"manifest run_attempt {run_meta.get('run_attempt')!r} != attempt {run.run_attempt}"
        )
    try:
        Trigger(manifest.trigger)
    except ValueError:
        reasons.append(f"unknown trigger {manifest.trigger!r}")

    if manifest.platform != expect.platform:
        reasons.append(f"platform {manifest.platform!r} != {expect.platform!r}")

    if not is_ancestor(expect.baseline_sha, manifest.source_sha):
        reasons.append(
            f"source_sha {manifest.source_sha[:12]} does not descend from baseline "
            f"{expect.baseline_sha[:12]}"
        )

    for name in expect.required_jobs:
        job = manifest.jobs.get(name)
        if job is None:
            reasons.append(f"required scan job {name!r} missing from bundle")
            continue
        missing = sorted(s.value for s in expect.scanners - job.scanners_present)
        if missing:
            reasons.append(f"scan job {name!r} lacks scanner results: {', '.join(missing)}")
        if job.platform != expect.platform:
            reasons.append(f"scan job {name!r} platform {job.platform!r} != {expect.platform!r}")

    job_results = dict(run_meta.get("job_results") or {})
    for name in expect.required_runtime_jobs:
        claimed = job_results.get(name)
        if claimed is None:
            reasons.append(f"runtime job {name!r} has no recorded result")
        record = manifest.runtime.get(name)
        if record is None:
            rel = RUNTIME_RECORDS[name][0] if name in RUNTIME_RECORDS else "<unknown>"
            reasons.append(f"runtime job {name!r} has no attached record ({rel})")
            continue
        reasons.extend(runtime_record_problems(manifest, record, claimed))

    return manifest, reasons


def runtime_record_problems(
    manifest: BaselineManifest, record: RuntimeRecord, claimed: str | None
) -> list[str]:
    """Why an attached runtime verdict does not back the run: it started an image other than the
    manifest's digest for that target, or the workflow claims `success` for a job whose own record
    says otherwise. A record that passed under a job GitHub marks failed is not a problem here: the
    job result stays as recorded and the run is persisted incomplete."""
    problems: list[str] = []
    target = RUNTIME_RECORDS[record.job][1].value
    expected = str((manifest.images.get(target) or {}).get("image_id") or "")
    if record.digest != expected:
        problems.append(
            f"runtime job {record.job!r} ran {record.image_ref}, manifest {target} image is "
            f"{expected or 'absent'}"
        )
    if claimed == "success" and not record.passed:
        problems.append(
            f"runtime job {record.job!r} result claims success but {record.path} reports "
            f"failed_step={record.failed_step!r}"
        )
    return problems


def proven_job_results(manifest: BaselineManifest) -> dict[str, str]:
    """`run.job_results` with `success` kept only where the attached verdict proves it; anything
    claimed but unproven is recorded as `unproven`, which persists the run incomplete."""
    results = {str(k): str(v) for k, v in (manifest.run.get("job_results") or {}).items()}
    for name, result in list(results.items()):
        if result != "success" or name not in RUNTIME_RECORDS:
            continue
        record = manifest.runtime.get(name)
        if record is None or runtime_record_problems(manifest, record, result):
            results[name] = "unproven"
    return results


def run_meta_for(
    manifest: BaselineManifest,
    run: WorkflowRunInfo,
    *,
    repo: str,
) -> RunMeta:
    job_results = proven_job_results(manifest)
    job_results["workflow"] = run.conclusion or run.status or "unknown"
    return RunMeta(
        external_run_id=external_run_id(repo, run),
        trigger=Trigger(manifest.trigger),
        source_repo=manifest.source_repo,
        source_branch=manifest.source_branch,
        source_sha=manifest.source_sha,
        platform=manifest.platform,
        lean_digest=str(manifest.images["lean"]["image_id"]) if "lean" in manifest.images else None,
        ci_digest=str(manifest.images["ci"]["image_id"]) if "ci" in manifest.images else None,
        ci_layer_delta=manifest.ci_layer_delta or None,
        started_at=manifest.built_at,
        finished_at=manifest.captured_at,
        run_attempt=run.run_attempt,
        scan_gate_mode=_gate_mode(manifest),
        job_results=job_results,
        workflow={**manifest.run, "url": manifest.run.get("url") or run.url},
    )


def _gate_mode(manifest: BaselineManifest) -> GateMode:
    raw = manifest.run.get("scan_gate_mode")
    return GateMode(str(raw)) if raw else GateMode.report


class ScanIntakeService:
    """Discovers, downloads, verifies and persists security-scan evidence bundles."""

    def __init__(
        self,
        engine: Engine,
        gh: GitHubClient,
        *,
        repo_root: Path,
        evidence_dir: Path,
        expect: IntakeExpectation | None = None,
        workflow_file: str = SECURITY_SCAN_WORKFLOW,
    ) -> None:
        self.engine = engine
        self.gh = gh
        self.repo_root = repo_root
        self.evidence_dir = evidence_dir
        self.expect = expect or IntakeExpectation()
        self.workflow_file = workflow_file

    # ------------------------------------------------------------------ discovery

    def completed_runs(self, *, branch: str | None = None) -> Iterator[WorkflowRunInfo]:
        """Newest first, paginated lazily by the client; consume only as far as needed."""
        runs = self.gh.list_workflow_runs(
            self.expect.source_repo,
            self.workflow_file,
            branch=branch or self.expect.source_branch,
            status="completed",
        )
        return (r for r in runs if r.status == "completed")

    def find_run(self, run_id: int) -> WorkflowRunInfo | None:
        """Walk the workflow's run listing (every branch and event) until `run_id` shows up."""
        for run in self.gh.list_workflow_runs(self.expect.source_repo, self.workflow_file):
            if run.id == run_id:
                return run
        return None

    def unseen_runs(self, *, limit: int) -> list[WorkflowRunInfo]:
        """The newest `limit` completed run attempts with no `ScanIntake` row yet, returned oldest
        first so a batch is ingested in scan chronology. Seen attempts are skipped before counting,
        so a backlog older than one page is still reached."""
        repo = self.expect.source_repo
        out: list[WorkflowRunInfo] = []
        with Session(self.engine) as db:
            for run in self.completed_runs():
                if len(out) >= limit:
                    break
                if self.seen(db, external_run_id(repo, run)) is None:
                    out.append(run)
        out.reverse()
        return out

    def seen(self, db: Session, ext_id: str) -> ScanIntake | None:
        return db.exec(select(ScanIntake).where(ScanIntake.external_run_id == ext_id)).first()

    # ------------------------------------------------------------------ intake

    def poll(self, *, limit: int = 10) -> list[IntakeOutcome]:
        """Ingest up to `limit` of the newest completed runs of the expected branch not seen
        before, oldest of those first; runs older still are picked up by later polls until none
        remain. Ingestion order is not load-bearing: a finding's current description and the
        "latest run" always follow scan `finished_at`, so a backlog entry brought in after a newer
        scan cannot present itself as current (see `ingest.persist._upsert_finding`)."""
        return [self.ingest_workflow_run(run) for run in self.unseen_runs(limit=limit)]

    def ingest_workflow_run(self, run: WorkflowRunInfo) -> IntakeOutcome:
        repo = self.expect.source_repo
        ext_id = external_run_id(repo, run)
        with session_scope(self.engine) as db:
            prior = self.seen(db, ext_id)
            if prior is not None:
                return IntakeOutcome(
                    external_run_id=ext_id,
                    status=prior.status,
                    reasons=list(prior.reasons),
                    scan_run_id=prior.scan_run_id,
                    created=False,
                    seen_before=True,
                )

        intake = ScanIntake(
            external_run_id=ext_id,
            source_repo=repo,
            workflow_run_id=run.id,
            run_attempt=run.run_attempt,
            head_branch=run.head_branch,
            head_sha=run.head_sha,
            conclusion=run.conclusion,
            url=run.url,
            status=IntakeStatus.rejected,
        )
        outcome = IntakeOutcome(external_run_id=ext_id, status=IntakeStatus.rejected)

        if run.status != "completed":
            outcome.reasons.append(f"workflow run is {run.status!r}, not completed")
            return self._record(intake, outcome)

        artifacts = self.gh.list_run_artifacts(repo, run.id)
        artifact = find_evidence_artifact(artifacts)
        if artifact is None:
            names = sorted(a.name for a in artifacts)
            outcome.reasons.append(
                f"expected exactly one unexpired {EVIDENCE_ARTIFACT_PREFIX}* artifact, "
                f"run has {names or 'none'}"
            )
            return self._record(intake, outcome)
        intake.artifact_id = artifact.id
        intake.artifact_name = artifact.name
        intake.artifact_digest = artifact.digest

        dest = self.evidence_dir / "runs" / str(run.id) / str(run.run_attempt)
        try:
            root = self.gh.download_artifact(repo, artifact.id, dest)
        except ArtifactError as exc:
            outcome.reasons.append(str(exc))
            return self._record(intake, outcome)
        intake.bundle_path = str(root)
        zip_path = root.with_suffix(".zip")
        if zip_path.is_file():
            intake.bundle_sha256 = hashlib.sha256(zip_path.read_bytes()).hexdigest()
            if artifact.digest and artifact.digest.split(":", 1)[-1] != intake.bundle_sha256:
                outcome.reasons.append(
                    f"downloaded zip sha256 {intake.bundle_sha256[:12]} != GitHub digest "
                    f"{artifact.digest}"
                )
                return self._record(intake, outcome)

        manifest, reasons = validate_bundle(root, run, self.expect, is_ancestor=self._is_ancestor)
        if reasons or manifest is None:
            outcome.reasons.extend(reasons)
            return self._record(intake, outcome)

        bounds = self._upper_bounds(manifest.source_sha)
        if bounds is None:
            outcome.reasons.append(
                f"pyproject.toml at {manifest.source_sha[:12]} unavailable; cannot classify "
                "upper-bound-blocked dependencies"
            )
            return self._record(intake, outcome)

        meta = run_meta_for(manifest, run, repo=repo)
        # The run's rows land in one write transaction that holds the lock from its first read, so
        # an operator launch in the service either sees this run pending or has already reserved
        # its work item (and bound its issue) before the run exists.
        with write_scope(self.engine) as db:
            result = ingest_run(db, meta, manifest.jobs, upper_bounds=bounds)
        outcome.status = IntakeStatus.ingested
        outcome.scan_run_id = result.scan_run_id
        outcome.created = result.created
        outcome.ingest = result
        if not result.created:
            outcome.reasons.append("scan run already present; no new rows written")
        conclusion = meta.job_results.get("workflow")
        if conclusion != "success":
            outcome.reasons.append(f"workflow conclusion {conclusion!r}; run persisted incomplete")
        return self._record(intake, outcome)

    def _record(self, intake: ScanIntake, outcome: IntakeOutcome) -> IntakeOutcome:
        intake.status = outcome.status
        intake.reasons = list(outcome.reasons)
        intake.scan_run_id = outcome.scan_run_id
        with session_scope(self.engine) as db:
            db.add(intake)
        if outcome.status is IntakeStatus.rejected:
            log.warning("scan intake %s rejected: %s", outcome.external_run_id, outcome.reasons)
        else:
            log.info("scan intake %s -> scan run %s", outcome.external_run_id, outcome.scan_run_id)
        return outcome

    # ------------------------------------------------------------------ helpers

    def _is_ancestor(self, base: str, head: str) -> bool:
        if base == head:
            return True
        try:
            return self.gh.compare(self.expect.source_repo, base, head).status in (
                "ahead",
                "identical",
            )
        except Exception as exc:
            log.warning("compare %s...%s failed: %s", base[:12], head[:12], exc)
            return False

    def _upper_bounds(self, source_sha: str) -> dict[str, SpecifierSet] | None:
        try:
            f = self.gh.get_file(self.expect.source_repo, "pyproject.toml", source_sha)
        except Exception as exc:
            log.warning("get_file pyproject.toml@%s failed: %s", source_sha[:12], exc)
            f = None
        if f is not None:
            return parse_upper_bounds(f.content)
        try:
            return parse_upper_bounds(load_source_pyproject(self.repo_root, source_sha))
        except (OSError, EvidenceError):
            return None
