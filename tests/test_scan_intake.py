"""Scan intake: completed fork `security-scan` runs become ScanRuns only when their evidence bundle
verifies and matches the run GitHub says it came from; everything else is recorded as rejected."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import Engine
from sqlmodel import Session, col, select

from hardening_loop.ci import WorkflowRun, write_scan_manifest
from hardening_loop.cli import main
from hardening_loop.config import BASELINE_SHA, FORK_REPO, Settings
from hardening_loop.db import open_database
from hardening_loop.devin.fake import FakeDevin
from hardening_loop.domain.enums import GateMode, ImageTarget, IntakeStatus, ScanRunStatus
from hardening_loop.github.fake import FakeGitHub
from hardening_loop.ingest.evidence import load_source_pyproject
from hardening_loop.ingest.intake import (
    IntakeExpectation,
    IntakeOutcome,
    ScanIntakeService,
    external_run_id,
    find_evidence_artifact,
)
from hardening_loop.models.tables import Finding, ScanIntake, ScanJob, ScanRun
from hardening_loop.orchestrator.engine import Orchestrator
from tests.test_ci_helpers import _images, _stage_jobs

ROOT = Path(__file__).resolve().parents[1]
RUN_ID = 34200000001
SHA_MAIN2 = "d" * 40  # a commit on main after the baseline


def _bundle(
    out: Path,
    *,
    run_id: int = RUN_ID,
    run_attempt: int = 1,
    source_sha: str = BASELINE_SHA,
    source_branch: str = "main",
    source_repo: str = FORK_REPO,
    event: str = "schedule",
    head_sha: str | None = None,
    job_results: dict[str, str] | None = None,
    drop: str | None = None,
) -> Path:
    """Stage a complete evidence tree the way the workflow's scan-manifest job leaves it."""
    out.mkdir(parents=True, exist_ok=True)
    _stage_jobs(out, drop=drop)
    gate = out / "gates" / "lean-policy.json"
    gate.parent.mkdir()
    policy = str(out / "lean" / "policy")
    assert main(["gate", "--job", policy, "--mode", "report", "--out", str(gate)]) == 0
    expected: tuple[str, ...] = ("lean-raw", "lean-policy", "ci-raw")
    if drop is not None:
        expected = tuple(j for j in expected if j != drop.replace("/", "-"))
    write_scan_manifest(
        out,
        source_repo=source_repo,
        source_branch=source_branch,
        source_sha=source_sha,
        platform="linux/amd64",
        images=_images(),
        run=WorkflowRun(
            run_id=run_id,
            run_attempt=run_attempt,
            event=event,
            workflow_sha=source_sha,
            ref=f"refs/heads/{source_branch}",
            gate_mode=GateMode.report,
            head_sha=head_sha,
            job_results=job_results
            if job_results is not None
            else {"lean-smoke": "success", "app-runs": "success"},
        ),
        expected_jobs=expected,
        gate_files={"lean-policy": gate},
        now=datetime(2026, 9, 8, 3, tzinfo=UTC),
    )
    return out


@pytest.fixture
def gh() -> FakeGitHub:
    fake = FakeGitHub(main_head=BASELINE_SHA)
    fake.add_commit(SHA_MAIN2, BASELINE_SHA)
    pyproject = load_source_pyproject(ROOT, BASELINE_SHA)
    fake.put_file("pyproject.toml", BASELINE_SHA, pyproject)
    fake.put_file("pyproject.toml", SHA_MAIN2, pyproject)
    return fake


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return open_database(tmp_path / "controller.sqlite3")


def _service(engine: Engine, gh: FakeGitHub, tmp_path: Path, **expect: object) -> ScanIntakeService:
    return ScanIntakeService(
        engine,
        gh,
        repo_root=ROOT,
        evidence_dir=tmp_path / "evidence",
        expect=IntakeExpectation(**expect),  # type: ignore[arg-type]
    )


def _publish(gh: FakeGitHub, tree: Path, *, run_id: int = RUN_ID, **run: object) -> None:
    info = gh.add_workflow_run(run_id=run_id, **run)  # type: ignore[arg-type]
    gh.add_artifact(info.id, f"scan-evidence-{BASELINE_SHA}", tree)


def _intakes(engine: Engine) -> list[ScanIntake]:
    with Session(engine) as db:
        return list(db.exec(select(ScanIntake).order_by(col(ScanIntake.id))).all())


# ------------------------------------------------------------------------------------ happy path


def test_complete_matching_bundle_is_ingested_once(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    _publish(gh, _bundle(tmp_path / "tree"), head_sha=BASELINE_SHA)
    svc = _service(engine, gh, tmp_path)

    first = svc.poll()
    assert [o.status for o in first] == [IntakeStatus.ingested]
    assert first[0].created and first[0].scan_run_id is not None
    assert first[0].reasons == []

    with Session(engine) as db:
        run = db.get(ScanRun, first[0].scan_run_id)
        assert run is not None
        assert run.external_run_id == f"gha:{FORK_REPO}:{RUN_ID}:1"
        assert run.status is ScanRunStatus.complete
        assert run.source_sha == BASELINE_SHA and run.source_branch == "main"
        assert run.workflow is not None and run.workflow["run_id"] == RUN_ID
        jobs = {j.name: j for j in db.exec(select(ScanJob).where(ScanJob.scan_run_id == run.id))}
        assert {"trivy-raw", "grype-raw", "trivy-policy", "grype-policy", "config-raw"} <= set(jobs)
        assert "trivy-raw@ci" in jobs, "secondary ci evidence is kept, separately named"
        assert jobs["lean-smoke"].success and jobs["app-runs"].success and jobs["workflow"].success
        assert jobs["trivy-raw"].image_target is ImageTarget.lean
        assert db.exec(select(Finding)).first() is not None, "raw findings opened from lean-raw"

    # Second poll: same run id + attempt, nothing new and no second ScanRun.
    second = svc.poll()
    assert second == []
    again = svc.ingest_workflow_run(svc.find_run(RUN_ID) or pytest.fail("run vanished"))
    assert again.seen_before and again.scan_run_id == first[0].scan_run_id
    with Session(engine) as db:
        assert len(db.exec(select(ScanRun)).all()) == 1
    intakes = _intakes(engine)
    assert len(intakes) == 1 and intakes[0].status is IntakeStatus.ingested
    assert intakes[0].bundle_sha256 and intakes[0].artifact_digest is not None
    assert intakes[0].artifact_digest == f"sha256:{intakes[0].bundle_sha256}"
    assert Path(intakes[0].bundle_path or "").joinpath("manifest.json").is_file()


def test_bundle_for_a_later_main_commit_is_accepted_via_ancestry(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    _publish(gh, _bundle(tmp_path / "tree", source_sha=SHA_MAIN2), head_sha=SHA_MAIN2)
    out = _service(engine, gh, tmp_path).poll()
    assert [o.status for o in out] == [IntakeStatus.ingested]
    assert any(c[0] == "compare" for c in gh.calls)


def test_failed_runtime_job_is_ingested_but_incomplete(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    tree = _bundle(tmp_path / "tree", job_results={"lean-smoke": "success", "app-runs": "failure"})
    _publish(gh, tree, head_sha=BASELINE_SHA, conclusion="failure")
    out = _service(engine, gh, tmp_path).poll()
    assert out[0].status is IntakeStatus.ingested
    assert any("persisted incomplete" in r for r in out[0].reasons)
    with Session(engine) as db:
        run = db.exec(select(ScanRun)).one()
        assert run.status is ScanRunStatus.incomplete
        names = {j.name: j.success for j in db.exec(select(ScanJob))}
        assert names["app-runs"] is False and names["workflow"] is False


# ------------------------------------------------------------------------------------ rejections


def _assert_rejected(engine: Engine, outcomes: list[IntakeOutcome], needle: str) -> None:
    assert len(outcomes) == 1
    o = outcomes[0]
    assert o.status is IntakeStatus.rejected
    assert any(needle in r for r in o.reasons), o.reasons
    with Session(engine) as db:
        assert db.exec(select(ScanRun)).first() is None, "rejected bundles never become runs"
    intakes = _intakes(engine)
    assert len(intakes) == 1 and intakes[0].status is IntakeStatus.rejected
    assert any(needle in r for r in intakes[0].reasons)


def test_tampered_file_is_rejected(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    tree = _bundle(tmp_path / "tree")
    vuln = tree / "lean" / "raw" / "trivy-vuln.json"
    doc = json.loads(vuln.read_text())
    doc["Results"] = []
    vuln.write_text(json.dumps(doc))
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "failed verification")


def test_missing_manifest_is_rejected(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    tree = _bundle(tmp_path / "tree")
    (tree / "manifest.json").unlink()
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "no manifest.json")


def test_missing_required_job_is_rejected(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    tree = _bundle(tmp_path / "tree", drop="ci/raw")
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "'ci-raw' missing")


def test_missing_runtime_result_is_rejected(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    tree = _bundle(tmp_path / "tree", job_results={"lean-smoke": "success"})
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "'app-runs' has no recorded")


def test_bundle_from_other_branch_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    tree = _bundle(tmp_path / "tree", source_branch="devin/1-fix", event="push")
    _publish(gh, tree, head_sha=BASELINE_SHA, head_branch="devin/1-fix")
    svc = _service(engine, gh, tmp_path)
    assert svc.poll() == [], "poller only looks at the remediation branch"
    run = svc.find_run(RUN_ID)
    assert run is not None
    _assert_rejected(engine, [svc.ingest_workflow_run(run)], "source_branch 'devin/1-fix'")


def test_bundle_from_other_repo_is_rejected(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    tree = _bundle(tmp_path / "tree", source_repo="apache/superset")
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "outside the allowlist")


def test_bundle_for_other_commit_than_the_run_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    tree = _bundle(tmp_path / "tree", source_sha=BASELINE_SHA)
    _publish(gh, tree, head_sha=SHA_MAIN2)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "workflow run was for")


def test_bundle_claiming_another_run_id_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    tree = _bundle(tmp_path / "tree", run_id=RUN_ID + 1)
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "manifest run_id")


def test_non_descendant_of_baseline_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    stray = "e" * 40
    gh.parents[stray] = None  # a root commit unrelated to 6.1.0
    gh.put_file("pyproject.toml", stray, load_source_pyproject(ROOT, BASELINE_SHA))
    tree = _bundle(tmp_path / "tree", source_sha=stray)
    _publish(gh, tree, head_sha=stray)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "does not descend")


def test_wrong_platform_is_rejected(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    tree = _bundle(tmp_path / "tree")
    _publish(gh, tree, head_sha=BASELINE_SHA)
    out = _service(engine, gh, tmp_path, platform="linux/arm64").poll()
    _assert_rejected(engine, out, "platform 'linux/amd64' != 'linux/arm64'")


def test_run_without_evidence_artifact_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    gh.add_workflow_run(run_id=RUN_ID, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "expected exactly one")


def test_two_evidence_artifacts_are_ambiguous(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    tree = _bundle(tmp_path / "tree")
    info = gh.add_workflow_run(run_id=RUN_ID, head_sha=BASELINE_SHA)
    gh.add_artifact(info.id, f"scan-evidence-{BASELINE_SHA}", tree)
    gh.add_artifact(info.id, "scan-evidence-other", tree)
    assert find_evidence_artifact(gh.list_run_artifacts(FORK_REPO, RUN_ID)) is None
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "expected exactly one")


def test_corrupt_zip_is_rejected(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    info = gh.add_workflow_run(run_id=RUN_ID, head_sha=BASELINE_SHA)
    art = gh.add_artifact(info.id, f"scan-evidence-{BASELINE_SHA}", _bundle(tmp_path / "tree"))
    stored = gh.workflow_runs[RUN_ID].artifacts
    stored[0] = (art, b"not a zip")
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "not a zip archive")


def test_missing_pyproject_fails_closed(engine: Engine, gh: FakeGitHub, tmp_path: Path) -> None:
    other = "f" * 40
    gh.add_commit(other, BASELINE_SHA)
    tree = _bundle(tmp_path / "tree", source_sha=other)
    _publish(gh, tree, head_sha=other)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "pyproject.toml")


def test_second_attempt_of_same_run_is_a_distinct_intake(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    _publish(gh, _bundle(tmp_path / "t1"), head_sha=BASELINE_SHA)
    svc = _service(engine, gh, tmp_path)
    assert svc.poll()[0].status is IntakeStatus.ingested
    # Re-run attempt 2 uploads a fresh bundle under the same run id.
    tree2 = _bundle(tmp_path / "t2", run_attempt=2)
    shutil.rmtree(tmp_path / "evidence", ignore_errors=True)
    info = gh.add_workflow_run(run_id=RUN_ID, head_sha=BASELINE_SHA, run_attempt=2)
    gh.add_artifact(info.id, f"scan-evidence-{BASELINE_SHA}", tree2)
    out = svc.poll()
    assert [o.status for o in out] == [IntakeStatus.ingested] and out[0].created
    ids = {i.external_run_id for i in _intakes(engine)}
    assert ids == {external_run_id(FORK_REPO, info), f"gha:{FORK_REPO}:{RUN_ID}:1"}


# ------------------------------------------------------------------------ orchestrator + CLI


def test_tick_polls_scans_and_reports_counts(gh: FakeGitHub, tmp_path: Path) -> None:
    settings = Settings(
        data_dir=tmp_path / "data", database_file="c.sqlite3", repo_root=ROOT, operator_mode=True
    )
    engine = open_database(settings.database_path)
    _publish(gh, _bundle(tmp_path / "good"), head_sha=BASELINE_SHA)
    bad = _bundle(tmp_path / "bad", run_id=RUN_ID + 1, source_repo="apache/superset")
    _publish(gh, bad, run_id=RUN_ID + 1, head_sha=BASELINE_SHA)

    orch = Orchestrator(engine, gh, FakeDevin(), settings)
    first = orch.tick(auto_dispatch=False)
    assert (first.scans_ingested, first.scans_rejected) == (1, 1)
    assert first.work_items_created > 0, "the ingested baseline run seeds work items"
    second = orch.tick(auto_dispatch=False)
    assert (second.scans_ingested, second.scans_rejected) == (0, 0)
    assert second.work_items_created == 0
    assert len(_intakes(engine)) == 2


def test_ingest_cli_refuses_without_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["ingest", "--db", str(tmp_path / "c.sqlite3")]) == 2
    assert "HL_GITHUB_TOKEN" in capsys.readouterr().err
