"""Scan intake: completed fork `security-scan` runs become ScanRuns only when their evidence bundle
verifies and matches the run GitHub says it came from; everything else is recorded as rejected."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from sqlalchemy import Engine
from sqlmodel import Session, col, select

from hardening_loop.ci import WorkflowRun, write_scan_manifest
from hardening_loop.cli import main
from hardening_loop.config import BASELINE_SHA, FORK_REPO, Settings
from hardening_loop.dashboard.app import header_context
from hardening_loop.db import open_database
from hardening_loop.devin.fake import FakeDevin
from hardening_loop.domain.enums import (
    GateMode,
    ImageTarget,
    IntakeStatus,
    ScanRunStatus,
    WorkItemState,
)
from hardening_loop.github.fake import FakeGitHub
from hardening_loop.ingest.evidence import RUNTIME_RECORDS, load_source_pyproject, sha256_file
from hardening_loop.ingest.intake import (
    IntakeExpectation,
    IntakeOutcome,
    ScanIntakeService,
    external_run_id,
    find_evidence_artifact,
)
from hardening_loop.models.tables import Finding, ScanIntake, ScanJob, ScanRun
from hardening_loop.orchestrator.engine import Orchestrator
from hardening_loop.replay.bundle import stage_runtime_records
from hardening_loop.replay.scenarios import DEP_FILES
from hardening_loop.replay.world import World
from hardening_loop.report.run_report import select_runs
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
    captured_at: datetime = datetime(2026, 9, 8, 3, tzinfo=UTC),
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
    results = (
        job_results if job_results is not None else {"lean-smoke": "success", "app-runs": "success"}
    )
    stage_runtime_records(out, _images(), results)
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
            job_results=results,
        ),
        expected_jobs=expected,
        gate_files={"lean-policy": gate},
        attach_dirs=("runtime",) if results else (),
        now=captured_at,
    )
    return out


def _resign(tree: Path) -> None:
    """Re-checksum a tree after editing files in place, as a producer that does not cross-check
    its own runtime records would. Files removed from disk drop out of the inventory."""
    manifest = json.loads((tree / "manifest.json").read_text())
    files = {rel: sha256_file(tree / rel) for rel in manifest["files"] if (tree / rel).is_file()}
    manifest["files"] = files
    manifest["attachments"] = {
        d: [rel for rel in listed if rel in files] for d, listed in manifest["attachments"].items()
    }
    (tree / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    files["manifest.json"] = sha256_file(tree / "manifest.json")
    (tree / "SHA256SUMS").write_text("".join(f"{d}  {rel}\n" for rel, d in files.items()))


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
    out = _service(engine, gh, tmp_path).poll()
    _assert_rejected(engine, out, "'app-runs' has no recorded")
    assert any("'app-runs' has no attached record" in r for r in out[0].reasons)


def test_runtime_success_without_attached_record_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    """`job_results` says both runtime jobs passed but app-runs left no verdict file: the string is
    a claim, the attached record is the proof, and without it the run is not ingested."""
    tree = _bundle(tmp_path / "tree")
    (tree / RUNTIME_RECORDS["app-runs"][0]).unlink()
    _resign(tree)
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(
        engine, _service(engine, gh, tmp_path).poll(), "'app-runs' has no attached record"
    )


def test_malformed_runtime_record_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    tree = _bundle(tmp_path / "tree")
    (tree / RUNTIME_RECORDS["lean-smoke"][0]).write_text('{"ok": true}\n')
    _resign(tree)
    _publish(gh, tree, head_sha=BASELINE_SHA)
    out = _service(engine, gh, tmp_path).poll()
    _assert_rejected(engine, out, "failed verification")
    assert any(
        "lean-smoke.json: image_ref None is not a digest reference" in r for r in out[0].reasons
    )


def _rewrite_manifest(tree: Path, edit: dict[str, object]) -> None:
    """Edit top-level manifest keys and re-sign, as a producer writing a bad value would."""
    manifest = json.loads((tree / "manifest.json").read_text())
    manifest.update(edit)
    (tree / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    _resign(tree)


@pytest.mark.parametrize(
    ("run_edit", "needle"),
    [
        ({"job_results": "success"}, "run.job_results is str"),
        ({"job_results": ["lean-smoke", "app-runs"]}, "run.job_results is list"),
        ({"job_results": {"lean-smoke": True, "app-runs": "success"}}, "non-string results"),
        ({"run_attempt": "first"}, "run.run_attempt 'first' is not a whole number"),
        ({"run_attempt": 1.5}, "run.run_attempt 1.5 is not a whole number"),
        ({"scan_gate_mode": "audit"}, "unknown scan_gate_mode 'audit'"),
        ({"scan_gate_mode": {"mode": "report"}}, "run.scan_gate_mode is dict"),
    ],
)
def test_malformed_run_metadata_is_rejected_not_raised(
    engine: Engine, gh: FakeGitHub, tmp_path: Path, run_edit: dict[str, object], needle: str
) -> None:
    """Every value under the manifest's `run` block is producer-written and converted at intake
    (`int(...)`, `dict(...)`, `GateMode(...)`); a wrong shape must become a recorded rejection with
    the reason, never an exception that leaves the run without an intake row."""
    tree = _bundle(tmp_path / "tree")
    manifest = json.loads((tree / "manifest.json").read_text())
    _rewrite_manifest(tree, {"run": {**manifest["run"], **run_edit}})
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), needle)


def test_manifest_of_the_wrong_shape_is_rejected_not_raised(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    """A manifest whose nested objects are not objects (`images` as a list here) fails inside the
    loader with a TypeError rather than a verification error; it is still a rejection."""
    tree = _bundle(tmp_path / "tree")
    _rewrite_manifest(tree, {"images": ["lean", "ci"]})
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(engine, _service(engine, gh, tmp_path).poll(), "failed verification")


def test_a_malformed_oldest_run_does_not_block_later_runs(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    """The poll works oldest-unseen first; a run that is rejected gets its intake row and is never
    retried, so the runs after it are ingested on the same poll and it stays out of later polls."""
    bad = _bundle(tmp_path / "bad", run_id=RUN_ID)
    manifest = json.loads((bad / "manifest.json").read_text())
    _rewrite_manifest(bad, {"run": {**manifest["run"], "job_results": "success"}})
    _publish(gh, bad, run_id=RUN_ID, head_sha=BASELINE_SHA)
    good = _bundle(
        tmp_path / "good",
        run_id=RUN_ID + 1,
        source_sha=SHA_MAIN2,
        captured_at=datetime(2026, 9, 8, 4, tzinfo=UTC),
    )
    _publish(gh, good, run_id=RUN_ID + 1, head_sha=SHA_MAIN2)

    svc = _service(engine, gh, tmp_path)
    out = svc.poll()
    assert [(o.external_run_id.rsplit(":", 2)[1], o.status) for o in out] == [
        (str(RUN_ID), IntakeStatus.rejected),
        (str(RUN_ID + 1), IntakeStatus.ingested),
    ]
    assert svc.poll() == [], "neither run is looked at again"
    intakes = _intakes(engine)
    assert [i.status for i in intakes] == [IntakeStatus.rejected, IntakeStatus.ingested]
    with Session(engine) as db:
        assert len(db.exec(select(ScanRun)).all()) == 1


def test_runtime_record_for_other_image_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    """A well-formed passing verdict for some other digest than the one this run built and
    scanned proves nothing about this run's image."""
    tree = _bundle(tmp_path / "tree")
    other = "ghcr.io/hunter-1298/superset@sha256:" + "f" * 64
    stage_runtime_records(
        tree,
        _images(),
        {"lean-smoke": "success", "app-runs": "success"},
        image_refs={"app-runs": other},
    )
    _resign(tree)
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(
        engine,
        _service(engine, gh, tmp_path).poll(),
        f"'app-runs' ran {other}, manifest ci image is sha256:{'b' * 64}",
    )


def test_job_result_success_contradicted_by_record_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    tree = _bundle(tmp_path / "tree")
    stage_runtime_records(tree, _images(), {"lean-smoke": "failure", "app-runs": "success"})
    _resign(tree)
    _publish(gh, tree, head_sha=BASELINE_SHA)
    _assert_rejected(
        engine,
        _service(engine, gh, tmp_path).poll(),
        "'lean-smoke' result claims success but runtime/lean-smoke/lean-smoke.json reports "
        "failed_step='login'",
    )


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


def test_feature_branch_run_claiming_main_is_rejected(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    """The manifest is produced by the workflow under test, so a PR branch can write `main` /
    `schedule` into it; GitHub's own record of the run says otherwise and wins."""
    tree = _bundle(tmp_path / "tree", source_branch="main", event="schedule")
    _publish(gh, tree, head_sha=BASELINE_SHA, head_branch="devin/1-fix", event="pull_request")
    svc = _service(engine, gh, tmp_path)
    assert svc.poll() == [], "poller only looks at the remediation branch"
    run = svc.find_run(RUN_ID)
    assert run is not None
    out = svc.ingest_workflow_run(run)
    _assert_rejected(engine, [out], "workflow run is for branch 'devin/1-fix'")
    assert any(
        "manifest trigger 'schedule' != workflow event 'pull_request'" in r for r in out.reasons
    )
    with Session(engine) as db:
        assert db.exec(select(ScanRun)).first() is None


def test_pull_request_run_on_main_with_synthetic_merge_head_is_accepted(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    """`pull_request` runs check out a synthetic merge commit: `source_sha` is that merge and
    `head_sha` the PR head GitHub reports. Both identities recorded truthfully still verify."""
    merge = "a" * 40
    gh.add_commit(merge, BASELINE_SHA)
    gh.put_file("pyproject.toml", merge, load_source_pyproject(ROOT, BASELINE_SHA))
    tree = _bundle(tmp_path / "tree", source_sha=merge, event="pull_request", head_sha=SHA_MAIN2)
    _publish(gh, tree, head_sha=SHA_MAIN2, head_branch="main", event="pull_request")
    out = _service(engine, gh, tmp_path).poll()
    assert [o.status for o in out] == [IntakeStatus.ingested], out[0].reasons


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


def test_backlog_deeper_than_one_poll_is_drained_exactly_once(
    engine: Engine, gh: FakeGitHub, tmp_path: Path
) -> None:
    """Seen attempts are skipped before `limit` is applied, so older never-seen runs are reached
    on later polls instead of being shadowed forever by the newest already-ingested ones. Each
    batch is ingested oldest first, and whatever the ingestion order, the run that finished last
    is the latest one everywhere."""
    run_ids = [RUN_ID + i for i in range(12)]
    for n, rid in enumerate(run_ids):
        tree = _bundle(
            tmp_path / f"tree-{rid}",
            run_id=rid,
            captured_at=datetime(2026, 9, 8, 3, tzinfo=UTC) + timedelta(hours=n),
        )
        _publish(gh, tree, run_id=rid, head_sha=BASELINE_SHA)
    svc = _service(engine, gh, tmp_path)

    batches: list[list[str]] = []
    for expected in (5, 5, 2, 0):
        gh.workflow_runs_yielded = 0
        out = svc.poll(limit=5)
        assert len(out) == expected
        assert all(o.status is IntakeStatus.ingested and not o.seen_before for o in out)
        batches.append([o.external_run_id for o in out])
    ext = [f"gha:{FORK_REPO}:{rid}:1" for rid in run_ids]
    # The listing is newest first and only read as far as needed to find `limit` unseen runs;
    # the selected batch is then ingested in scan order.
    assert batches == [ext[7:12], ext[2:7], ext[0:2], []]
    seen = [e for b in batches for e in b]
    assert len(seen) == len(set(seen)) == 12
    assert gh.workflow_runs_yielded == 12, "the empty poll had to walk the whole listing"
    assert len(_intakes(engine)) == 12
    with Session(engine) as db:
        runs = db.exec(select(ScanRun).order_by(col(ScanRun.id))).all()
        assert len(runs) == 12
        newest = max(runs, key=ScanRun.chronology)
        assert newest.external_run_id == ext[-1]
        assert newest.id != runs[-1].id, "the last-ingested run is an older backlog entry"
        assert [r.external_run_id for r in sorted(runs, key=ScanRun.chronology)] == ext
    settings = Settings(
        data_dir=tmp_path / "data", database_file="c.sqlite3", repo_root=ROOT, operator_mode=True
    )
    with Session(engine) as db:
        latest = Orchestrator(engine, gh, FakeDevin(), settings)._latest_main_run(db, None)
    assert latest is not None and latest.external_run_id == ext[-1]
    header = header_context(engine, "main").latest_run
    assert header is not None and header.external_run_id == ext[-1]
    _, report_latest = select_runs(list(runs), fork_repo=FORK_REPO, branch="main")
    assert report_latest is not None and report_latest.external_run_id == ext[-1]


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


def test_scan_api_failure_does_not_stall_sessions_prs_or_labels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An Actions/artifact API outage is reported on the tick and retried later; the sessions,
    PRs and human labels already in flight keep progressing meanwhile."""
    w = World(tmp_path / "replay.sqlite3")
    w.baseline("cryptography")
    w.tick()
    wi = w.only_wi()
    assert wi.state is WorkItemState.session_active

    def outage(*_: object, **__: object) -> object:
        raise httpx.ConnectError("actions api unreachable")

    monkeypatch.setattr(w.gh, "list_workflow_runs", outage)
    output = {
        "packages": [{"name": "cryptography", "from": "42.0.2", "to": "42.0.4"}],
        "regenerated_with": "./scripts/uv-pip-compile.sh",
    }
    _url, number = w.devin_opens_pr(wi, output, files=DEP_FILES, acus=1.0)
    report = w.tick()
    assert report.scan_intake_error == "ConnectError: actions api unreachable"
    assert (report.scans_ingested, report.scans_rejected) == (0, 0)
    assert report.sessions_polled >= 1
    assert w.state_of(wi.id or 0) is WorkItemState.checks_running, "session outcome was applied"

    head = w.gh.prs[number].head_sha
    w.ci(head)
    assert w.tick().scan_intake_error is not None
    w.review_done(head)
    assert w.tick().scan_intake_error is not None
    assert w.state_of(wi.id or 0) is WorkItemState.ready_for_human, "PR checks were polled"
    w.gh.approve(number, "Hunter-1298", at=w.clock.now())
    report = w.tick()
    assert report.scan_intake_error is not None and report.prs_polled >= 1
    pr_row = w.pr_row(wi.id or 0)
    assert pr_row is not None and pr_row.approved_by == "Hunter-1298", "PR approval was polled"
    w.gh.close_issue(FORK_REPO, wi.issue_number or 0)
    report = w.tick()
    assert report.scan_intake_error is not None and report.labels_applied >= 1
    assert w.state_of(wi.id or 0) is WorkItemState.abandoned, "issue state was polled"
    assert w.scan_intakes() == [], "no intake row is written for runs that were never listed"

    monkeypatch.undo()
    assert w.tick().scan_intake_error is None


def _closure_stamps(engine: Engine) -> list[datetime | None]:
    with Session(engine) as db:
        return [
            r.closure_applied_at for r in db.exec(select(ScanRun).order_by(col(ScanRun.id))).all()
        ]


def test_run_ingested_by_the_service_alone_is_evaluated_by_the_next_tick(
    gh: FakeGitHub, tmp_path: Path
) -> None:
    """The `ingest` CLI is the intake service without an orchestrator: it persists the run and
    stops. The next operator tick owes that run its closing evaluation and does it once."""
    settings = Settings(
        data_dir=tmp_path / "data", database_file="c.sqlite3", repo_root=ROOT, operator_mode=True
    )
    engine = open_database(settings.database_path)
    _publish(gh, _bundle(tmp_path / "good"), head_sha=BASELINE_SHA)
    svc = ScanIntakeService(
        engine,
        gh,
        repo_root=ROOT,
        evidence_dir=settings.data_dir / "evidence",
        expect=IntakeExpectation(source_repo=FORK_REPO, source_branch="main"),
    )
    assert [o.status for o in svc.poll()] == [IntakeStatus.ingested]
    assert _closure_stamps(engine) == [None]

    orch = Orchestrator(engine, gh, FakeDevin(), settings)
    first = orch.tick(auto_dispatch=False)
    assert (first.scans_ingested, first.scans_rejected) == (0, 0), "already seen; not re-pulled"
    stamps = _closure_stamps(engine)
    assert stamps != [None]
    orch.tick(auto_dispatch=False)
    assert _closure_stamps(engine) == stamps
    assert len(_intakes(engine)) == 1


def test_run_that_outlived_a_crash_before_its_intake_record_is_recovered_and_evaluated(
    gh: FakeGitHub, tmp_path: Path
) -> None:
    """`ScanRun` and `ScanIntake` are written in separate transactions. Losing the second leaves
    a run the poller will meet again as `created=False`; it must still be evaluated exactly once
    and end up with its intake row."""
    settings = Settings(
        data_dir=tmp_path / "data", database_file="c.sqlite3", repo_root=ROOT, operator_mode=True
    )
    engine = open_database(settings.database_path)
    _publish(gh, _bundle(tmp_path / "good"), head_sha=BASELINE_SHA)
    svc = ScanIntakeService(
        engine,
        gh,
        repo_root=ROOT,
        evidence_dir=settings.data_dir / "evidence",
        expect=IntakeExpectation(source_repo=FORK_REPO, source_branch="main"),
    )
    assert svc.poll()[0].created
    with Session(engine) as db:
        for row in db.exec(select(ScanIntake)).all():
            db.delete(row)
        db.commit()
    assert _intakes(engine) == [] and _closure_stamps(engine) == [None]

    orch = Orchestrator(engine, gh, FakeDevin(), settings)
    report = orch.tick(auto_dispatch=False)
    assert (report.scans_ingested, report.scans_rejected) == (1, 0)
    intakes = _intakes(engine)
    assert len(intakes) == 1 and intakes[0].status is IntakeStatus.ingested
    assert "scan run already present; no new rows written" in intakes[0].reasons
    with Session(engine) as db:
        assert len(db.exec(select(ScanRun)).all()) == 1
    stamps = _closure_stamps(engine)
    assert stamps != [None]
    orch.tick(auto_dispatch=False)
    assert _closure_stamps(engine) == stamps


def test_ingest_cli_refuses_without_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["ingest", "--db", str(tmp_path / "c.sqlite3")]) == 2
    assert "HL_GITHUB_TOKEN" in capsys.readouterr().err


def _git_repo_with(tmp_path: Path) -> Path:
    """A throwaway git repo (`baseline -> main2`, plus an orphan) for offline ancestry answers."""
    import subprocess

    repo = tmp_path / "fork-git"
    repo.mkdir()
    env = {
        "GIT_AUTHOR_NAME": "t",
        "GIT_AUTHOR_EMAIL": "t@x",
        "GIT_COMMITTER_NAME": "t",
        "GIT_COMMITTER_EMAIL": "t@x",
        "HOME": str(tmp_path),
    }

    def git(*a: str) -> str:
        return subprocess.run(
            ["git", "-C", str(repo), *a], check=True, capture_output=True, text=True, env=env
        ).stdout.strip()

    git("init", "-q")
    (repo / "f").write_text("a")
    git("add", "f")
    git("commit", "-q", "-m", "baseline")
    base = git("rev-parse", "HEAD")
    (repo / "f").write_text("b")
    git("commit", "-q", "-am", "main2")
    head = git("rev-parse", "HEAD")
    git("checkout", "-q", "--orphan", "unrelated")
    (repo / "f").write_text("c")
    git("add", "f")
    git("commit", "-q", "-m", "unrelated")
    unrelated = git("rev-parse", "HEAD")
    (repo / ".shas").write_text(json.dumps([base, head, unrelated]))
    return repo


def test_evidence_verify_cli_accepts_matching_bundle_and_rejects_offline(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = _git_repo_with(tmp_path)
    base, head, unrelated = json.loads((repo / ".shas").read_text())

    good = _bundle(tmp_path / "good", source_sha=head)
    common = [
        "--run-id",
        str(RUN_ID),
        "--head-sha",
        head,
        "--baseline-sha",
        base,
        "--git",
        str(repo),
    ]
    out = tmp_path / "verdict.json"
    assert main(["evidence-verify", str(good), *common, "--out", str(out)]) == 0
    verdict = json.loads(out.read_text())
    assert verdict["accepted"] is True and verdict["reasons"] == []
    assert verdict["source_sha"] == head

    # A byte changed in a checksummed raw file.
    tampered = _bundle(tmp_path / "tampered", source_sha=head)
    vuln = tampered / "lean" / "raw" / "trivy-vuln.json"
    vuln.write_text(vuln.read_text().replace("{", " {", 1))
    assert main(["evidence-verify", str(tampered), *common]) == 1
    assert "failed verification" in capsys.readouterr().out

    # Evidence for a commit that is not the run's head.
    other = _bundle(tmp_path / "other", source_sha=base)
    assert main(["evidence-verify", str(other), *common]) == 1
    assert "workflow run was for" in capsys.readouterr().out

    # Evidence built from a commit outside the baseline's history.
    foreign_history = _bundle(tmp_path / "foreign-history", source_sha=unrelated)
    rc = main(["evidence-verify", str(foreign_history), *common, "--head-sha", unrelated])
    assert rc == 1
    assert "does not descend from baseline" in capsys.readouterr().out

    # The run GitHub reports was a pull_request, the manifest says schedule.
    assert main(["evidence-verify", str(good), *common, "--event", "pull_request"]) == 1
    assert "manifest trigger 'schedule' != workflow event 'pull_request'" in capsys.readouterr().out
    assert main(["evidence-verify", str(good), *common, "--event", "schedule"]) == 0

    # Another repository, even a real one.
    foreign = _bundle(tmp_path / "foreign", source_sha=head, source_repo="apache/superset")
    assert main(["evidence-verify", str(foreign), *common]) == 1
    assert "outside the allowlist" in capsys.readouterr().out

    # No manifest at all.
    (good / "manifest.json").unlink()
    assert main(["evidence-verify", str(good), *common]) == 1
    assert "no manifest.json" in capsys.readouterr().out


def test_rest_list_workflow_runs_pages_until_short_page() -> None:
    """The REST client walks `page=1,2,...` at `per_page=100` and stops at the first short page,
    so a backlog longer than one page is fully enumerated; a run listing must not stop at 100."""
    from pydantic import SecretStr

    from hardening_loop.github.rest import PER_PAGE, GitHubRest

    total = PER_PAGE * 2 + 7
    pages_seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/repos/{FORK_REPO}/actions/workflows/security-scan.yml/runs"
        assert request.url.params["per_page"] == str(PER_PAGE)
        assert request.url.params["branch"] == "main"
        assert request.url.params["status"] == "completed"
        page = int(request.url.params["page"])
        pages_seen.append(page)
        start = (page - 1) * PER_PAGE
        ids = range(total - start, max(total - start - PER_PAGE, 0), -1)
        return httpx.Response(
            200,
            json={
                "total_count": total,
                "workflow_runs": [
                    {
                        "id": i,
                        "run_attempt": 1,
                        "event": "schedule",
                        "status": "completed",
                        "conclusion": "success",
                        "head_branch": "main",
                        "head_sha": "a" * 40,
                        "html_url": f"https://example/{i}",
                    }
                    for i in ids
                ],
            },
        )

    gh = GitHubRest(SecretStr("t"), transport=httpx.MockTransport(handler))
    runs = gh.list_workflow_runs(FORK_REPO, "security-scan.yml", branch="main", status="completed")
    first = next(runs)
    assert first.id == total and pages_seen == [1]  # lazy: one page fetched so far
    rest = list(runs)
    assert [first.id, *(r.id for r in rest)] == list(range(total, 0, -1))
    assert pages_seen == [1, 2, 3]


def test_rest_list_run_artifacts_pages_until_short_page() -> None:
    """A run with more than one page of artifacts (matrix jobs each upload several) must still
    surface the `scan-evidence-*` artifact when it lands beyond the first 100 entries."""
    from pydantic import SecretStr

    from hardening_loop.github.rest import PER_PAGE, GitHubRest

    total = PER_PAGE + 3
    pages_seen: list[int] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == f"/repos/{FORK_REPO}/actions/runs/{RUN_ID}/artifacts"
        assert request.url.params["per_page"] == str(PER_PAGE)
        page = int(request.url.params["page"])
        pages_seen.append(page)
        start = (page - 1) * PER_PAGE
        ids = range(start + 1, min(start + PER_PAGE, total) + 1)
        return httpx.Response(
            200,
            json={
                "total_count": total,
                "artifacts": [
                    {
                        "id": i,
                        "name": "scan-evidence-x" if i == total else f"sbom-{i}",
                        "size_in_bytes": 1,
                        "expired": False,
                    }
                    for i in ids
                ],
            },
        )

    gh = GitHubRest(SecretStr("t"), transport=httpx.MockTransport(handler))
    artifacts = gh.list_run_artifacts(FORK_REPO, RUN_ID)
    assert len(artifacts) == total and pages_seen == [1, 2]
    evidence = find_evidence_artifact(artifacts)
    assert evidence is not None and evidence.id == total
