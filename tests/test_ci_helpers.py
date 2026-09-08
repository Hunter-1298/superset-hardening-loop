"""The CI helpers the fork's `security-scan` workflow runs: policy gate over a real evidence dir,
`security/vex/approved/` lint, scanner-ignore-file rejection and manifest aggregation that refuses
incomplete or digest-mismatched runs."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from hardening_loop.ci import (
    RegistryImage,
    WorkflowRun,
    find_ignore_files,
    gate_job,
    layer_delta,
    lint_approved_vex,
    load_registry_image,
    write_scan_manifest,
)
from hardening_loop.cli import main
from hardening_loop.config import BASELINE_SHA, FORK_REPO
from hardening_loop.domain.enums import GateMode, ImageTarget
from hardening_loop.ingest.evidence import SCAN_MANIFEST_SCHEMA, EvidenceError, load_baseline
from hardening_loop.replay.synth import approved_vex

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "baseline" / BASELINE_SHA
ISSUE_URL = f"https://github.com/{FORK_REPO}/issues/41"
LEAN_DIGEST = "sha256:" + "a" * 64
CI_DIGEST = "sha256:" + "b" * 64


# ------------------------------------------------------------------------------------------ gate


def test_gate_report_mode_records_but_passes() -> None:
    result = gate_job(FIXTURE / "lean" / "policy", GateMode.report)
    v = result.verdict
    assert v.passed and v.mode is GateMode.report
    assert v.policy_high + v.policy_critical > 0  # the 6.1.0 baseline is far from clean
    assert not v.ready_for_enforce
    assert result.counts_by_severity["HIGH"] == v.policy_high
    assert result.image_target == "lean"


def test_gate_enforce_fails_on_any_high_or_critical() -> None:
    result = gate_job(FIXTURE / "lean" / "policy", GateMode.enforce)
    assert not result.verdict.passed
    assert "fix availability ignored" in result.verdict.reason


def test_gate_rejects_raw_job() -> None:
    with pytest.raises(EvidenceError, match="policy jobs only"):
        gate_job(FIXTURE / "lean" / "raw", GateMode.report)


def test_gate_counts_are_deduplicated_across_scanners() -> None:
    from hardening_loop.ingest.evidence import load_scan_job

    job = load_scan_job(FIXTURE / "lean" / "policy")
    result = gate_job(FIXTURE / "lean" / "policy", GateMode.report)
    total = sum(result.counts_by_severity.values())
    assert total < len(job.trivy_vulns) + len(job.grype_vulns)
    assert total >= max(len(job.trivy_vulns), len(job.grype_vulns)) - 50


def test_gate_cli_exit_codes(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    out = tmp_path / "gate.json"
    assert (
        main(
            [
                "gate",
                "--job",
                str(FIXTURE / "lean" / "policy"),
                "--mode",
                "report",
                "--out",
                str(out),
            ]
        )
        == 0
    )
    payload = json.loads(out.read_text())
    assert payload["passed"] is True and payload["mode"] == "report"
    assert main(["gate", "--job", str(FIXTURE / "lean" / "policy"), "--mode", "enforce"]) == 1
    assert "::error::" in capsys.readouterr().out
    assert main(["gate", "--job", str(FIXTURE / "lean" / "raw"), "--mode", "report"]) == 2


# -------------------------------------------------------------------------------------- vex-lint


def _write_approved(src: Path, name: str, doc: Any) -> Path:
    d = src / "security" / "vex" / "approved"
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text(json.dumps(doc) if not isinstance(doc, str) else doc)
    return p


def _good() -> dict[str, Any]:
    return approved_vex(
        issue_url=ISSUE_URL,
        vuln_id="CVE-2023-48795",
        purl="pkg:pypi/paramiko@3.4.0",
        approver="hunter",
    )


def test_vex_lint_empty_or_missing_dir_is_ok(tmp_path: Path) -> None:
    assert lint_approved_vex(tmp_path).ok
    (tmp_path / "security" / "vex" / "approved").mkdir(parents=True)
    (tmp_path / "security" / "vex" / "approved" / "README.md").write_text("approved OpenVEX only\n")
    report = lint_approved_vex(tmp_path)
    assert report.ok and report.checked == []


def test_vex_lint_accepts_complete_document(tmp_path: Path) -> None:
    _write_approved(tmp_path, "cve-2023-48795.json", _good())
    # proposed/ documents are not policy input and may be incomplete
    proposed = tmp_path / "security" / "vex" / "proposed"
    proposed.mkdir(parents=True)
    (proposed / "draft.json").write_text("{}")
    report = lint_approved_vex(tmp_path, repo=FORK_REPO, approvers=frozenset({"hunter"}))
    assert report.ok, report.problems
    assert report.issue_urls == {"security/vex/approved/cve-2023-48795.json": ISSUE_URL}


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda d: d.pop("x-approval"), "missing or malformed x-approval"),
        (lambda d: d["x-approval"].pop("approved_at"), "approved_at"),
        (lambda d: d["x-approval"].update(approved_at="2026-09-01"), "approved_at"),
        (lambda d: d["x-approval"].update(approved_at="2026-09-01T10:00:00"), "approved_at"),
        (lambda d: d["x-approval"].update(approved_by="stranger"), "not an allowed approver"),
        (
            lambda d: d["x-approval"].update(
                issue_url="https://github.com/apache/superset/issues/1"
            ),
            "points at apache/superset",
        ),
        (lambda d: d["statements"][0].update(status="under_investigation"), "cannot suppress"),
        (lambda d: d["statements"][0].pop("justification"), "needs a justification"),
        (lambda d: d["statements"][0].update(impact_statement=" "), "impact_statement"),
        (lambda d: d.pop("author"), "`author` is required"),
        (lambda d: d.update(timestamp="yesterday"), "`timestamp`"),
        (lambda d: d.update({"@context": "https://example.com"}), "not an OpenVEX document"),
    ],
)
def test_vex_lint_rejects_incomplete_approvals(tmp_path: Path, mutate: Any, needle: str) -> None:
    doc = _good()
    mutate(doc)
    _write_approved(tmp_path, "cve-2023-48795.json", doc)
    report = lint_approved_vex(tmp_path, repo=FORK_REPO, approvers=frozenset({"hunter"}))
    assert not report.ok
    assert any(needle in p for p in report.problems), report.problems


def test_vex_lint_rejects_non_json_and_stray_files(tmp_path: Path) -> None:
    _write_approved(tmp_path, "notes.txt", "not vex")
    _write_approved(tmp_path, "broken.json", "{not json")
    (tmp_path / "security" / "vex" / "approved" / "nested").mkdir()
    report = lint_approved_vex(tmp_path)
    assert len(report.problems) == 3
    assert any("only *.json" in p for p in report.problems)
    assert any("not valid JSON" in p for p in report.problems)


def test_vex_lint_cli(tmp_path: Path) -> None:
    _write_approved(tmp_path, "cve-2023-48795.json", _good())
    issues = tmp_path / "issues.json"
    assert (
        main(
            [
                "vex-lint",
                str(tmp_path),
                "--repo",
                FORK_REPO,
                "--approvers",
                "hunter, other",
                "--issues-out",
                str(issues),
            ]
        )
        == 0
    )
    assert json.loads(issues.read_text()) == {
        "security/vex/approved/cve-2023-48795.json": ISSUE_URL
    }
    assert main(["vex-lint", str(tmp_path), "--approvers", "nobody"]) == 1


# ---------------------------------------------------------------------------- forbid-ignore-files


def test_find_ignore_files(tmp_path: Path) -> None:
    assert find_ignore_files(tmp_path) == []
    (tmp_path / ".trivyignore").write_text("CVE-2024-0001\n")
    (tmp_path / "helm" / "superset").mkdir(parents=True)
    (tmp_path / "helm" / "superset" / ".grype.yaml").write_text("ignore: []\n")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / ".trivyignore").write_text("")
    assert find_ignore_files(tmp_path) == [".trivyignore", "helm/superset/.grype.yaml"]
    assert main(["forbid-ignore-files", str(tmp_path)]) == 1


# --------------------------------------------------------------------------------------- manifest


def _layer(digest: str, size: int) -> dict[str, Any]:
    return {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": digest,
        "size": size,
    }


def _image(
    target: ImageTarget, digest: str, layers: list[dict[str, Any]], user: str = "superset"
) -> RegistryImage:
    return RegistryImage(
        target=target,
        tag=f"ghcr.io/hunter-1298/superset:sha-{BASELINE_SHA[:12]}-{target.value}",
        digest=digest,
        manifest={
            "schemaVersion": 2,
            "config": {"digest": "sha256:" + "c" * 64, "size": 10},
            "layers": layers,
        },
        config={
            "created": "2026-09-07T00:00:00Z",
            "config": {"User": user, "Labels": {"org.opencontainers.image.revision": BASELINE_SHA}},
        },
    )


SHARED = [_layer("sha256:" + "1" * 64, 100), _layer("sha256:" + "2" * 64, 200)]
CI_EXTRA = _layer("sha256:" + "3" * 64, 555)


def _stage_jobs(
    out: Path,
    *,
    lean_digest: str = LEAN_DIGEST,
    ci_digest: str = CI_DIGEST,
    drop: str | None = None,
) -> None:
    """Copy the fixture jobs and rewrite their image_ref to the registry digests used in this test.
    The committed baseline has no ci/raw job, so it is staged from lean/raw with the target renamed.
    Rewriting job.json is legal because job.json is not part of its own checksum list."""
    for name, src, digest in (
        ("lean/raw", "lean/raw", lean_digest),
        ("lean/policy", "lean/policy", lean_digest),
        ("ci/raw", "lean/raw", ci_digest),
    ):
        if name == drop:
            continue
        dst = out / name
        shutil.copytree(FIXTURE / src, dst)
        job = json.loads((dst / "job.json").read_text())
        job["image_ref"] = f"ghcr.io/hunter-1298/superset@{digest}"
        job["image_target"] = name.split("/")[0]
        (dst / "job.json").write_text(json.dumps(job, indent=2))


def _run() -> WorkflowRun:
    return WorkflowRun(
        run_id=42,
        run_attempt=1,
        event="push",
        workflow_sha=BASELINE_SHA,
        ref="refs/heads/main",
        gate_mode=GateMode.report,
        job_results={"lean-smoke": "success", "app-runs": "success"},
    )


def test_workflow_run_runtime_verified_requires_every_runtime_job_green() -> None:
    assert _run().runtime_verified is True
    broken = WorkflowRun(
        run_id=1,
        run_attempt=1,
        event="pull_request",
        workflow_sha="a" * 40,
        ref="refs/pull/9/merge",
        gate_mode=GateMode.report,
        head_sha="b" * 40,
        job_results={"lean-smoke": "success", "app-runs": "failure"},
    )
    assert broken.runtime_verified is False
    assert broken.to_dict()["head_sha"] == "b" * 40
    none_recorded = WorkflowRun(
        run_id=1,
        run_attempt=1,
        event="push",
        workflow_sha="a" * 40,
        ref="r",
        gate_mode=GateMode.report,
    )
    assert none_recorded.runtime_verified is False
    partial = WorkflowRun(
        run_id=1,
        run_attempt=1,
        event="push",
        workflow_sha="a" * 40,
        ref="r",
        gate_mode=GateMode.report,
        job_results={"lean-smoke": "success"},
    )
    assert partial.runtime_verified is False, "app-runs missing must not count as verified"


def _images() -> dict[ImageTarget, RegistryImage]:
    return {
        ImageTarget.lean: _image(ImageTarget.lean, LEAN_DIGEST, SHARED),
        ImageTarget.ci: _image(ImageTarget.ci, CI_DIGEST, [*SHARED, CI_EXTRA]),
    }


def test_layer_delta_counts_only_ci_layers() -> None:
    images = _images()
    delta = layer_delta(images[ImageTarget.lean], images[ImageTarget.ci])
    assert delta["ci_extra_bytes"] == 555
    assert delta["ci_only_layers"] == [CI_EXTRA["digest"]]
    assert delta["shared_layer_count"] == 2 and delta["lean_only_layers"] == []


def test_write_scan_manifest_roundtrips_through_load_baseline(tmp_path: Path) -> None:
    _stage_jobs(tmp_path)
    gate = tmp_path / "gates" / "lean-policy.json"
    gate.parent.mkdir()
    assert (
        main(
            [
                "gate",
                "--job",
                str(tmp_path / "lean" / "policy"),
                "--mode",
                "report",
                "--out",
                str(gate),
            ]
        )
        == 0
    )
    manifest = write_scan_manifest(
        tmp_path,
        source_repo=FORK_REPO,
        source_branch="main",
        source_sha=BASELINE_SHA,
        platform="linux/amd64",
        images=_images(),
        run=_run(),
        gate_files={"lean-policy": gate},
    )
    assert manifest["schema"] == SCAN_MANIFEST_SCHEMA
    assert manifest["images"]["lean"]["image_id"] == LEAN_DIGEST
    assert manifest["images"]["lean"]["config_user"] == "superset"
    assert manifest["ci_layer_delta"]["ci_extra_bytes"] == 555
    assert manifest["gates"]["lean-policy"]["mode"] == "report"
    assert manifest["run"]["url"].endswith("/actions/runs/42/attempts/1")
    assert "gates/lean-policy.json" in manifest["files"]
    sums = (tmp_path / "SHA256SUMS").read_text().splitlines()
    assert sums[-1].endswith("  manifest.json")

    loaded = load_baseline(tmp_path)
    assert loaded.source_sha == BASELINE_SHA and loaded.trigger == "push"
    assert set(loaded.jobs) == {"lean-raw", "lean-policy", "ci-raw"}
    assert loaded.lean_image_id == LEAN_DIGEST
    assert loaded.run["run_id"] == 42 and loaded.gates["lean-policy"]["passed"] is True
    assert loaded.run["runtime_verified"] is True
    assert loaded.run["job_results"] == {"app-runs": "success", "lean-smoke": "success"}


def test_write_scan_manifest_attaches_runtime_records_and_controller_sha(tmp_path: Path) -> None:
    _stage_jobs(tmp_path)
    gate = tmp_path / "gates" / "lean-policy.json"
    gate.parent.mkdir()
    policy = str(tmp_path / "lean" / "policy")
    assert main(["gate", "--job", policy, "--mode", "report", "--out", str(gate)]) == 0
    (tmp_path / "runtime" / "lean-smoke").mkdir(parents=True)
    (tmp_path / "runtime" / "lean-smoke" / "result.json").write_text('{"ok": true}\n')
    (tmp_path / "runtime" / "app-runs" / "checks").mkdir(parents=True)
    (tmp_path / "runtime" / "app-runs" / "checks" / "login.json").write_text("{}\n")
    (tmp_path / "provenance").mkdir()
    (tmp_path / "provenance" / "lean.jsonl").write_text("{}\n")
    controller = "c" * 40

    manifest = write_scan_manifest(
        tmp_path,
        source_repo=FORK_REPO,
        source_branch="main",
        source_sha=BASELINE_SHA,
        platform="linux/amd64",
        images=_images(),
        run=_run(),
        gate_files={"lean-policy": gate},
        attach_dirs=("runtime", "provenance"),
        controller_sha=controller,
    )
    assert manifest["controller_sha"] == controller
    assert manifest["attachments"] == {
        "runtime": ["runtime/app-runs/checks/login.json", "runtime/lean-smoke/result.json"],
        "provenance": ["provenance/lean.jsonl"],
    }
    for rel in ("runtime/lean-smoke/result.json", "provenance/lean.jsonl"):
        assert rel in manifest["files"]
        assert f"  {rel}" in (tmp_path / "SHA256SUMS").read_text()
    load_baseline(tmp_path)

    # A byte changed in an attached record is caught like any scan file.
    (tmp_path / "runtime" / "lean-smoke" / "result.json").write_text('{"ok": false}\n')
    with pytest.raises(EvidenceError):
        load_baseline(tmp_path)


def test_write_scan_manifest_refuses_bad_attachments(tmp_path: Path) -> None:
    _stage_jobs(tmp_path)
    for attach, controller, needle in (
        (("missing",), None, "is not a directory"),
        ((), "main", "not a full commit sha"),
    ):
        with pytest.raises(EvidenceError, match=needle):
            write_scan_manifest(
                tmp_path,
                source_repo=FORK_REPO,
                source_branch="main",
                source_sha=BASELINE_SHA,
                platform="linux/amd64",
                images=_images(),
                run=_run(),
                attach_dirs=attach,
                controller_sha=controller,
            )
    (tmp_path / "empty").mkdir()
    with pytest.raises(EvidenceError, match="no files under"):
        write_scan_manifest(
            tmp_path,
            source_repo=FORK_REPO,
            source_branch="main",
            source_sha=BASELINE_SHA,
            platform="linux/amd64",
            images=_images(),
            run=_run(),
            attach_dirs=("empty",),
        )
    assert not (tmp_path / "manifest.json").exists()


def _stale_gate(tmp_path: Path, **override: object) -> Path:
    _stage_jobs(tmp_path)
    gate = tmp_path / "gates" / "lean-policy.json"
    gate.parent.mkdir()
    assert (
        main(
            [
                "gate",
                "--job",
                str(tmp_path / "lean" / "policy"),
                "--mode",
                "report",
                "--out",
                str(gate),
            ]
        )
        == 0
    )
    doc = json.loads(gate.read_text())
    doc.update(override)
    gate.write_text(json.dumps(doc))
    return gate


@pytest.mark.parametrize(
    ("override", "needle"),
    [
        ({"image_ref": "ghcr.io/hunter-1298/superset@sha256:" + "f" * 64}, "job scanned"),
        ({"image_target": "ci"}, "image_target"),
        ({"mode": "enforce"}, "evaluated in 'enforce'"),
    ],
)
def test_write_scan_manifest_refuses_gate_for_other_evidence(
    tmp_path: Path, override: dict[str, str], needle: str
) -> None:
    gate = _stale_gate(tmp_path, **override)
    with pytest.raises(EvidenceError, match=needle):
        write_scan_manifest(
            tmp_path,
            source_repo=FORK_REPO,
            source_branch="main",
            source_sha=BASELINE_SHA,
            platform="linux/amd64",
            images=_images(),
            run=_run(),
            gate_files={"lean-policy": gate},
        )
    assert not (tmp_path / "manifest.json").exists()


def test_write_scan_manifest_refuses_gate_without_matching_job(tmp_path: Path) -> None:
    gate = _stale_gate(tmp_path)
    with pytest.raises(EvidenceError, match="no scan job of that name"):
        write_scan_manifest(
            tmp_path,
            source_repo=FORK_REPO,
            source_branch="main",
            source_sha=BASELINE_SHA,
            platform="linux/amd64",
            images=_images(),
            run=_run(),
            gate_files={"ci-policy": gate},
        )


def test_write_scan_manifest_refuses_incomplete_run(tmp_path: Path) -> None:
    _stage_jobs(tmp_path, drop="ci/raw")
    with pytest.raises(EvidenceError, match="ci-raw: missing evidence"):
        write_scan_manifest(
            tmp_path,
            source_repo=FORK_REPO,
            source_branch="main",
            source_sha=BASELINE_SHA,
            platform="linux/amd64",
            images=_images(),
            run=_run(),
        )
    assert not (tmp_path / "manifest.json").exists()


def test_write_scan_manifest_refuses_digest_mismatch(tmp_path: Path) -> None:
    _stage_jobs(tmp_path, ci_digest="sha256:" + "f" * 64)
    with pytest.raises(EvidenceError, match=r"ci-raw: scanned .* build pushed"):
        write_scan_manifest(
            tmp_path,
            source_repo=FORK_REPO,
            source_branch="main",
            source_sha=BASELINE_SHA,
            platform="linux/amd64",
            images=_images(),
            run=_run(),
        )


def test_write_scan_manifest_refuses_platform_mismatch(tmp_path: Path) -> None:
    _stage_jobs(tmp_path)
    with pytest.raises(EvidenceError, match="platform linux/amd64 != linux/arm64"):
        write_scan_manifest(
            tmp_path,
            source_repo=FORK_REPO,
            source_branch="main",
            source_sha=BASELINE_SHA,
            platform="linux/arm64",
            images=_images(),
            run=_run(),
        )


def test_write_scan_manifest_refuses_tampered_evidence(tmp_path: Path) -> None:
    _stage_jobs(tmp_path)
    p = tmp_path / "lean" / "raw" / "trivy-vuln.json"
    p.write_text(p.read_text().replace("CRITICAL", "LOW", 1))
    with pytest.raises(EvidenceError, match="checksum mismatch"):
        write_scan_manifest(
            tmp_path,
            source_repo=FORK_REPO,
            source_branch="main",
            source_sha=BASELINE_SHA,
            platform="linux/amd64",
            images=_images(),
            run=_run(),
        )


def test_load_registry_image_rejects_index_and_bad_digest(tmp_path: Path) -> None:
    (tmp_path / "index.json").write_text(json.dumps({"manifests": []}))
    (tmp_path / "config.json").write_text(json.dumps({"config": {}}))
    (tmp_path / "manifest.json").write_text(json.dumps({"layers": [], "config": {}}))
    with pytest.raises(EvidenceError, match="got an index"):
        load_registry_image(
            ImageTarget.lean, "t", LEAN_DIGEST, tmp_path / "index.json", tmp_path / "config.json"
        )
    with pytest.raises(EvidenceError, match="not a sha256 digest"):
        load_registry_image(
            ImageTarget.lean, "t", "latest", tmp_path / "manifest.json", tmp_path / "config.json"
        )


def test_scan_manifest_cli(tmp_path: Path) -> None:
    _stage_jobs(tmp_path)
    meta = tmp_path / "meta"
    meta.mkdir()
    for target, digest, layers in (
        (ImageTarget.lean, LEAN_DIGEST, SHARED),
        (ImageTarget.ci, CI_DIGEST, [*SHARED, CI_EXTRA]),
    ):
        img = _image(target, digest, layers)
        (meta / f"{target.value}.manifest.json").write_text(json.dumps(img.manifest))
        (meta / f"{target.value}.config.json").write_text(json.dumps(img.config))
    args = [
        "scan-manifest",
        "--out",
        str(tmp_path),
        "--source-repo",
        FORK_REPO,
        "--source-branch",
        "main",
        "--source-sha",
        BASELINE_SHA,
        "--run-id",
        "42",
        "--run-attempt",
        "1",
        "--event",
        "push",
        "--workflow-sha",
        BASELINE_SHA,
        "--ref",
        "refs/heads/main",
        "--gate-mode",
        "report",
        "--expect-job",
        "lean-raw",
        "--expect-job",
        "lean-policy",
        "--expect-job",
        "ci-raw",
    ]
    for target, digest in ((ImageTarget.lean, LEAN_DIGEST), (ImageTarget.ci, CI_DIGEST)):
        tag = f"ghcr.io/hunter-1298/superset:sha-{BASELINE_SHA[:12]}-{target.value}"
        m, c = meta / f"{target.value}.manifest.json", meta / f"{target.value}.config.json"
        args += ["--image", f"{target.value}={tag}@{digest}:{m}:{c}"]
    assert main(args) == 0
    assert load_baseline(tmp_path).lean_image_id == LEAN_DIGEST
