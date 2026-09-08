"""Stage a `security-scan` evidence bundle from the committed baseline fixture, laid out the way the
workflow's `scan-manifest` job leaves it, so intake can be replayed without GitHub or a registry."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hardening_loop.ci import RegistryImage, WorkflowRun, gate_job, write_scan_manifest
from hardening_loop.config import BASELINE_SHA, FORK_REPO
from hardening_loop.domain.enums import GateMode, ImageTarget
from hardening_loop.ingest.evidence import RUNTIME_RECORDS

LEAN_DIGEST = "sha256:" + "a" * 64
CI_DIGEST = "sha256:" + "b" * 64
_SHARED_LAYERS = [
    {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": "sha256:" + "1" * 64,
        "size": 100,
    },
    {
        "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
        "digest": "sha256:" + "2" * 64,
        "size": 200,
    },
]
_CI_LAYER = {
    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
    "digest": "sha256:" + "3" * 64,
    "size": 555,
}


def registry_image(target: ImageTarget, digest: str, layers: list[dict[str, Any]]) -> RegistryImage:
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
            "config": {
                "User": "superset",
                "Labels": {"org.opencontainers.image.revision": BASELINE_SHA},
            },
        },
    )


def registry_images() -> dict[ImageTarget, RegistryImage]:
    return {
        ImageTarget.lean: registry_image(ImageTarget.lean, LEAN_DIGEST, _SHARED_LAYERS),
        ImageTarget.ci: registry_image(ImageTarget.ci, CI_DIGEST, [*_SHARED_LAYERS, _CI_LAYER]),
    }


def stage_runtime_records(
    out: Path,
    images: dict[ImageTarget, RegistryImage],
    job_results: dict[str, str],
    *,
    image_refs: dict[str, str] | None = None,
) -> None:
    """Write the verdict each runtime job leaves under `runtime/<job>/`, shaped like lean_smoke.sh
    and app_runs.py write it and consistent with `job_results` (a failed job names a failed step).
    Jobs without a result leave no record, as when the job never ran. `image_refs` overrides the
    image a record claims to have started."""
    for job, (rel, target) in RUNTIME_RECORDS.items():
        result = job_results.get(job)
        if result is None:
            continue
        passed = result == "success"
        image = images[target]
        ref = (image_refs or {}).get(job) or f"{image.tag.rsplit(':', 1)[0]}@{image.digest}"
        checks = {"init": "ok", "migrations": "4b2a8c9d3e1f (head)", "health": "200 OK after 6s"}
        doc = {
            "image_ref": ref,
            "passed": passed,
            "failed_step": None if passed else "login",
            "checks": checks if passed else {"init": "ok", "health": "200 OK after 6s"},
        }
        path = out / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")


def stage_evidence_bundle(
    out: Path,
    *,
    repo_root: Path,
    run_id: int,
    run_attempt: int = 1,
    source_sha: str = BASELINE_SHA,
    source_branch: str = "main",
    source_repo: str = FORK_REPO,
    event: str = "schedule",
    head_sha: str | None = None,
    job_results: dict[str, str] | None = None,
    now: datetime | None = None,
) -> Path:
    """Copy the fixture's lean raw/policy jobs (plus a ci/raw job derived from lean/raw), rewrite
    their `image_ref` to the staged registry digests, run the report-mode gate, and write the
    manifest. Rewriting `job.json` is legal: it is not part of its own checksum list."""
    fixture = repo_root / "fixtures" / "baseline" / BASELINE_SHA
    out.mkdir(parents=True, exist_ok=True)
    for name, src, digest in (
        ("lean/raw", "lean/raw", LEAN_DIGEST),
        ("lean/policy", "lean/policy", LEAN_DIGEST),
        ("ci/raw", "lean/raw", CI_DIGEST),
    ):
        dst = out / name
        shutil.copytree(fixture / src, dst)
        job = json.loads((dst / "job.json").read_text())
        job["image_ref"] = f"ghcr.io/hunter-1298/superset@{digest}"
        job["image_target"] = name.split("/")[0]
        (dst / "job.json").write_text(json.dumps(job, indent=2))
    gate = out / "gates" / "lean-policy.json"
    gate.parent.mkdir()
    payload = gate_job(out / "lean" / "policy", GateMode.report).to_dict()
    gate.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")
    results = (
        job_results if job_results is not None else {"lean-smoke": "success", "app-runs": "success"}
    )
    stage_runtime_records(out, registry_images(), results)
    write_scan_manifest(
        out,
        source_repo=source_repo,
        source_branch=source_branch,
        source_sha=source_sha,
        platform="linux/amd64",
        images=registry_images(),
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
        expected_jobs=("lean-raw", "lean-policy", "ci-raw"),
        gate_files={"lean-policy": gate},
        attach_dirs=("runtime",) if results else (),
        now=now or datetime(2026, 9, 8, 3, tzinfo=UTC),
    )
    return out
