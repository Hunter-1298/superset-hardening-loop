"""Helpers the fork's GitHub Actions workflow calls after `scripts/scan_image.sh`.

Three small, side-effect-free-by-default operations, so the workflow YAML stays declarative and
every rule that decides pass/fail lives (and is unit-tested) here:

* `gate_job`            policy job → `GateVerdict` for the configured `SCAN_GATE_MODE`
* `lint_approved_vex`   `security/vex/approved/` → list of problems (empty == OK)
* `write_scan_manifest` per-job evidence dirs + registry metadata → `manifest.json` + `SHA256SUMS`
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hardening_loop.domain.enums import GateMode, ImageTarget, ScanMode, Trigger
from hardening_loop.gate import GateVerdict, gate_verdict
from hardening_loop.ingest.evidence import (
    SCAN_MANIFEST_SCHEMA,
    EvidenceError,
    ScanJobEvidence,
    load_scan_job,
    sha256_file,
)
from hardening_loop.ingest.normalize import normalize
from hardening_loop.ingest.vex import (
    APPROVED_DIR,
    VexEvidenceError,
    approval_of,
    validate_openvex,
)

FORBIDDEN_IGNORE_FILES: tuple[str, ...] = (
    ".trivyignore",
    ".trivyignore.yaml",
    ".trivyignore.yml",
    ".grype.yaml",
    ".grype.yml",
    ".grype",
)


# --------------------------------------------------------------------------------------- gate


@dataclass(frozen=True)
class GateResult:
    verdict: GateVerdict
    counts_by_severity: dict[str, int]
    job_dir: Path
    image_ref: str
    image_target: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "hardening-loop/gate/v1",
            "mode": self.verdict.mode.value,
            "passed": self.verdict.passed,
            "reason": self.verdict.reason,
            "policy_high": self.verdict.policy_high,
            "policy_critical": self.verdict.policy_critical,
            "ready_for_enforce": self.verdict.ready_for_enforce,
            "counts_by_severity": dict(sorted(self.counts_by_severity.items())),
            "job_dir": str(self.job_dir),
            "image_ref": self.image_ref,
            "image_target": self.image_target,
        }


def policy_counts(job: ScanJobEvidence) -> dict[str, int]:
    """Deduplicated vulnerability counts by severity across both scanners of ONE policy job.
    A CVE both scanners report on the same package counts once, at the higher severity."""
    findings = normalize([*job.trivy_vulns, *job.grype_vulns])
    return dict(Counter(f.severity.value for f in findings))


def gate_job(job_dir: Path, mode: GateMode) -> GateResult:
    job = load_scan_job(job_dir)
    if job.mode is not ScanMode.policy:
        raise EvidenceError(f"{job_dir}: gate applies to policy jobs only, this one is {job.mode}")
    counts = policy_counts(job)
    return GateResult(
        verdict=gate_verdict(mode, counts),
        counts_by_severity=counts,
        job_dir=job_dir,
        image_ref=job.image_ref,
        image_target=job.image_target.value,
    )


# ----------------------------------------------------------------------------------- vex-lint

_ISSUE_URL_REPO = re.compile(r"^https://github\.com/([\w.-]+/[\w.-]+)/issues/(\d+)$")
_NOT_AFFECTED_JUSTIFICATIONS = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)


@dataclass
class VexLintReport:
    checked: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)
    issue_urls: dict[str, str] = field(default_factory=dict)  # file -> issue url

    @property
    def ok(self) -> bool:
        return not self.problems


def _lint_document(
    rel: str, doc: dict[str, Any], *, repo: str | None, approvers: frozenset[str] | None
) -> tuple[list[str], str | None]:
    problems: list[str] = []
    try:
        statements = validate_openvex(doc, where=rel)
    except VexEvidenceError as exc:
        return [str(exc)], None

    raw_statements = doc.get("statements") or []
    for i, (summary, raw) in enumerate(zip(statements, raw_statements, strict=True)):
        if summary.status == "not_affected":
            justification = raw.get("justification")
            impact = raw.get("impact_statement")
            if justification not in _NOT_AFFECTED_JUSTIFICATIONS:
                problems.append(
                    f"{rel}: statement {i} ({summary.vulnerability}) not_affected needs a "
                    f"justification from the OpenVEX list, got {justification!r}"
                )
            if not isinstance(impact, str) or not impact.strip():
                problems.append(
                    f"{rel}: statement {i} ({summary.vulnerability}) not_affected needs a "
                    "non-empty impact_statement (the reachability argument)"
                )
    author = doc.get("author")
    if not isinstance(author, str) or not author.strip():
        problems.append(f"{rel}: OpenVEX `author` is required")
    for key in ("timestamp",):
        value = doc.get(key)
        if not isinstance(value, str) or _parse_iso(value) is None:
            problems.append(f"{rel}: OpenVEX `{key}` must be an ISO-8601 timestamp")

    approval = approval_of(doc)
    raw_approval = doc.get("x-approval")
    if approval is None:
        problems.append(
            f"{rel}: missing or malformed x-approval "
            "(needs issue_url=https://github.com/<owner>/<repo>/issues/<n>, approved_by)"
        )
        return problems, None
    m = _ISSUE_URL_REPO.match(approval.issue_url)
    assert m is not None  # approval_of already matched the shape
    if repo is not None and m.group(1).lower() != repo.lower():
        problems.append(f"{rel}: x-approval.issue_url points at {m.group(1)}, expected {repo}")
    if approvers is not None and approval.approved_by not in approvers:
        problems.append(
            f"{rel}: x-approval.approved_by {approval.approved_by!r} is not an allowed approver"
        )
    approved_at = raw_approval.get("approved_at") if isinstance(raw_approval, dict) else None
    if not isinstance(approved_at, str) or _parse_iso(approved_at) is None:
        problems.append(f"{rel}: x-approval.approved_at must be an ISO-8601 timestamp")
    return problems, approval.issue_url


def _parse_iso(value: str) -> datetime | None:
    """An unambiguous instant: date and time with an explicit UTC offset (`Z` or `±hh:mm`)."""
    if "T" not in value and " " not in value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def lint_approved_vex(
    src: Path, *, repo: str | None = None, approvers: frozenset[str] | None = None
) -> VexLintReport:
    """Validate every file under `<src>/security/vex/approved/`.

    Every entry must be a `.json` OpenVEX document whose suppressing statements carry a
    justification and impact statement, with `author`/`timestamp`, and an `x-approval` block whose
    `issue_url` is an issue of `repo`, whose `approved_by` is an allowed approver (when an allowlist
    is given) and whose `approved_at` parses. Documents under `security/vex/proposed/` are not
    policy input and are deliberately not validated here."""
    report = VexLintReport()
    approved = src / APPROVED_DIR
    if not approved.is_dir():
        return report
    for path in sorted(approved.iterdir()):
        rel = path.relative_to(src).as_posix()
        if path.name in {"README.md", ".gitkeep"}:
            continue
        report.checked.append(rel)
        if path.is_dir() or path.suffix != ".json":
            report.problems.append(
                f"{rel}: only *.json OpenVEX documents belong in {APPROVED_DIR}/"
            )
            continue
        try:
            with path.open("rb") as fh:
                doc = json.load(fh)
        except (OSError, ValueError) as exc:
            report.problems.append(f"{rel}: not valid JSON ({exc})")
            continue
        if not isinstance(doc, dict):
            report.problems.append(f"{rel}: expected a JSON object")
            continue
        problems, issue_url = _lint_document(rel, doc, repo=repo, approvers=approvers)
        report.problems.extend(problems)
        if issue_url is not None:
            report.issue_urls[rel] = issue_url
    return report


def find_ignore_files(src: Path) -> list[str]:
    """Scanner ignore files anywhere in the tree (node_modules excluded); any hit is a failure."""
    hits: list[str] = []
    for name in FORBIDDEN_IGNORE_FILES:
        for p in src.rglob(name):
            if "node_modules" in p.parts:
                continue
            hits.append(p.relative_to(src).as_posix())
    return sorted(hits)


# ------------------------------------------------------------------------------------ manifest


@dataclass(frozen=True)
class RegistryImage:
    """What the build job pushed for one image target, as recorded by `docker buildx imagetools`."""

    target: ImageTarget
    tag: str
    digest: str  # registry manifest digest, the immutable reference every downstream job used
    manifest: dict[str, Any]  # OCI/Docker image manifest (layers with compressed sizes)
    config: dict[str, Any]  # image config (User, Labels, created, rootfs.diff_ids)

    @property
    def size_bytes(self) -> int:
        cfg_size = int((self.manifest.get("config") or {}).get("size") or 0)
        return cfg_size + sum(
            int(layer.get("size") or 0) for layer in self.manifest.get("layers") or []
        )

    @property
    def layer_digests(self) -> list[str]:
        return [str(layer["digest"]) for layer in self.manifest.get("layers") or []]

    def to_dict(self) -> dict[str, Any]:
        cfg = self.config.get("config") or {}
        return {
            "tag": self.tag,
            "image_id": self.digest,
            "digest_kind": "registry_manifest_digest",
            "config_digest": (self.manifest.get("config") or {}).get("digest"),
            "created": self.config.get("created"),
            "size_bytes": self.size_bytes,
            "config_user": cfg.get("User"),
            "labels": cfg.get("Labels"),
            "layer_count": len(self.layer_digests),
        }


def layer_delta(lean: RegistryImage, ci: RegistryImage) -> dict[str, Any]:
    lean_layers = lean.layer_digests
    ci_layers = ci.layer_digests
    ci_sizes = {
        str(layer["digest"]): int(layer.get("size") or 0) for layer in ci.manifest["layers"]
    }
    shared = [d for d in ci_layers if d in set(lean_layers)]
    ci_only = [d for d in ci_layers if d not in set(lean_layers)]
    lean_only = [d for d in lean_layers if d not in set(ci_layers)]
    return {
        "layer_digest_kind": "registry_compressed",
        "shared_layer_count": len(shared),
        "ci_only_layers": ci_only,
        "lean_only_layers": lean_only,
        "ci_extra_bytes": sum(ci_sizes[d] for d in ci_only),
        "lean_size_bytes": lean.size_bytes,
        "ci_size_bytes": ci.size_bytes,
        "note": "ci = lean + Postgres/DuckDB extras; used only for app-runs integration coverage",
    }


REQUIRED_RUNTIME_JOBS: tuple[str, ...] = ("lean-smoke", "app-runs")
DEFAULT_EXPECTED_JOBS: tuple[str, ...] = ("lean-raw", "lean-policy", "ci-raw")


@dataclass(frozen=True)
class WorkflowRun:
    run_id: int
    run_attempt: int
    event: str
    workflow_sha: str
    ref: str
    gate_mode: GateMode
    server_url: str = "https://github.com"
    head_sha: str | None = None  # PR head when `source_sha` is the synthetic merge commit
    job_results: dict[str, str] = field(default_factory=dict)  # job name -> GitHub result

    @property
    def trigger(self) -> Trigger:
        return Trigger(self.event)

    @property
    def runtime_verified(self) -> bool:
        """True only when every required runtime job is recorded and all recorded ones succeeded."""
        return all(j in self.job_results for j in REQUIRED_RUNTIME_JOBS) and all(
            r == "success" for r in self.job_results.values()
        )

    def url(self, repo: str) -> str:
        return f"{self.server_url}/{repo}/actions/runs/{self.run_id}/attempts/{self.run_attempt}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "event": self.event,
            "workflow_sha": self.workflow_sha,
            "ref": self.ref,
            "scan_gate_mode": self.gate_mode.value,
            "head_sha": self.head_sha,
            "job_results": dict(sorted(self.job_results.items())),
            "runtime_verified": self.runtime_verified,
        }


def write_scan_manifest(
    out: Path,
    *,
    source_repo: str,
    source_branch: str,
    source_sha: str,
    platform: str,
    images: dict[ImageTarget, RegistryImage],
    run: WorkflowRun,
    expected_jobs: tuple[str, ...] = DEFAULT_EXPECTED_JOBS,
    gate_files: dict[str, Path] | None = None,
    attach_dirs: tuple[str, ...] = (),
    controller_sha: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Aggregate `<out>/<target>/<mode>/` job dirs into `<out>/manifest.json` + `SHA256SUMS`.

    Every expected job must be present, load (checksums, VEX, tool pins) and describe exactly the
    digest the build job pushed for its target; otherwise the run is incomplete and nothing is
    written. The result is the same shape as the committed baseline manifest so the controller
    ingests fixture and CI runs through one loader."""
    jobs: dict[str, ScanJobEvidence] = {}
    for name in expected_jobs:
        target, mode = name.split("-", 1)
        job_dir = out / target / mode
        if not (job_dir / "job.json").is_file():
            raise EvidenceError(
                f"{name}: missing evidence at {job_dir} (job failed or not uploaded)"
            )
        job = load_scan_job(job_dir)
        image = images.get(ImageTarget(target))
        if image is None:
            raise EvidenceError(f"{name}: no registry metadata for image target {target}")
        if job.image_ref.rsplit("@", 1)[-1] != image.digest:
            raise EvidenceError(f"{name}: scanned {job.image_ref}, build pushed {image.digest}")
        if job.mode.value != mode or job.image_target.value != target:
            raise EvidenceError(f"{name}: job.json says {job.image_target}/{job.mode}")
        if job.platform != platform:
            raise EvidenceError(f"{name}: platform {job.platform} != {platform}")
        jobs[name] = job

    files: dict[str, str] = {}
    job_entries: dict[str, Any] = {}
    for name, job in jobs.items():
        target, mode = name.split("-", 1)
        raw = json.loads((job.path / "job.json").read_text())
        job_entries[name] = raw
        for f, digest in raw["files"].items():
            files[f"{target}/{mode}/{f}"] = digest
        for f in ("job.json", "SHA256SUMS"):
            files[f"{target}/{mode}/{f}"] = sha256_file(job.path / f)
    gates: dict[str, Any] = {}
    for name, gate_path in (gate_files or {}).items():
        gated_job = jobs.get(name)
        if gated_job is None:
            raise EvidenceError(f"gate {name}: no scan job of that name in this run")
        gate = json.loads(gate_path.read_text())
        if not isinstance(gate, dict):
            raise EvidenceError(f"gate {name}: {gate_path} is not a JSON object")
        if gate.get("image_ref") != gated_job.image_ref:
            raise EvidenceError(
                f"gate {name}: verdict is for {gate.get('image_ref')}, "
                f"job scanned {gated_job.image_ref}"
            )
        if gate.get("image_target") != gated_job.image_target.value:
            raise EvidenceError(f"gate {name}: image_target {gate.get('image_target')!r} != {name}")
        if gate.get("mode") != run.gate_mode.value:
            raise EvidenceError(
                f"gate {name}: evaluated in {gate.get('mode')!r}, run is {run.gate_mode.value}"
            )
        gates[name] = gate
        rel = gate_path.relative_to(out).as_posix()
        files[rel] = sha256_file(gate_path)
    attachments: dict[str, list[str]] = {}
    for rel_dir in attach_dirs:
        base = out / rel_dir
        if not base.is_dir():
            raise EvidenceError(f"attach {rel_dir}: {base} is not a directory under {out}")
        listed: list[str] = []
        for f in sorted(p for p in base.rglob("*") if p.is_file()):
            rel = f.relative_to(out).as_posix()
            files[rel] = sha256_file(f)
            listed.append(rel)
        if not listed:
            raise EvidenceError(f"attach {rel_dir}: no files under {base}")
        attachments[rel_dir] = listed
    if controller_sha is not None and not re.fullmatch(r"[0-9a-f]{40}", controller_sha):
        raise EvidenceError(f"controller sha {controller_sha!r} is not a full commit sha")

    lean, ci = images.get(ImageTarget.lean), images.get(ImageTarget.ci)
    manifest: dict[str, Any] = {
        "schema": SCAN_MANIFEST_SCHEMA,
        "source_repo": source_repo,
        "source_branch": source_branch,
        "source_sha": source_sha,
        "trigger": run.trigger.value,
        "platform": platform,
        "built_at": min(j.started_at for j in jobs.values()).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "captured_at": (now or datetime.now(UTC)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run": run.to_dict() | {"url": run.url(source_repo)},
        "images": {
            t.value: img.to_dict() for t, img in sorted(images.items(), key=lambda kv: kv[0].value)
        },
        "ci_layer_delta": layer_delta(lean, ci) if lean and ci else {},
        "gates": gates,
        "jobs": job_entries,
        "attachments": attachments,
        "controller_sha": controller_sha,
        "files": files,
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    with (out / "SHA256SUMS").open("w") as fh:
        for rel, digest in sorted(files.items()):
            fh.write(f"{digest}  {rel}\n")
        fh.write(f"{sha256_file(out / 'manifest.json')}  manifest.json\n")
    return manifest


def load_registry_image(
    target: ImageTarget, tag: str, digest: str, manifest_path: Path, config_path: Path
) -> RegistryImage:
    manifest = json.loads(manifest_path.read_text())
    config = json.loads(config_path.read_text())
    if not isinstance(manifest, dict) or "layers" not in manifest:
        raise EvidenceError(
            f"{manifest_path}: not a single-platform image manifest (got an index?)"
        )
    if not isinstance(config, dict):
        raise EvidenceError(f"{config_path}: expected an image config object")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise EvidenceError(f"{target}: {digest!r} is not a sha256 digest")
    return RegistryImage(target=target, tag=tag, digest=digest, manifest=manifest, config=config)


__all__ = [
    "FORBIDDEN_IGNORE_FILES",
    "GateResult",
    "RegistryImage",
    "VexLintReport",
    "WorkflowRun",
    "find_ignore_files",
    "gate_job",
    "layer_delta",
    "lint_approved_vex",
    "load_registry_image",
    "policy_counts",
    "write_scan_manifest",
]
