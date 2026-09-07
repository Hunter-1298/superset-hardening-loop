"""Load a scan evidence directory (as written by scripts/scan_image.sh / capture_baseline.sh).

Every file is checksum-verified against job.json before it is parsed; a mismatch is an error, not a
warning, because these files are the only proof a finding was (or was not) present.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hardening_loop.domain.enums import ImageTarget, ScanMode, Scanner
from hardening_loop.ingest.grype import grype_db_built_at, parse_grype_vulns
from hardening_loop.ingest.records import RawConfigFinding, RawVuln, SbomComponent
from hardening_loop.ingest.sbom import parse_cyclonedx
from hardening_loop.ingest.trivy import parse_trivy_misconfigs, parse_trivy_vulns

JOB_SCHEMA = "hardening-loop/scan-job/v1"
MANIFEST_SCHEMA = "hardening-loop/baseline-manifest/v1"


class EvidenceError(ValueError):
    pass


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ToolVersions(BaseModel):
    model_config = ConfigDict(frozen=True)

    syft: str
    trivy: str
    grype: str
    trivy_db_updated_at: datetime | None
    grype_db_built_at: datetime | None


class ScanJobEvidence(BaseModel):
    """One `scan_image.sh` output directory, verified and parsed."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    path: Path
    mode: ScanMode
    image_ref: str
    image_target: ImageTarget
    platform: str
    layer_scope: str
    started_at: datetime
    finished_at: datetime
    files: dict[str, str]
    vex_documents: list[dict[str, str]]
    tools: ToolVersions
    sbom: list[SbomComponent]
    trivy_vulns: list[RawVuln]
    grype_vulns: list[RawVuln]
    image_config: list[RawConfigFinding]
    iac_config: list[RawConfigFinding]
    raw_reports: dict[str, dict[str, Any]] = Field(default_factory=dict)

    @property
    def vulns(self) -> list[RawVuln]:
        return [*self.trivy_vulns, *self.grype_vulns]

    @property
    def configs(self) -> list[RawConfigFinding]:
        return [*self.image_config, *self.iac_config]

    @property
    def scanners_present(self) -> set[Scanner]:
        return {Scanner.trivy, Scanner.grype}

    def evidence_ref(self, name: str) -> str:
        return f"{self.path.name}/{name}@sha256:{self.files[name]}"


def _parse_ts(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("rb") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise EvidenceError(f"{path}: expected a JSON object")
    return data


def _verify_files(root: Path, expected: dict[str, str]) -> None:
    for name, digest in expected.items():
        p = root / name
        if not p.is_file():
            raise EvidenceError(f"missing evidence file {p}")
        actual = sha256_file(p)
        if actual != digest:
            raise EvidenceError(f"checksum mismatch for {p}: {actual} != {digest}")


def load_scan_job(path: Path) -> ScanJobEvidence:
    job = _load_json(path / "job.json")
    if job.get("schema") != JOB_SCHEMA:
        raise EvidenceError(f"{path}: unexpected job schema {job.get('schema')!r}")
    files: dict[str, str] = dict(job["files"])
    _verify_files(path, files)

    tools = job["tools"]
    trivy_db = (tools["trivy"].get("vuln_db") or {}).get("UpdatedAt")
    grype_report = _load_json(path / "grype-vuln.json")
    grype_built = grype_db_built_at(grype_report)
    versions = ToolVersions(
        syft=tools["syft"]["version"],
        trivy=tools["trivy"]["version"],
        grype=tools["grype"]["version"],
        trivy_db_updated_at=_parse_ts(trivy_db) if trivy_db else None,
        grype_db_built_at=_parse_ts(grype_built) if grype_built else None,
    )

    sbom_doc = _load_json(path / "sbom.cdx.json")
    trivy_vuln = _load_json(path / "trivy-vuln.json")
    trivy_image_config = _load_json(path / "trivy-image-config.json")
    trivy_config = _load_json(path / "trivy-config.json")

    return ScanJobEvidence(
        path=path,
        mode=ScanMode(job["mode"]),
        image_ref=job["image_ref"],
        image_target=ImageTarget(job["image_target"]),
        platform=job["platform"],
        layer_scope=job["layer_scope"],
        started_at=_parse_ts(job["started_at"]),
        finished_at=_parse_ts(job["finished_at"]),
        files=files,
        vex_documents=list(job.get("vex_documents") or []),
        tools=versions,
        sbom=parse_cyclonedx(sbom_doc),
        trivy_vulns=parse_trivy_vulns(trivy_vuln),
        grype_vulns=parse_grype_vulns(grype_report),
        image_config=parse_trivy_misconfigs(trivy_image_config, image_ref=job["image_ref"]),
        iac_config=parse_trivy_misconfigs(trivy_config),
        raw_reports={
            "trivy-vuln.json": trivy_vuln,
            "grype-vuln.json": grype_report,
            "trivy-image-config.json": trivy_image_config,
            "trivy-config.json": trivy_config,
        },
    )


class BaselineManifest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    path: Path
    source_repo: str
    source_branch: str
    source_sha: str
    trigger: str
    platform: str
    built_at: datetime
    captured_at: datetime
    images: dict[str, dict[str, Any]]
    ci_layer_delta: dict[str, Any]
    jobs: dict[str, ScanJobEvidence]

    @property
    def lean_image_id(self) -> str:
        return str(self.images["lean"]["image_id"])


def load_baseline(path: Path) -> BaselineManifest:
    manifest = _load_json(path / "manifest.json")
    if manifest.get("schema") != MANIFEST_SCHEMA:
        raise EvidenceError(f"{path}: unexpected manifest schema {manifest.get('schema')!r}")
    _verify_files(path, dict(manifest["files"]))
    sums = (path / "SHA256SUMS").read_text().splitlines()
    listed = {line.split("  ", 1)[1]: line.split("  ", 1)[0] for line in sums if "  " in line}
    if listed.get("manifest.json") != sha256_file(path / "manifest.json"):
        raise EvidenceError(f"{path}: manifest.json does not match SHA256SUMS")

    jobs: dict[str, ScanJobEvidence] = {}
    for name in manifest["jobs"]:
        target, mode = name.split("-", 1)
        job = load_scan_job(path / target / mode)
        if (
            job.image_ref != f"docker:{manifest['images'][target]['image_id']}"
            and not job.image_ref.endswith(manifest["images"][target]["image_id"])
        ):
            raise EvidenceError(
                f"{name}: scanned {job.image_ref}, manifest says {manifest['images'][target]}"
            )
        jobs[name] = job

    return BaselineManifest(
        path=path,
        source_repo=manifest["source_repo"],
        source_branch=manifest["source_branch"],
        source_sha=manifest["source_sha"],
        trigger=manifest["trigger"],
        platform=manifest["platform"],
        built_at=_parse_ts(manifest["built_at"]),
        captured_at=_parse_ts(manifest["captured_at"]),
        images=manifest["images"],
        ci_layer_delta=manifest["ci_layer_delta"],
        jobs=jobs,
    )
