"""Golden tests over the committed, checksum-verified 6.1.0 baseline fixture.

Every number here was produced by scripts/capture_baseline.sh against
Hunter-1298/superset@c83fb2bb (lean image sha256:e3a88c34...) with the pinned Syft 1.45.1,
Trivy 0.71.2 and Grype 0.114.0. They are exact on purpose: the fixture is immutable evidence.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from packaging.specifiers import SpecifierSet
from sqlmodel import select

from hardening_loop.classify.group import group_findings
from hardening_loop.classify.rules import ClassificationContext, classify, parse_upper_bounds
from hardening_loop.config import BASELINE_SHA, FORK_REPO
from hardening_loop.db import open_database, session_scope
from hardening_loop.domain.enums import Ecosystem, Kind, Layer, Risk, ScanMode, Scanner, Severity
from hardening_loop.ingest.evidence import BaselineManifest, EvidenceError, load_baseline
from hardening_loop.ingest.normalize import normalize
from hardening_loop.ingest.persist import ingest_baseline
from hardening_loop.models.tables import Finding, ScanJob, ScanRun, Sighting

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "baseline" / BASELINE_SHA
LEAN_IMAGE_ID = "sha256:e3a88c342786852cf0916ea99bc973f4a1feff46e44dfe6ceae4ad8b546df29c"
CI_IMAGE_ID = "sha256:d275b3e60184637bd75dd24853403aaae8296b23d14355bb341531e5c190cd8f"

# Upper bounds from Superset 6.1.0 pyproject.toml that matter for the baseline findings.
UPPER_BOUNDS: dict[str, SpecifierSet] = parse_upper_bounds(
    """
[project]
dependencies = [
    "cryptography>=42.0.4, <45.0.0",
    "msgpack>=1.0.0, <1.1",
    "pyarrow>=14.0.1, <22",
    "pillow>=10.3.0",
]
"""
)


@pytest.fixture(scope="module")
def manifest() -> BaselineManifest:
    return load_baseline(FIXTURE)


def test_manifest_identity(manifest: BaselineManifest) -> None:
    assert manifest.source_repo == FORK_REPO
    assert manifest.source_sha == BASELINE_SHA
    assert manifest.platform == "linux/amd64"
    assert manifest.images["lean"]["image_id"] == LEAN_IMAGE_ID
    assert manifest.images["ci"]["image_id"] == CI_IMAGE_ID
    assert manifest.images["lean"]["labels"]["org.opencontainers.image.revision"] == BASELINE_SHA
    assert manifest.ci_layer_delta["shared_layer_count"] == 29
    assert len(manifest.ci_layer_delta["ci_only_layers"]) == 1
    assert manifest.ci_layer_delta["ci_extra_bytes"] == 532_979_658
    assert set(manifest.jobs) == {"lean-raw", "lean-policy"}
    for job in manifest.jobs.values():
        assert job.image_ref == f"docker:{LEAN_IMAGE_ID}"
        assert job.tools.syft == "1.45.1"
        assert job.tools.trivy == "0.71.2"
        assert job.tools.grype == "0.114.0"
        assert job.tools.trivy_db_updated_at is not None
        assert job.tools.grype_db_built_at is not None
    assert manifest.jobs["lean-raw"].mode is ScanMode.raw
    assert manifest.jobs["lean-policy"].mode is ScanMode.policy
    assert manifest.jobs["lean-policy"].vex_documents == []


def test_checksums_cover_every_evidence_file() -> None:
    listed = {
        line.split("  ", 1)[1]
        for line in (FIXTURE / "SHA256SUMS").read_text().splitlines()
        if line.strip()
    }
    on_disk = {
        str(p.relative_to(FIXTURE))
        for p in FIXTURE.rglob("*")
        if p.is_file() and p != FIXTURE / "SHA256SUMS"
    }
    assert listed == on_disk
    for rel in listed:
        expected = next(
            line.split("  ", 1)[0]
            for line in (FIXTURE / "SHA256SUMS").read_text().splitlines()
            if line.endswith("  " + rel)
        )
        assert hashlib.sha256((FIXTURE / rel).read_bytes()).hexdigest() == expected


def test_tampered_evidence_is_rejected(tmp_path: Path) -> None:
    import shutil

    copy = tmp_path / BASELINE_SHA
    shutil.copytree(FIXTURE, copy)
    target = copy / "lean" / "raw" / "trivy-vuln.json"
    report = json.loads(target.read_text())
    report["Results"][0]["Vulnerabilities"] = []  # "hide" findings
    target.write_text(json.dumps(report))
    with pytest.raises(EvidenceError):
        load_baseline(copy)


def test_raw_parse_counts(manifest: BaselineManifest) -> None:
    raw = manifest.jobs["lean-raw"]
    assert len(raw.sbom) == 7008
    assert Counter(c.ecosystem for c in raw.sbom)[Ecosystem.pypi] == 197
    assert Counter(c.ecosystem for c in raw.sbom)[Ecosystem.deb] == 126

    assert len(raw.trivy_vulns) == 1044
    assert Counter(v.ecosystem for v in raw.trivy_vulns) == {Ecosystem.deb: 982, Ecosystem.pypi: 62}
    assert len(raw.grype_vulns) == 468
    assert Counter(v.ecosystem for v in raw.grype_vulns) == {
        Ecosystem.deb: 365,
        Ecosystem.pypi: 62,
        Ecosystem.binary: 41,
    }
    assert len(raw.image_config) == 1
    assert len(raw.iac_config) == 58
    assert Counter(c.layer for c in raw.configs) == {Layer.helm: 58, Layer.dockerfile: 1}
    # Raw records are preserved verbatim.
    assert all(v.record for v in raw.trivy_vulns)
    assert all(v.record for v in raw.grype_vulns)


def test_policy_without_vex_equals_raw(manifest: BaselineManifest) -> None:
    raw, pol = manifest.jobs["lean-raw"], manifest.jobs["lean-policy"]
    assert {v.dedupe_key for v in raw.trivy_vulns} == {v.dedupe_key for v in pol.trivy_vulns}
    assert {v.dedupe_key for v in raw.grype_vulns} == {v.dedupe_key for v in pol.grype_vulns}


def test_normalize_dedupes_across_scanners(manifest: BaselineManifest) -> None:
    raw = manifest.jobs["lean-raw"]
    findings = normalize(raw.vulns, raw.configs)
    assert len(findings) == 1141
    by_reporters = Counter(frozenset(f.reported_by) for f in findings)
    assert by_reporters == {
        frozenset({Scanner.trivy, Scanner.grype}): 424,
        frozenset({Scanner.trivy}): 617 + 59,  # 617 vulns + 59 config findings (trivy-only)
        frozenset({Scanner.grype}): 41,
    }
    assert Counter(f.severity for f in findings) == {
        Severity.critical: 22,
        Severity.high: 209,
        Severity.medium: 555,
        Severity.low: 278,
        Severity.unknown: 77,
    }
    # Every python-package finding is seen by both scanners (62 raw records each -> 59 unique).
    py = [f for f in findings if f.ecosystem is Ecosystem.pypi]
    assert len(py) == 59
    assert all(f.reported_by == frozenset({Scanner.trivy, Scanner.grype}) for f in py)
    # GHSA/CVE canonicalisation: a GHSA id survives only when neither scanner offered a CVE alias.
    ghsa = sorted(f.vuln_id for f in findings if f.vuln_id.startswith("GHSA-"))
    assert ghsa == ["GHSA-537c-gmf6-5ccf", "GHSA-6v7p-g79w-8964"]
    # Scanner-specific severities are retained, disagreements are counted not hidden.
    assert sum(f.severity_disagreement for f in findings) == 109


def test_classification_is_total_and_disjoint(manifest: BaselineManifest) -> None:
    raw = manifest.jobs["lean-raw"]
    findings = normalize(raw.vulns, raw.configs)
    ctx = ClassificationContext({Scanner.trivy: True, Scanner.grype: True}, UPPER_BOUNDS)
    classified = [(f, classify(f, ctx)) for f in findings]
    assert Counter(c.kind for _, c in classified) == {
        Kind.dependency_upgrade: 58,
        Kind.no_fix_reachability: 297,
        Kind.container_hardening: 111,
        Kind.scanner_disagreement: 617,
        Kind.helm_deploy_config: 58,
    }
    assert not [f for f, c in classified if c.kind is None]

    blocked = {f.pkg_name for f, c in classified if c.bound_blocked}
    assert blocked == {"cryptography", "msgpack", "pyarrow"}
    assert all(c.risk is Risk.high for _, c in classified if c.bound_blocked)
    assert all(c.kind is Kind.dependency_upgrade for _, c in classified if c.bound_blocked)

    # The CPython binary is Grype-only but Trivy cannot see it => never a disagreement: 36 of its
    # CVEs have a fixed interpreter release (kind 3), 5 have none yet (kind 2).
    python = Counter(c.kind for f, c in classified if f.pkg_name == "python")
    assert python == {Kind.container_hardening: 36, Kind.no_fix_reachability: 5}
    # Debian "will not fix" and "no fix yet" both land in kind 2, never kind 1/3.
    for f, c in classified:
        if c.kind is Kind.no_fix_reachability:
            assert not f.has_fix

    candidates, unclassified = group_findings(classified)
    assert unclassified == []
    assert Counter(c.kind for c in candidates) == {
        Kind.dependency_upgrade: 19,
        Kind.no_fix_reachability: 53,
        Kind.container_hardening: 3,
        Kind.scanner_disagreement: 7,
        Kind.helm_deploy_config: 1,
    }
    keys = {c.group_key for c in candidates}
    assert "pypi:cryptography" in keys
    assert "pypi:pillow" in keys
    assert "nofix:pypi:paramiko" in keys
    assert "container:dockerfile" in keys
    assert "container:binary-packages" in keys
    assert "disagreement:deb:linux-libc-dev" in keys
    assert "deploy:helm" in keys
    lld = next(c for c in candidates if c.group_key == "disagreement:deb:linux-libc-dev")
    assert len(lld.members) == 608
    assert all(m.reported_by == frozenset({Scanner.trivy}) for m in lld.members)


def test_ingest_baseline_into_sqlite(tmp_path: Path, manifest: BaselineManifest) -> None:
    engine = open_database(tmp_path / "loop.db")
    result = ingest_baseline(engine, manifest, upper_bounds=UPPER_BOUNDS)
    assert result.created
    assert result.findings_total == result.findings_new == 1141
    assert result.unclassified == 0
    assert result.policy_suppressed == 0
    assert result.findings_by_kind == {"1": 58, "2": 297, "3": 111, "4": 617, "5": 58}

    again = ingest_baseline(engine, manifest, upper_bounds=UPPER_BOUNDS)
    assert not again.created
    assert again.scan_run_id == result.scan_run_id

    with session_scope(engine) as db:
        run = db.exec(select(ScanRun)).one()
        assert run.is_baseline
        assert run.source_sha == BASELINE_SHA
        assert run.lean_digest == LEAN_IMAGE_ID
        assert run.ci_digest == CI_IMAGE_ID
        jobs = {j.name: j for j in db.exec(select(ScanJob)).all()}
        assert set(jobs) == {
            "trivy-raw",
            "grype-raw",
            "config-raw",
            "trivy-policy",
            "grype-policy",
            "config-policy",
        }
        assert all(j.success for j in jobs.values())
        assert jobs["trivy-raw"].counts == {
            "CRITICAL": 4,
            "HIGH": 175,
            "MEDIUM": 549,
            "LOW": 237,
            "UNKNOWN": 79,
        }
        assert jobs["grype-raw"].counts == {
            "CRITICAL": 21,
            "HIGH": 124,
            "MEDIUM": 124,
            "LOW": 133,
            "UNKNOWN": 66,
        }
        findings = db.exec(select(Finding)).all()
        assert len(findings) == 1141
        sightings = db.exec(select(Sighting)).all()
        # one raw + one policy sighting per (finding, scanner) pair
        raw_s = [s for s in sightings if s.mode is ScanMode.raw]
        pol_s = [s for s in sightings if s.mode is ScanMode.policy]
        assert len(raw_s) == len(pol_s) == 1565
        assert all(s.present for s in sightings)
