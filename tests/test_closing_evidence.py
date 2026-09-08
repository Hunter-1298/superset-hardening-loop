"""Evidence pairing and per-job quality rules: a policy job may only speak for the image its raw
job scanned, and every job whose silence is read as absence must be pinned and fresh."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hardening_loop.config import (
    BASELINE_SHA,
    FORK_REPO,
    REMEDIATION_BRANCH,
    TRIVY_VERSION,
)
from hardening_loop.domain.enums import (
    Ecosystem,
    ImageTarget,
    Kind,
    Layer,
    ScanMode,
    Scanner,
    ScanRunStatus,
    Severity,
    Trigger,
)
from hardening_loop.models.tables import Finding, ScanJob, ScanRun
from hardening_loop.orchestrator.closer import validate_closing_run

OPENED_AT = datetime(2026, 9, 1, tzinfo=UTC)
FRESH = OPENED_AT + timedelta(days=1)


def _finding() -> Finding:
    return Finding(
        dedupe_key="t:CVE-2024-26130",
        vuln_id="CVE-2024-26130",
        purl="pkg:pypi/cryptography@42.0.2",
        pkg_name="cryptography",
        pkg_version="42.0.2",
        ecosystem=Ecosystem.pypi,
        layer=Layer.python,
        image_target=ImageTarget.lean,
        severity=Severity.high,
        kind=Kind.dependency_upgrade,
        platform="linux/amd64",
        reported_by_trivy=True,
        opened_by_trivy=True,
        opening_db_built_at=OPENED_AT,
    )


def _run() -> ScanRun:
    return ScanRun(
        id=1,
        external_run_id="gha:9",
        trigger=Trigger.push,
        source_repo=FORK_REPO,
        source_branch=REMEDIATION_BRANCH,
        source_sha=BASELINE_SHA,
        platform="linux/amd64",
        lean_digest="sha256:abc",
        status=ScanRunStatus.complete,
    )


def _job(name: str, mode: ScanMode, *, db_built_at: datetime | None = FRESH) -> ScanJob:
    return ScanJob(
        scan_run_id=1,
        name=name,
        scanner=Scanner.trivy,
        mode=mode,
        image_target=ImageTarget.lean,
        layer_scope="all",
        success=True,
        tool_version=TRIVY_VERSION,
        db_built_at=db_built_at,
    )


def _validate(jobs: list[ScanJob]) -> list[str]:
    return validate_closing_run(
        _run(),
        jobs,
        _finding(),
        merge_sha=None,
        is_ancestor=lambda _a, _b: True,
        require_policy=True,
    ).reasons


def test_fresh_raw_and_policy_jobs_close() -> None:
    assert _validate([_job("trivy-raw", ScanMode.raw), _job("trivy-policy", ScanMode.policy)]) == []


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"db_built_at": None}, "trivy-policy has no db timestamp"),
        ({"db_built_at": OPENED_AT - timedelta(days=7)}, "trivy-policy db"),
    ],
)
def test_stale_policy_job_cannot_close(kwargs: dict[str, datetime | None], message: str) -> None:
    jobs = [_job("trivy-raw", ScanMode.raw), _job("trivy-policy", ScanMode.policy, **kwargs)]
    assert any(message in r for r in _validate(jobs))


def test_outdated_policy_scanner_cannot_close() -> None:
    policy = _job("trivy-policy", ScanMode.policy)
    policy.tool_version = "0.1.0"
    reasons = _validate([_job("trivy-raw", ScanMode.raw), policy])
    assert any(f"trivy-policy 0.1.0 < pinned {TRIVY_VERSION}" in r for r in reasons)


def test_policy_job_of_another_image_cannot_close() -> None:
    policy = _job("trivy-policy", ScanMode.policy)
    policy.image_target = ImageTarget.ci
    reasons = _validate([_job("trivy-raw", ScanMode.raw), policy])
    assert any("trivy-policy scanned" in r for r in reasons)
