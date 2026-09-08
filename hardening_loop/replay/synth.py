"""Synthetic scan evidence for replay. Builds `ScanJobEvidence` objects in memory (no files) with
realistic-looking records so every classifier rule and closure path can be exercised without a
build, a scanner, or the network. Vulnerability IDs here are illustrative, not authoritative."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from sqlalchemy.engine import Engine

from hardening_loop.config import GRYPE_VERSION, SYFT_VERSION, TRIVY_VERSION
from hardening_loop.db import session_scope
from hardening_loop.domain.enums import (
    Ecosystem,
    GateMode,
    ImageTarget,
    Layer,
    ScanMode,
    Scanner,
    Severity,
    Trigger,
)
from hardening_loop.ingest.evidence import ScanJobEvidence, ToolVersions
from hardening_loop.ingest.persist import IngestResult, RunMeta, ingest_run
from hardening_loop.ingest.records import RawConfigFinding, RawVuln, SbomComponent

FORK_REPO = "Hunter-1298/superset"
BASELINE_SHA = "c83fb2bb1dcfac41ac51bcebd82471f4a7180d18"
PLATFORM = "linux/amd64"
T0 = datetime(2026, 9, 1, 0, 0, tzinfo=UTC)


@dataclass(frozen=True)
class Seed:
    """One synthetic vulnerable component, reported by the given scanners."""

    key: str
    pkg_name: str
    pkg_version: str
    ecosystem: Ecosystem
    layer: Layer
    vulns: tuple[tuple[str, Severity, tuple[str, ...]], ...]  # (id, severity, fixed_versions)
    reported_by: frozenset[Scanner] = frozenset({Scanner.trivy, Scanner.grype})
    fix_state: str = "fixed"

    def with_version(self, version: str) -> Seed:
        return replace(self, pkg_version=version)


@dataclass(frozen=True)
class ConfigSeed:
    key: str
    rule_id: str
    resource: str
    layer: Layer
    severity: Severity
    title: str
    kind: str = "iac"  # iac | image_config


SEEDS: dict[str, Seed] = {
    s.key: s
    for s in (
        Seed(
            key="cryptography",
            pkg_name="cryptography",
            pkg_version="42.0.2",
            ecosystem=Ecosystem.pypi,
            layer=Layer.python,
            vulns=(("CVE-2024-26130", Severity.high, ("42.0.4",)),),
        ),
        Seed(
            key="pillow",
            pkg_name="pillow",
            pkg_version="10.2.0",
            ecosystem=Ecosystem.pypi,
            layer=Layer.python,
            vulns=(
                ("CVE-2024-28219", Severity.critical, ("10.3.0",)),
                ("CVE-2023-50447", Severity.critical, ("10.2.1", "10.3.0")),
            ),
        ),
        Seed(
            key="requests",
            pkg_name="requests",
            pkg_version="2.31.0",
            ecosystem=Ecosystem.pypi,
            layer=Layer.python,
            vulns=(("CVE-2024-35195", Severity.medium, ("2.32.0",)),),
        ),
        Seed(
            key="paramiko",
            pkg_name="paramiko",
            pkg_version="3.4.0",
            ecosystem=Ecosystem.pypi,
            layer=Layer.python,
            vulns=(("CVE-2023-48795", Severity.high, ()),),
            fix_state="affected",
        ),
        Seed(
            key="libexpat1",
            pkg_name="libexpat1",
            pkg_version="2.5.0-1",
            ecosystem=Ecosystem.deb,
            layer=Layer.os,
            vulns=(("CVE-2024-45490", Severity.high, ("2.5.0-1+deb12u1",)),),
        ),
        Seed(
            key="linux-libc-dev",
            pkg_name="linux-libc-dev",
            pkg_version="6.1.90-1",
            ecosystem=Ecosystem.deb,
            layer=Layer.os,
            vulns=(("CVE-2024-40971", Severity.high, ()),),
            reported_by=frozenset({Scanner.trivy}),
            fix_state="affected",
        ),
    )
}

CONFIG_SEEDS: dict[str, ConfigSeed] = {
    c.key: c
    for c in (
        ConfigSeed(
            key="helm-run-as-root",
            rule_id="AVD-KSV-0012",
            resource="helm/superset/templates/deployment.yaml",
            layer=Layer.helm,
            severity=Severity.high,
            title="Runs as root user",
        ),
        ConfigSeed(
            key="dockerfile-root",
            rule_id="AVD-DS-0002",
            resource="Dockerfile",
            layer=Layer.dockerfile,
            severity=Severity.high,
            title="Image user should not be 'root'",
        ),
        ConfigSeed(
            key="image-no-healthcheck",
            rule_id="AVD-DS-0026",
            resource="image-config",
            layer=Layer.dockerfile,
            severity=Severity.low,
            title="No HEALTHCHECK defined",
            kind="image_config",
        ),
    )
}


def _purl(seed: Seed) -> str:
    if seed.ecosystem is Ecosystem.pypi:
        return f"pkg:pypi/{seed.pkg_name}@{seed.pkg_version}"
    return f"pkg:deb/debian/{seed.pkg_name}@{seed.pkg_version}?distro=debian-12"


def _vulns(seed: Seed, scanner: Scanner) -> list[RawVuln]:
    if scanner not in seed.reported_by:
        return []
    out: list[RawVuln] = []
    for vid, sev, fixes in seed.vulns:
        out.append(
            RawVuln(
                scanner=scanner,
                primary_id=vid if scanner is Scanner.trivy else f"GHSA-{vid[-4:]}-fake-{seed.key}",
                aliases=[] if scanner is Scanner.trivy else [vid],
                pkg_name=seed.pkg_name,
                pkg_version=seed.pkg_version,
                purl=_purl(seed),
                ecosystem=seed.ecosystem,
                layer=seed.layer,
                severity=sev,
                fixed_versions=list(fixes),
                fix_state=seed.fix_state if not fixes else "fixed",
                title=f"{seed.pkg_name}: {vid}",
                location=None,
                record={"synthetic": True, "scanner": scanner.value, "id": vid},
            )
        )
    return out


def _config(seed: ConfigSeed) -> RawConfigFinding:
    return RawConfigFinding(
        scanner=Scanner.trivy,
        rule_id=seed.rule_id,
        resource=seed.resource,
        layer=seed.layer,
        severity=seed.severity,
        title=seed.title,
        message=seed.title,
        fix_available=True,
        record={"synthetic": True, "rule": seed.rule_id},
    )


@dataclass
class SyntheticRun:
    """Describe a scan run: which seeds are present, which jobs succeeded, which VEX applies."""

    source_sha: str
    seeds: list[Seed] = field(default_factory=list)
    configs: list[ConfigSeed] = field(default_factory=list)
    policy_suppressed_keys: set[str] = field(default_factory=set)
    vex_documents: list[dict[str, Any]] = field(default_factory=list)
    job_success: dict[str, bool] = field(
        default_factory=lambda: {"trivy": True, "grype": True, "config": True}
    )
    policy_job_success: dict[str, bool] | None = None
    trigger: Trigger = Trigger.replay
    source_branch: str = "main"
    source_repo: str = FORK_REPO
    image_target: ImageTarget = ImageTarget.lean
    platform: str = PLATFORM
    at: datetime = T0
    tool_versions: tuple[str, str, str] = (SYFT_VERSION, TRIVY_VERSION, GRYPE_VERSION)
    db_age: timedelta | None = timedelta(hours=1)  # None: run publishes no db timestamp
    gate_mode: GateMode = GateMode.report
    is_baseline: bool = False
    run_attempt: int = 1

    def with_seeds(self, *keys: str) -> SyntheticRun:
        self.seeds = [SEEDS[k] for k in keys]
        return self

    def with_configs(self, *keys: str) -> SyntheticRun:
        self.configs = [CONFIG_SEEDS[k] for k in keys]
        return self

    # ---------------------------------------------------------------- evidence

    def _job(self, mode: ScanMode) -> ScanJobEvidence:
        seeds = self.seeds
        configs = self.configs
        if mode is ScanMode.policy:
            seeds = [s for s in seeds if s.key not in self.policy_suppressed_keys]
            configs = [c for c in configs if c.key not in self.policy_suppressed_keys]
        success = (
            self.job_success
            if mode is ScanMode.raw
            else (self.policy_job_success or dict(self.job_success))
        )
        trivy = [v for s in seeds for v in _vulns(s, Scanner.trivy)] if success["trivy"] else []
        grype = [v for s in seeds for v in _vulns(s, Scanner.grype)] if success["grype"] else []
        iac = [_config(c) for c in configs if c.kind == "iac"] if success["config"] else []
        image_config = (
            [_config(c) for c in configs if c.kind == "image_config"] if success["config"] else []
        )
        image_id = f"sha256:{'0' * 24}{self.source_sha[:40]}"
        db_at = None if self.db_age is None else self.at - self.db_age
        return ScanJobEvidence(
            path=Path(f"replay://{self.source_sha[:12]}/{mode.value}"),
            mode=mode,
            image_ref=image_id,
            image_target=self.image_target,
            platform=self.platform,
            layer_scope="image",
            started_at=self.at,
            finished_at=self.at + timedelta(minutes=5),
            files={},
            vex_documents=list(self.vex_documents) if mode is ScanMode.policy else [],
            tools=ToolVersions(
                syft=self.tool_versions[0],
                trivy=self.tool_versions[1],
                grype=self.tool_versions[2],
                trivy_db_updated_at=db_at,
                grype_db_built_at=db_at,
            ),
            sbom=[
                SbomComponent(
                    name=s.pkg_name,
                    version=s.pkg_version,
                    purl=_purl(s),
                    component_type="library",
                    ecosystem=s.ecosystem,
                )
                for s in self.seeds
            ],
            trivy_vulns=trivy,
            grype_vulns=grype,
            image_config=image_config,
            iac_config=iac,
            job_success=dict(success),
        )

    def jobs(self) -> dict[str, ScanJobEvidence]:
        return {"lean/raw": self._job(ScanMode.raw), "lean/policy": self._job(ScanMode.policy)}

    def meta(self, external_run_id: str) -> RunMeta:
        return RunMeta(
            external_run_id=external_run_id,
            trigger=self.trigger,
            source_repo=self.source_repo,
            source_branch=self.source_branch,
            source_sha=self.source_sha,
            platform=self.platform,
            lean_digest=f"sha256:{'0' * 24}{self.source_sha[:40]}",
            ci_digest=None,
            ci_layer_delta=None,
            started_at=self.at,
            finished_at=self.at + timedelta(minutes=6),
            is_baseline=self.is_baseline,
            run_attempt=self.run_attempt,
            scan_gate_mode=self.gate_mode,
        )


def ingest_synthetic(engine: Engine, run: SyntheticRun, external_run_id: str) -> IngestResult:
    with session_scope(engine) as db:
        return ingest_run(db, run.meta(external_run_id), run.jobs(), upper_bounds={}, now=run.at)


def approved_vex(
    *,
    issue_url: str,
    vuln_id: str,
    purl: str,
    approver: str,
    approved_at: str = "2026-09-01T12:00:00Z",
) -> dict[str, Any]:
    """OpenVEX document as it would appear under security/vex/approved/ (passes `vex-lint`)."""
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/{FORK_REPO}/security/vex/approved/{vuln_id.lower()}.json",
        "author": approver,
        "timestamp": approved_at,
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": vuln_id},
                "products": [{"@id": purl}],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": (
                    f"{vuln_id}: the vulnerable code path is not reachable from Superset's "
                    "runtime; see the reachability analysis attached to the approval issue."
                ),
            }
        ],
        "x-approval": {
            "issue_url": issue_url,
            "approved_by": approver,
            "approved_at": approved_at,
        },
    }
