"""Pure policy checks: PR diff policy, dispatch eligibility, PR identity verification."""

from __future__ import annotations

import re
from collections.abc import Iterable

from hardening_loop.config import FORK_REPO, REMEDIATION_BRANCH, REPO_ALLOWLIST
from hardening_loop.domain.enums import HumanLabel, Kind, Severity
from hardening_loop.github.protocol import DiffFile, PullRequestInfo

IGNORE_FILE_NAMES = frozenset(
    {".trivyignore", ".trivyignore.yaml", ".trivyignore.yml", ".grype.yaml", ".grype.yml"}
)
PROTECTED_PATHS = (
    ".github/workflows/security-scan.yml",
    ".github/workflows/app-runs.yml",
    ".github/workflows/lean-smoke.yml",
    ".github/workflows/install-scanners.yml",
    ".github/workflows/vex-lint.yml",
)
GENERATED_REQUIREMENTS = re.compile(r"^requirements/.*\.txt$")
REQUIREMENT_SOURCES = re.compile(r"^(pyproject\.toml|requirements/.*\.in)$")
VEX_APPROVED = re.compile(r"^security/vex/approved/")
VEX_PROPOSED = re.compile(r"^security/vex/proposed/.*\.json$")

PR_URL_RE = re.compile(r"^https://github\.com/(?P<repo>[^/]+/[^/]+)/pull/(?P<number>\d+)$")


def diff_policy_violations(files: Iterable[DiffFile], kind: Kind) -> list[str]:
    names = [f.filename for f in files]
    violations: list[str] = []
    for n in names:
        base = n.rsplit("/", 1)[-1]
        if base in IGNORE_FILE_NAMES or n.startswith(".grype/") or "/.grype/" in n:
            violations.append(f"scanner ignore file: {n}")
        if n in PROTECTED_PATHS or n.startswith("ci-negative/"):
            violations.append(f"protected CI path modified: {n}")
        if VEX_APPROVED.match(n):
            violations.append(f"approved VEX directory touched: {n}")
        if (
            n.startswith("security/vex/")
            and not VEX_PROPOSED.match(n)
            and not VEX_APPROVED.match(n)
        ):
            violations.append(f"VEX outside security/vex/proposed/: {n}")
    generated = [n for n in names if GENERATED_REQUIREMENTS.match(n)]
    sources = [n for n in names if REQUIREMENT_SOURCES.match(n)]
    if generated and not sources:
        violations.append(
            "generated requirements changed without pyproject.toml/*.in: " + ", ".join(generated)
        )
    if kind is Kind.no_fix_reachability:
        # VEX PR: only proposed VEX documents and analysis notes.
        for n in names:
            if not (VEX_PROPOSED.match(n) or n.startswith("security/analysis/")):
                violations.append(f"no-fix PR may only add proposed VEX/analysis, found: {n}")
    if kind is Kind.scanner_disagreement:
        violations.append("scanner-disagreement work items are analysis-only; no PR expected")
    return violations


def verify_pull_request(pr: PullRequestInfo, claimed_url: str | None) -> list[str]:
    problems: list[str] = []
    if pr.repo not in REPO_ALLOWLIST or pr.repo != FORK_REPO:
        problems.append(f"PR repo {pr.repo} is not the fork")
    if pr.base_ref != REMEDIATION_BRANCH:
        problems.append(f"PR base is {pr.base_ref!r}, expected {REMEDIATION_BRANCH!r}")
    if pr.head_repo != FORK_REPO:
        problems.append(f"PR head repo {pr.head_repo} is not the fork (no cross-fork PRs)")
    if claimed_url is not None and claimed_url.rstrip("/") != pr.url.rstrip("/"):
        problems.append(f"structured_output.pr_url {claimed_url} != session PR {pr.url}")
    return problems


def parse_pr_url(url: str) -> tuple[str, int] | None:
    m = PR_URL_RE.match(url.strip().rstrip("/"))
    if not m:
        return None
    return m.group("repo"), int(m.group("number"))


DEFAULT_DISPATCH_SEVERITIES: frozenset[Severity] = frozenset({Severity.high, Severity.critical})


def dispatch_allowed(severity: Severity, labels: Iterable[str]) -> bool:
    """HIGH/CRITICAL dispatch by default; anything else only with `dispatch:approved`."""
    return severity in DEFAULT_DISPATCH_SEVERITIES or HumanLabel.dispatch_approved.value in set(
        labels
    )
