"""Operator-triggered negative suite: prove the fork's `security-scan` workflow catches what it
must.

Each case mutates a checkout of the fork's `main`, is pushed as a throwaway branch behind a draft
PR, and the resulting check runs are compared with an explicit expectation table. Cases:

    broken-build           `RUN false` in the lean stage     -> build-image fails, the rest skips
    broken-runtime         import-time error in config.py    -> image builds; smoke/app-runs fail
    dependency-regression  older urllib3 via base.in + regen -> green in report mode, raw counts
                                                                go UP, enforce would fail
    ignore-file            a .trivyignore at the repo root   -> forbid-ignore-files + scans fail
    unapproved-vex         approved/ doc without x-approval  -> vex-lint + policy scan fail

`mutate()` is pure file surgery (plus the repo's own `scripts/uv-pip-compile.sh` for the dependency
case: generated requirements are never edited by hand). `NegativeRunner` drives GitHub; the
workflow YAML only wires the two together.
"""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hardening_loop.ci import gate_job
from hardening_loop.domain.enums import GateMode
from hardening_loop.github.protocol import CheckRun
from hardening_loop.github.rest import GitHubRest
from hardening_loop.ingest.evidence import EvidenceError, load_baseline
from hardening_loop.ingest.normalize import normalize

# Job names in the fork's .github/workflows/security-scan.yml. Kept here so the expectation table
# and the workflow can never drift apart silently (tests assert the YAML uses exactly these).
CHECK_BUILD = "build-image"
CHECK_IGNORE = "forbid-ignore-files"
CHECK_VEX_LINT = "vex-lint"
CHECK_SCAN_LEAN_RAW = "scan-lean-raw"
CHECK_SCAN_LEAN_POLICY = "scan-lean-policy"
CHECK_SCAN_CI_RAW = "scan-ci-raw"
CHECK_GATE = "policy-gate"
CHECK_SMOKE = "lean-smoke"
CHECK_APP_RUNS = "app-runs"
CHECK_MANIFEST = "scan-manifest"
ALL_CHECKS: tuple[str, ...] = (
    CHECK_BUILD,
    CHECK_IGNORE,
    CHECK_VEX_LINT,
    CHECK_SCAN_LEAN_RAW,
    CHECK_SCAN_LEAN_POLICY,
    CHECK_SCAN_CI_RAW,
    CHECK_GATE,
    CHECK_SMOKE,
    CHECK_APP_RUNS,
    CHECK_MANIFEST,
)
SECURITY_SCAN_WORKFLOW = "security-scan.yml"
EVIDENCE_ARTIFACT_PREFIX = "scan-evidence-"

MARKER = "ci-negative"
REGRESSION_PIN = "urllib3==1.26.4"  # CVE-2021-33503 + CVE-2023-43804 (HIGH), well below main's pin
_BASE_IN_LINE = "urllib3>=2.6.3,<3.0.0"


class MutationError(RuntimeError):
    pass


@dataclass(frozen=True)
class NegativeCase:
    name: str
    summary: str
    # check name -> allowed conclusions ("skipped" for jobs that must not run)
    expect: dict[str, frozenset[str]]
    mutate: Callable[[Path, Callable[[Path], None]], list[str]]
    compares_counts: bool = False  # dependency-regression only


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _mutate_broken_build(src: Path, _regen: Callable[[Path], None]) -> list[str]:
    dockerfile = src / "Dockerfile"
    lines = dockerfile.read_text().splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.strip() == "FROM python-common AS lean":
            lines.insert(i + 1, f"RUN false  # {MARKER}: broken-build\n")
            break
    else:
        raise MutationError("Dockerfile has no `FROM python-common AS lean` stage")
    dockerfile.write_text("".join(lines))
    return ["Dockerfile"]


def _mutate_broken_runtime(src: Path, _regen: Callable[[Path], None]) -> list[str]:
    config = src / "superset" / "config.py"
    if not config.is_file():
        raise MutationError("superset/config.py missing")
    with config.open("a") as fh:
        fh.write(f'\nraise RuntimeError("{MARKER}: broken-runtime")\n')
    return ["superset/config.py"]


def _mutate_dependency_regression(src: Path, regenerate: Callable[[Path], None]) -> list[str]:
    base_in = src / "requirements" / "base.in"
    text = base_in.read_text()
    if _BASE_IN_LINE not in text.splitlines():
        raise MutationError(f"requirements/base.in has no `{_BASE_IN_LINE}` line to downgrade")
    base_in.write_text(text.replace(_BASE_IN_LINE, REGRESSION_PIN))
    base_txt = src / "requirements" / "base.txt"
    before = base_txt.read_text()
    regenerate(src)
    after = base_txt.read_text()
    if after == before:
        raise MutationError("scripts/uv-pip-compile.sh did not change requirements/base.txt")
    if REGRESSION_PIN not in after.splitlines():
        raise MutationError(f"regenerated base.txt does not pin {REGRESSION_PIN}")
    changed = ["requirements/base.in", "requirements/base.txt"]
    dev = src / "requirements" / "development.txt"
    if dev.is_file():
        changed.append("requirements/development.txt")
    return changed


def _mutate_ignore_file(src: Path, _regen: Callable[[Path], None]) -> list[str]:
    _write(src / ".trivyignore", f"# {MARKER}: forbidden suppression file\nCVE-2024-0001\n")
    return [".trivyignore"]


def _mutate_unapproved_vex(src: Path, _regen: Callable[[Path], None]) -> list[str]:
    rel = f"security/vex/approved/{MARKER}-unapproved.json"
    doc: dict[str, Any] = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/Hunter-1298/superset/{rel}",
        "author": f"{MARKER} (nobody approved this)",
        "timestamp": "2026-01-01T00:00:00Z",
        "version": 1,
        "statements": [
            {
                "vulnerability": {"name": "CVE-2023-48795"},
                "products": [{"@id": "pkg:pypi/paramiko@3.5.1"}],
                "status": "not_affected",
                "justification": "vulnerable_code_not_in_execute_path",
                "impact_statement": f"{MARKER}: placed without an approval issue on purpose",
            }
        ],
    }
    _write(src / rel, json.dumps(doc, indent=2) + "\n")
    return [rel]


_SUCCESS = frozenset({"success"})
_FAILURE = frozenset({"failure"})
_SKIPPED = frozenset({"skipped"})
_NOT_SUCCESS = frozenset({"failure", "skipped", "cancelled"})

CASES: dict[str, NegativeCase] = {
    "broken-build": NegativeCase(
        name="broken-build",
        summary="`RUN false` in the lean stage: build-image must fail and image jobs must skip",
        expect={
            CHECK_BUILD: _FAILURE,
            CHECK_IGNORE: _SUCCESS,
            CHECK_VEX_LINT: _SUCCESS,
            CHECK_SCAN_LEAN_RAW: _SKIPPED,
            CHECK_SCAN_LEAN_POLICY: _SKIPPED,
            CHECK_SCAN_CI_RAW: _SKIPPED,
            CHECK_GATE: _SKIPPED,
            CHECK_SMOKE: _SKIPPED,
            CHECK_APP_RUNS: _SKIPPED,
            CHECK_MANIFEST: _NOT_SUCCESS,
        },
        mutate=_mutate_broken_build,
    ),
    "broken-runtime": NegativeCase(
        name="broken-runtime",
        summary="import-time error in superset/config.py: image builds and scans but never starts",
        expect={
            CHECK_BUILD: _SUCCESS,
            CHECK_SCAN_LEAN_RAW: _SUCCESS,
            CHECK_SCAN_LEAN_POLICY: _SUCCESS,
            CHECK_SCAN_CI_RAW: _SUCCESS,
            CHECK_SMOKE: _FAILURE,
            CHECK_APP_RUNS: _FAILURE,
            CHECK_MANIFEST: _NOT_SUCCESS,
        },
        mutate=_mutate_broken_runtime,
    ),
    "dependency-regression": NegativeCase(
        name="dependency-regression",
        summary=(
            f"{REGRESSION_PIN} via requirements/base.in + scripts/uv-pip-compile.sh: report mode "
            "stays green while raw HIGH/CRITICAL counts rise; enforce mode would fail"
        ),
        expect={
            CHECK_BUILD: _SUCCESS,
            CHECK_IGNORE: _SUCCESS,
            CHECK_VEX_LINT: _SUCCESS,
            CHECK_SCAN_LEAN_RAW: _SUCCESS,
            CHECK_SCAN_LEAN_POLICY: _SUCCESS,
            CHECK_SCAN_CI_RAW: _SUCCESS,
            CHECK_GATE: _SUCCESS,
            CHECK_SMOKE: _SUCCESS,
            CHECK_APP_RUNS: _SUCCESS,
            CHECK_MANIFEST: _SUCCESS,
        },
        mutate=_mutate_dependency_regression,
        compares_counts=True,
    ),
    "ignore-file": NegativeCase(
        name="ignore-file",
        summary=".trivyignore at the repo root: forbid-ignore-files and every scan must fail",
        expect={
            CHECK_IGNORE: _FAILURE,
            CHECK_SCAN_LEAN_RAW: _FAILURE,
            CHECK_SCAN_LEAN_POLICY: _FAILURE,
            CHECK_SCAN_CI_RAW: _FAILURE,
            CHECK_MANIFEST: _NOT_SUCCESS,
        },
        mutate=_mutate_ignore_file,
    ),
    "unapproved-vex": NegativeCase(
        name="unapproved-vex",
        summary="approved/ OpenVEX without x-approval: vex-lint and the policy scan must fail",
        expect={
            CHECK_VEX_LINT: _FAILURE,
            CHECK_SCAN_LEAN_RAW: _SUCCESS,
            CHECK_SCAN_LEAN_POLICY: _FAILURE,
            CHECK_GATE: _NOT_SUCCESS,
            CHECK_MANIFEST: _NOT_SUCCESS,
        },
        mutate=_mutate_unapproved_vex,
    ),
}


def regenerate_requirements(src: Path) -> None:
    """The repo's own generator (runs `uv pip compile` inside python:<current>-slim via Docker)."""
    subprocess.run(["./scripts/uv-pip-compile.sh"], cwd=src, check=True)


def mutate(
    case_name: str, src: Path, *, regenerate: Callable[[Path], None] | None = None
) -> list[str]:
    """Apply one case to a checkout and return the paths that changed (for `git add`)."""
    case = CASES[case_name]
    return case.mutate(src, regenerate or regenerate_requirements)


# --------------------------------------------------------------------------------------- runner


@dataclass
class CaseReport:
    case: str
    summary: str
    branch: str
    head_sha: str
    pr_url: str | None = None
    check_results: dict[str, str | None] = field(default_factory=dict)
    expectation_failures: list[str] = field(default_factory=list)
    counts: dict[str, Any] = field(default_factory=dict)
    passed: bool = False
    started_at: str = ""
    finished_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "hardening-loop/ci-negative-report/v1",
            "case": self.case,
            "summary": self.summary,
            "branch": self.branch,
            "head_sha": self.head_sha,
            "pr_url": self.pr_url,
            "check_results": dict(sorted(self.check_results.items())),
            "expectation_failures": self.expectation_failures,
            "counts": self.counts,
            "passed": self.passed,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }


def evaluate(case: NegativeCase, runs: list[CheckRun]) -> tuple[dict[str, str | None], list[str]]:
    """Compare completed check runs with the expectation table. Missing expected checks fail."""
    by_name: dict[str, CheckRun] = {}
    for run in runs:
        prev = by_name.get(run.name)
        if prev is None or (prev.status != "completed" and run.status == "completed"):
            by_name[run.name] = run
    results: dict[str, str | None] = {n: r.conclusion for n, r in by_name.items()}
    failures: list[str] = []
    for name, allowed in case.expect.items():
        found = by_name.get(name)
        if found is None:
            failures.append(f"{name}: no check run reported")
        elif found.status != "completed":
            failures.append(f"{name}: still {found.status}")
        elif found.conclusion not in allowed:
            failures.append(f"{name}: {found.conclusion}, expected one of {sorted(allowed)}")
    return results, failures


def all_expected_completed(case: NegativeCase, runs: list[CheckRun]) -> bool:
    names = {r.name for r in runs if r.status == "completed"}
    return all(name in names for name in case.expect)


def raw_counts(evidence_root: Path) -> dict[str, Any]:
    """Deduplicated lean/raw counts of a downloaded scan-evidence artifact."""
    manifest = load_baseline(evidence_root)
    job = manifest.jobs["lean-raw"]
    findings = normalize([*job.trivy_vulns, *job.grype_vulns])
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity.value] = by_sev.get(f.severity.value, 0) + 1
    return {
        "source_sha": manifest.source_sha,
        "image": manifest.lean_image_id,
        "total": len(findings),
        "high_critical": by_sev.get("HIGH", 0) + by_sev.get("CRITICAL", 0),
        "by_severity": dict(sorted(by_sev.items())),
    }


class NegativeRunner:
    def __init__(
        self,
        gh: GitHubRest,
        *,
        repo: str,
        base_branch: str = "main",
        poll_seconds: float = 30.0,
        timeout_seconds: float = 90 * 60,
        work_dir: Path,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.gh = gh
        self.repo = repo
        self.base_branch = base_branch
        self.poll_seconds = poll_seconds
        self.timeout_seconds = timeout_seconds
        self.work_dir = work_dir
        self.sleep = sleep

    def run(self, case_name: str, *, branch: str, head_sha: str, run_url: str) -> CaseReport:
        """Branch is already pushed by the workflow (git needs a real checkout for the dependency
        case). Open the draft PR, wait for the fork's checks, evaluate, always clean up."""
        case = CASES[case_name]
        report = CaseReport(
            case=case.name,
            summary=case.summary,
            branch=branch,
            head_sha=head_sha,
            started_at=datetime.now(UTC).isoformat(timespec="seconds"),
        )
        pr = self.gh.create_pull_request(
            self.repo,
            title=f"[{MARKER}] {case.name} (expected to fail checks)",
            body=(
                f"Operator-triggered negative test `{case.name}`: {case.summary}.\n\n"
                f"Driven by {run_url}. This PR is closed automatically; never merge it."
            ),
            head=branch,
            base=self.base_branch,
            draft=True,
        )
        report.pr_url = pr.url
        try:
            deadline = time.monotonic() + self.timeout_seconds
            runs: list[CheckRun] = []
            while True:
                runs = self.gh.list_check_runs(self.repo, head_sha)
                if all_expected_completed(case, runs):
                    break
                if time.monotonic() >= deadline:
                    break
                self.sleep(self.poll_seconds)
            report.check_results, report.expectation_failures = evaluate(case, runs)
            if case.compares_counts and not report.expectation_failures:
                report.counts = self._compare_counts(head_sha)
                report.expectation_failures.extend(report.counts.pop("failures", []))
            report.passed = not report.expectation_failures
            self.gh.comment_issue(
                self.repo,
                pr.number,
                f"`{MARKER}` verdict: **{'PASS' if report.passed else 'FAIL'}**\n\n"
                + "\n".join(f"- {k}: `{v}`" for k, v in sorted(report.check_results.items()))
                + (
                    "\n\n" + "\n".join(f"- {f}" for f in report.expectation_failures)
                    if report.expectation_failures
                    else ""
                ),
            )
        finally:
            report.finished_at = datetime.now(UTC).isoformat(timespec="seconds")
            try:
                self.gh.close_pull_request(self.repo, pr.number)
            finally:
                self.gh.delete_branch(self.repo, branch)
        return report

    def _evidence_for(self, head_sha: str) -> Path | None:
        for run in self.gh.list_workflow_runs(self.repo, SECURITY_SCAN_WORKFLOW, head_sha=head_sha):
            if run.get("head_sha") != head_sha:
                continue
            for artifact in self.gh.list_run_artifacts(self.repo, int(run["id"])):
                if str(artifact["name"]).startswith(EVIDENCE_ARTIFACT_PREFIX):
                    dest = self.work_dir / "evidence" / str(run["id"])
                    return self.gh.download_artifact(self.repo, int(artifact["id"]), dest)
        return None

    def _latest_main_evidence(self) -> Path | None:
        for run in self.gh.list_workflow_runs(
            self.repo, SECURITY_SCAN_WORKFLOW, branch=self.base_branch
        ):
            if run.get("conclusion") != "success":
                continue
            for artifact in self.gh.list_run_artifacts(self.repo, int(run["id"])):
                if str(artifact["name"]).startswith(EVIDENCE_ARTIFACT_PREFIX):
                    dest = self.work_dir / "evidence" / f"main-{run['id']}"
                    return self.gh.download_artifact(self.repo, int(artifact["id"]), dest)
        return None

    def _compare_counts(self, head_sha: str) -> dict[str, Any]:
        failures: list[str] = []
        pr_root = self._evidence_for(head_sha)
        main_root = self._latest_main_evidence()
        out: dict[str, Any] = {"failures": failures}
        if pr_root is None:
            failures.append("no scan-evidence artifact for the PR head")
            return out
        if main_root is None:
            failures.append(f"no successful security-scan run with evidence on {self.base_branch}")
            return out
        try:
            pr_counts, main_counts = raw_counts(pr_root), raw_counts(main_root)
        except EvidenceError as exc:
            failures.append(f"evidence rejected: {exc}")
            return out
        out["pr"] = pr_counts
        out["main"] = main_counts
        if pr_counts["total"] <= main_counts["total"]:
            failures.append(
                f"raw lean total did not increase: {main_counts['total']} -> {pr_counts['total']}"
            )
        if pr_counts["high_critical"] <= main_counts["high_critical"]:
            failures.append(
                "raw lean HIGH+CRITICAL did not increase: "
                f"{main_counts['high_critical']} -> {pr_counts['high_critical']}"
            )
        enforce = gate_job(pr_root / "lean" / "policy", GateMode.enforce)
        out["enforce_verdict"] = enforce.to_dict()
        if enforce.verdict.passed:
            failures.append("enforce-mode gate passed on the regressed policy scan")
        return out


__all__ = [
    "ALL_CHECKS",
    "CASES",
    "REGRESSION_PIN",
    "CaseReport",
    "MutationError",
    "NegativeCase",
    "NegativeRunner",
    "all_expected_completed",
    "evaluate",
    "mutate",
    "raw_counts",
]
