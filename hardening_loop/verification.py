"""Verification depth: which rungs of the L0-L6 ladder a PR head has actually earned.

The ladder maps every rung to the GitHub check runs on the fork that prove it. A rung is
`passed` only when every one of its components has a completed, successful check run on the
exact head; `failed` when any completed one failed; `pending` while any is still running;
`unavailable` when nothing on this head produced evidence for it (no such check run, or the run
was skipped by the fork's change detector); `partial` when every component that can exist here
passed but the rung also has components with no check on this repository (recorded so the gap
is visible instead of silently counting as passed).

Check-run names are the job names GitHub reports for the fork's workflows; matrix jobs appear
as `name (matrix, values)`, so components match on the exact name or on `name (` as a prefix.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass

from hardening_loop.domain.enums import CheckSource, CheckStatus, VerificationDepth
from hardening_loop.github.protocol import CheckRun

_SUCCESS = frozenset({"success"})
_UNAVAILABLE_CONCLUSIONS = frozenset({"skipped", "neutral"})


@dataclass(frozen=True)
class Component:
    """One thing a rung requires. `check` is the GitHub check-run name (or matrix prefix) that
    proves it; `None` means no check exists on this repository, so it is always unavailable."""

    name: str
    description: str
    check: str | None


DEFAULT_LADDER: dict[VerificationDepth, tuple[Component, ...]] = {
    VerificationDepth.requirements_pip: (
        Component(
            "requirements-regenerated",
            "pins regenerate cleanly from source inputs (scripts/uv-pip-compile.sh)",
            "check-python-deps",
        ),
        Component(
            "pip-install",
            "pip installs the pinned set while building the immutable image",
            "build-image",
        ),
    ),
    VerificationDepth.import_migrations: (
        Component(
            "import-and-migrations",
            "superset imports, `superset db upgrade` reaches head, gunicorn serves /health, "
            "login works, all inside the exact lean image",
            "lean-smoke",
        ),
    ),
    VerificationDepth.targeted_unit: (
        Component("python-unit-tests", "pytest unit suite", "unit-tests"),
    ),
    VerificationDepth.immutable_image_runtime: (
        Component(
            "postgres-redis-app-runs",
            "exact ci image with Postgres, Redis and Celery: migrations, login, dashboards, "
            "chart data, SQL Lab sync + async, CSV export",
            "app-runs",
        ),
        Component("screenshot", "rendered dashboard screenshot from the running image", None),
    ),
    VerificationDepth.db_subset: (
        Component("integration-postgres", "integration tests on PostgreSQL", "test-postgres"),
        Component("integration-mysql", "integration tests on MySQL", "test-mysql"),
        Component("integration-sqlite", "integration tests on SQLite", "test-sqlite"),
    ),
    VerificationDepth.playwright: (
        Component("playwright", "Playwright end-to-end suite", "playwright-tests"),
    ),
    VerificationDepth.canary: (
        Component("canary", "canary deployment with traffic; no environment exists", None),
    ),
}


@dataclass(frozen=True)
class CheckRecord:
    depth: VerificationDepth
    name: str
    source: CheckSource
    status: CheckStatus
    detail: str
    url: str | None = None


@dataclass(frozen=True)
class DepthEvaluation:
    records: tuple[CheckRecord, ...]
    rungs: dict[VerificationDepth, CheckStatus]

    @property
    def highest_passed(self) -> VerificationDepth | None:
        passed = [d for d, s in self.rungs.items() if s is CheckStatus.passed]
        return max(passed) if passed else None

    def rung_summary(self) -> dict[str, str]:
        return {d.name: s.value for d, s in self.rungs.items()}


def matching_runs(check: str, runs: Iterable[CheckRun]) -> list[CheckRun]:
    prefix = check + " ("
    return [r for r in runs if r.name == check or r.name.startswith(prefix)]


def _component_status(check: str, runs: Sequence[CheckRun]) -> tuple[CheckStatus, str, str | None]:
    matched = matching_runs(check, runs)
    if not matched:
        return CheckStatus.unavailable, f"no check run named {check!r} on this head", None
    url = next((r.url for r in matched if r.url), None)
    if any(r.status != "completed" for r in matched):
        running = sum(1 for r in matched if r.status != "completed")
        return CheckStatus.pending, f"{running}/{len(matched)} runs still in progress", url
    failed = [r for r in matched if r.conclusion not in _SUCCESS | _UNAVAILABLE_CONCLUSIONS]
    if failed:
        names = ", ".join(f"{r.name}={r.conclusion}" for r in failed)
        return CheckStatus.failed, names, url
    succeeded = [r for r in matched if r.conclusion in _SUCCESS]
    if not succeeded:
        conclusions = ", ".join(sorted({str(r.conclusion) for r in matched}))
        return CheckStatus.unavailable, f"all runs concluded {conclusions}; no evidence", url
    skipped = len(matched) - len(succeeded)
    detail = f"{len(succeeded)} run(s) succeeded" + (f", {skipped} skipped" if skipped else "")
    return CheckStatus.passed, detail, url


def _rung_status(statuses: Sequence[CheckStatus]) -> CheckStatus:
    if any(s is CheckStatus.failed for s in statuses):
        return CheckStatus.failed
    if any(s is CheckStatus.pending for s in statuses):
        return CheckStatus.pending
    if all(s is CheckStatus.unavailable for s in statuses):
        return CheckStatus.unavailable
    if all(s is CheckStatus.passed for s in statuses):
        return CheckStatus.passed
    return CheckStatus.partial


def evaluate(
    runs: Iterable[CheckRun],
    ladder: dict[VerificationDepth, tuple[Component, ...]] = DEFAULT_LADDER,
) -> DepthEvaluation:
    runs = list(runs)
    records: list[CheckRecord] = []
    rungs: dict[VerificationDepth, CheckStatus] = {}
    for depth in VerificationDepth:
        statuses: list[CheckStatus] = []
        for comp in ladder.get(depth, ()):
            if comp.check is None:
                status, detail, url = (
                    CheckStatus.unavailable,
                    f"no check exists for this on the repository: {comp.description}",
                    None,
                )
                source = CheckSource.ladder
            else:
                status, detail, url = _component_status(comp.check, runs)
                source = CheckSource.github_check
            statuses.append(status)
            records.append(CheckRecord(depth, comp.name, source, status, detail, url))
        rungs[depth] = _rung_status(statuses) if statuses else CheckStatus.unavailable
    return DepthEvaluation(tuple(records), rungs)


def claims_from_output(structured_output: dict[str, object] | None) -> tuple[CheckRecord, ...]:
    """Devin's `tests_run` entries, kept as informational records. They are stored beside the
    CI evidence but never change a rung's status."""
    if not structured_output:
        return ()
    raw = structured_output.get("tests_run")
    if not isinstance(raw, list):
        return ()
    out: list[CheckRecord] = []
    for i, item in enumerate(raw):
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", ""))[:200]
        code = item.get("exit_code")
        status = CheckStatus.passed if code == 0 else CheckStatus.failed
        out.append(
            CheckRecord(
                VerificationDepth.targeted_unit,
                f"devin-tests-run-{i + 1}",
                CheckSource.devin_claim,
                status,
                f"exit {code}: {command}",
            )
        )
    return tuple(out)
