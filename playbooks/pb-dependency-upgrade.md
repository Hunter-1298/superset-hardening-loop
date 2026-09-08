---
kind: dependency_upgrade
title: Superset hardening: dependency upgrade (kind 1)
macro: !hl-dependency-upgrade
---
# Dependency upgrade

You are fixing one group of fixable Python dependency CVEs in `Hunter-1298/superset`. The tracking
issue, the work item id and a machine-readable findings attachment are in the session prompt. The
controller that started this session polls your structured output; a human approves and merges.

## Boundaries

- Work only in `Hunter-1298/superset`. Never open anything against `apache/superset`.
- Branch from `main` (Superset 6.1.0 baseline). Open exactly one PR targeting `main`.
- Touch only what the upgrade needs: `pyproject.toml` bounds, `requirements/*.in` when required,
  and the regenerated `requirements/*.txt`.
- Never edit `requirements/*.txt` by hand. Regenerate with `./scripts/uv-pip-compile.sh` and
  report the exact command in `regenerated_with`.
- Never add or edit `.trivyignore`, `.grype.yaml`, `security/vex/` or any scanner suppression.
- Never claim a test you did not run. Record every command in `tests_run` with its exit code.
- Stop and return `blocked` (with a reason of at least ten characters) instead of guessing when
  the upgrade needs a breaking change, a fork of a dependency, or a change outside the boundaries.

## Procedure

1. Read the findings attachment. Every finding names a package, the installed version and the fix
   versions each scanner reports. Take the smallest fix version that satisfies every finding for
   the package.
2. Check `pyproject.toml` (and the `requirements/*.in` inputs) for an upper bound that excludes the
   fix version. If one exists, raise it to the smallest bound that admits the fix and record it in
   `bound_changes` with a justification that names the changelog entry you read. A bound you cannot
   justify is a `blocked` outcome, not a guess.
3. Regenerate the pins: `./scripts/uv-pip-compile.sh`. Do not edit the output afterwards.
4. Verify locally in this order and stop at the first failure you cannot fix within the boundaries:
   - `pip install -r requirements/base.txt` (or the project's documented equivalent);
   - `python -c "import superset"`;
   - `superset db upgrade` against SQLite;
   - the unit tests that import the upgraded package, then `pytest tests/unit_tests -x -q`.
5. Run pre-commit on the changed files.
6. Open the PR against `main` with a Conventional Commit title such as
   `fix(deps): upgrade <package> to <version> (CVE-...)`. Link the tracking issue in the body, list
   the CVEs closed, and paste the regeneration command.
7. Finish with the structured output. `outcome` is `pr_opened` with `pr_url`, `packages`
   (`name`, `from`, `to`) and `regenerated_with`; `findings_addressed` lists every CVE the PR
   fixes and `findings_not_addressed` explains each one it does not.

## What CI will check

The fork's CI rebuilds the immutable `lean` image, rescans it with Trivy and Grype, and runs the
`lean-smoke` and `app-runs` jobs (Postgres, Redis, migrations, login, dashboards, chart data,
SQL Lab, CSV export). A dependency that installs but breaks the runtime will fail there; fix it
within your ACU cap or return `blocked`.
