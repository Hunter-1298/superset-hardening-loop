# First live remediation (one bounded session)

The first live run is one Normal Devin session on one small, fixable Python dependency
(kind 1), capped at 5 ACUs in total. Nothing here bypasses a gate: if a step fails, stop,
keep the evidence, and fix the cause before repeating the step.

Every command below is run from the controller checkout with the virtualenv active. Values of
`HL_GITHUB_TOKEN` and `HL_DEVIN_API_KEY` are never printed; `doctor` reports them as
`set`/`unset`.

## 1. Gates that must already be green

1. Controller checks on the PR head: `ruff format --check . && ruff check . && mypy
   hardening_loop tests && pytest -q`.
2. `hardening-loop replay --out data/replay` — every scenario passed, zero sockets opened.
3. `docker compose run --rm replay` — the same inside `network_mode: none`.
4. A fresh `security-scan` run of fork `main` that installed the controller from the immutable
   controller SHA pinned in the fork's `CONTROLLER_REF` (recorded in the bundle's
   `manifest.json` as `controller_sha`), with every required job
   green: `forbid-ignore-files`, `vex-lint`, `build-image`, `scan-lean-raw`, `scan-lean-policy`,
   `scan-ci-raw`, `policy-gate`, `lean-smoke`, `app-runs`, `scan-manifest`.
5. That run's evidence artifact ingested locally, then ingested again:

   ```bash
   hardening-loop ingest --db data/live.sqlite3 --run-id <run id> --json data/ingest-1.json
   hardening-loop ingest --db data/live.sqlite3 --run-id <run id> --json data/ingest-2.json
   ```

   The first outcome is `ingested`; the second is `duplicate` with no new `scan_runs` row,
   no new sighting and no new evidence directory. `data/evidence/runs/<run id>/<attempt>/`
   holds the verified bundle (`manifest.json`, raw Trivy/Grype JSON, SARIF, SBOM, lean-smoke
   and app-runs records) with the per-file checksums the intake verified.

   The same checks run offline against any extracted bundle, with no GitHub access and no
   database, which is what the fork's `evidence-negative` workflow uses to prove tampered and
   source-mismatched evidence is refused:

   ```bash
   hardening-loop evidence-verify data/evidence/runs/<run id>/1 \
     --run-id <run id> --head-sha <fork main sha> --git ../superset
   ```
6. The operator-triggered negatives (`ci-negative` in the controller repository) have each
   produced the expected failure once against the current fork `main`.

## 2. Profile

```bash
export HL_OPERATOR_LOGIN=Hunter-1298
export HL_AUTO_DISPATCH=false
export HL_AUTO_OPEN_ISSUES=false
export HL_MAX_CONCURRENT_SESSIONS=1
export HL_GLOBAL_ACU_BUDGET=5
export HL_SCAN_GATE_MODE=report
export HL_REPLAY_MODE=false
export HL_DATA_DIR=data/live
export HL_REQUIRED_CHECK_NAMES='["forbid-ignore-files","vex-lint","build-image","scan-lean-raw","scan-lean-policy","scan-ci-raw","policy-gate","lean-smoke","app-runs","scan-manifest"]'
hardening-loop doctor --live
```

`doctor --live` fails closed on anything outside this profile, on a missing credential, on a
database at an old schema, on drifted committed assets or exported schemas, and on Devin assets
that are not yet synced.

## 3. Assets

```bash
hardening-loop assets sync                  # creates or updates the five playbooks + knowledge note
hardening-loop assets sync --expect-noop    # second pass must change nothing (exit 0)
```

Asset ids land in `devin_assets`; dispatch refuses to run when they are missing or drifted.

## 4. Candidate

Pick exactly one kind-1 work item whose upgrade is the smallest safe change:

* a single Python package, `fixed_version` known to both scanners, no `pyproject.toml` upper
  bound in the way (an upper-bound-blocked package is `risk:high` and stays out of the first run);
* not a framework or a database driver (no `flask*`, `sqlalchemy*`, `psycopg*`, `pandas`,
  `numpy`);
* the CVE page shows both scanners agreeing on package, installed version and fix.

Note the work item id, CVE ids, package and the `fixed_version` from the CVE page.

## 5. Launch

```bash
hardening-loop serve --operator            # loopback only; poll loop on HL_POLL_INTERVAL_SECONDS
```

Open `http://127.0.0.1:8080/findings/<finding id>` → **Launch Devin** → confirm. The launch:

1. opens the tracking issue in the fork (or adopts the open `hardening-loop` issue with the same
   title), labels it, and — for severities below HIGH — adds `dispatch:approved` with an
   "operator launched by Hunter-1298" comment;
2. creates one Normal session tagged `wi-<id>`, `max_acu_limit=5`, the dependency-upgrade
   playbook, the knowledge note, and the kind-1 structured-output schema;
3. records the session id, then polls it.

A second click on the same item is refused while the session is active. The budget guard
refuses a launch that would commit more than 5 ACUs in total.

## 6. What the session must deliver

* One focused PR to fork `main` touching `pyproject.toml`/`requirements/*.in` inputs and the
  regenerated `requirements/*.txt` (via the official regeneration script), nothing else.
* Structured output matching `playbooks/schemas/pb-dependency-upgrade.json` (`outcome`,
  `base_branch`, `findings_addressed`, `findings_not_addressed`, plus `pr_url`, `packages`,
  `regenerated_with` and `tests_run` for a PR).
* CI green on the PR head; Devin Review triggered by the controller for that exact head SHA and
  `completed`.

The controller records lifecycle (`session_active → pr_open → ready_for_human`), verification
depth (L0 requirements+pip, L1 import+migrations, L2 targeted tests; L3+ marked unavailable
unless the PR's `security-scan` run supplies them), ACUs and cost per poll.

Failures (CI red, Review errored, blocked output) go back to the same session as a message,
at most `HL_RETRIES_PER_WORK_ITEM` times and never past the 5-ACU cap; beyond that the item is
`needs-human` with a `blocked_reason` on the issue.

## 7. What stays with Hunter

* Reviewing the PR, reading the Review comments, approving and merging.
* After the merge, `security-scan` runs on `main`; the controller ingests it and the finding
  closes only if that complete, source-matching run no longer reports it. Until then the issue
  stays open with `merged` verification and the finding stays `pr_merged`.

## 8. Stop conditions

Stop and leave the evidence in place (dashboard, `data/live/`, the issue) if:

* `doctor --live` fails;
* the candidate list has no item meeting section 4;
* the launch is refused by the budget, capacity or duplicate guard;
* the session ends `usage_limit_exceeded`, `out_of_credits` or any quota/credit state;
* Devin Review cannot be triggered or polled for the exact head;
* the PR is not against fork `main`, or touches generated pins without the regeneration script.
