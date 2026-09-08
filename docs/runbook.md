# Runbook

Day-to-day operation of the controller. Everything here is either no-spend (replay, doubles,
doctor, report) or reads/writes only the fork `Hunter-1298/superset` and the Devin org through
the credentials named in [settings.md](settings.md). Nothing in this document targets
`apache/superset`.

## Install

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Or run the image: `docker compose build` then use the `replay`, `dashboard` and `operator`
services in `docker-compose.yml`.

## No-spend checks (run before anything live)

```bash
ruff format --check . && ruff check . && mypy hardening_loop tests && pytest -q
hardening-loop replay --out data/replay          # R0-R21, N1-N5, OP1, DEMO; outbound network blocked
hardening-loop doctor                            # settings, database, committed assets, fixtures
hardening-loop assets sync --doubles --dry-run   # what a live sync would do, against the double
docker compose run --rm replay                   # same replay inside network_mode: none
```

`replay` writes `data/replay/replay-report.{json,md}` plus one SQLite file per scenario and
`replay.sqlite3` for the dashboard. A scenario fails if any expectation fails **or** if anything
tried to open a socket. Every scenario also leaves one `metrics_snapshots` row
(`trigger=replay:<name>`).

## Dashboard

```bash
hardening-loop serve --replay --db data/replay/replay.sqlite3          # read-only, labelled replay
hardening-loop serve --db data/hardening_loop.sqlite3                  # read-only, live data
hardening-loop serve --operator --doubles --operator-login <login>      # writable, in-memory doubles
HL_OPERATOR_LOGIN=<login> hardening-loop serve --operator               # writable, live clients
```

`serve` without `--operator` has no write route (every route is GET-only). `--operator` adds
`POST /operator/launch/<work item>` behind a confirmation step, CSRF token and same-origin check,
binds loopback only, and runs the poll loop on `HL_POLL_INTERVAL_SECONDS`. Each tick persists a
metrics snapshot (`trigger=tick`).

JSON: `/api/metrics`, `/api/metrics/history`, `/api/runs`, `/api/work-items`,
`/api/work-items/{id}/events`, `/healthz`.

## Scan intake

The fork's `security-scan` workflow uploads one `scan-evidence-<source sha>` artifact per run.

```bash
hardening-loop ingest                           # poll completed security-scan runs on main
hardening-loop ingest --run-id <actions run id> # one run
hardening-loop ingest --json data/ingest.json   # also write outcomes
```

Every run seen gets exactly one `scan_intakes` row keyed by run id + attempt (`ingested`,
`incomplete` or `rejected` with reasons); running `ingest` again for the same run is a no-op.
Rejection reasons and the fail-closed rules are documented at the top of
`hardening_loop/ingest/intake.py`. Rejected bundles stay on disk under
`data/evidence/runs/<run id>/<attempt>/` for inspection. The operator poll loop performs the same intake
on every tick.

Intake only persists a run. Its closing evaluation (closures, regressions, database drift) happens
on the next operator tick, which evaluates every `scan_runs` row whose `closure_applied_at` is still
null, oldest scan first, and stamps it in the same transaction as its effects. Within a tick this
evaluation runs after the session and PR polls, so a scan of `main` that finished after a merge
the controller has not yet observed is weighed against the merged state and closes the work item
in that same tick rather than being spent early and forcing another rescan. A run brought in by
the CLI, or one persisted just before a crash cut its intake record short, is therefore evaluated
exactly once. An older run evaluated after a newer one has already reported or closed a finding
cannot close or reopen that finding.

An `incomplete` run (a runtime job failed, or the workflow conclusion is not `success`) is
persisted with its raw evidence but never used by the closer as proof of absence.

## Issues, labels and human actions

The controller opens one issue per work item on the fork with labels
`hardening-loop`, `kind:<kind>`, `severity:<severity>` and, for upper-bound-blocked dependency
upgrades, `risk:high`. Humans drive the loop through labels on that issue:

| Label | Who sets it | Effect |
|---|---|---|
| `awaiting-dispatch-approval` | controller | MEDIUM/LOW work items wait here; HIGH/CRITICAL are dispatchable by default |
| `dispatch:approved` | human | allows dispatch of a MEDIUM/LOW item (an operator launch applies it, and revokes it if the launch fails) |
| `needs-human` | controller | the item stopped: blocked output, `no_change_needed` claims, retries exhausted, budget, Review error, waiting-for-approval, etc.; `blocked_reason` is on the issue and the dashboard |
| `retry` | human | re-run the work item in the same Devin session (within its ACU cap) |
| `disposition:approved` | human | accept a proposed OpenVEX (kind 2); the VEX is then linted from `security/vex/approved/` only |
| `disagreement:resolved` | human | close a scanner-disagreement analysis (kind 4) |

PR approvals and merges happen in GitHub only. The controller never merges, never applies
repository settings, and never removes a `needs-human` label a human has to act on.

## Closure

A finding closes only when a later **complete** scan of `main` (workflow success, every
required job green, both scanners present, matching image/platform/layer scope, commit a
descendant of the PR merge) no longer reports it. Outcomes are kept distinct: `fixed`,
`approved disposition`, `scanner disagreement`, `regression`, `human-blocked`. Partial or
failed scans prove nothing (replay R13, R18, R20; intake R21).

## Rescan after a merge

1. Merge the remediation PR into fork `main` (human).
2. `security-scan` runs on the push to `main` (or dispatch it: Actions → security-scan → Run
   workflow, leaving `controller_ref` empty so the committed pin is used).
3. Confirm every job is green in the run: `forbid-ignore-files`, `vex-lint`, `build-image`,
   `scan-lean-raw`, `scan-lean-policy`, `scan-ci-raw`, `policy-gate`, `lean-smoke`,
   `app-runs`, `scan-manifest`.
4. `hardening-loop ingest --run-id <run id>` (or wait one operator tick).
5. The work item moves to `rescan_verified` and the issue closes with the outcome; check
   `/issues/<id>` and `hardening-loop report`.

## Report and metrics

```bash
hardening-loop report --db <sqlite> [--upstream-sha <sha>] [--acu-cost-usd <usd>]
hardening-loop metrics snapshot --db <sqlite> [--trigger <label>] [--acu-cost-usd <usd>]
hardening-loop metrics history --db <sqlite> [--limit N] [--json]
```

`report` compares baseline, latest `main` scan and `upstream-master` pins per dependency.
Metrics snapshots denormalize open HIGH/CRITICAL, needs-human, active sessions, verified PRs,
ACUs and cost; the full `Metrics` payload is in the `body` column.

## Negative tests (operator-triggered, never in CI)

Controller repo → Actions → `ci-negative` → Run workflow with `cases` = `all` or a subset of
`broken-build broken-runtime dependency-regression ignore-file unapproved-vex`. Each case pushes
a throwaway branch to the fork, opens a draft PR, waits for `security-scan`, asserts the
expected job fails (or, for `dependency-regression`, that report mode stays green while finding
counts rise), then deletes the branch. Needs the `FORK_TOKEN` repository secret in the controller
repo. `dependency-regression` compares against the latest successful `security-scan` run on
`base_branch`; set `compare_run_id` to a specific successful run when that branch has none yet.
The same steps run from a shell (`hardening-loop ci-negative mutate` → push → `hardening-loop
ci-negative run --compare-run-id <id>`) when Actions cannot be dispatched. Evidence-side
negatives (invalid checksum, source-mismatched manifest, tampered file, path traversal) are unit
tests in `tests/test_scan_intake.py` and replay scenarios; they need no network.

## Devin assets

```bash
hardening-loop schemas export --check          # exported schemas match schemas.py
hardening-loop assets sync --dry-run           # live: list create/update/no-op per asset
hardening-loop assets sync                     # live: reconcile playbooks + knowledge, persist ids
hardening-loop assets sync --expect-noop       # live: exit 1 if anything changed
```

Playbooks live in `playbooks/*.md` (front matter + body), schemas in `playbooks/schemas/`, the
knowledge note in `knowledge/`, and the fork's environment blueprint copy in
`blueprint/superset.yaml`. Sync matches remote assets by persisted id, then by exact title/name,
and fails closed on ambiguity, malformed assets or API errors.

## Troubleshooting

| Symptom | Where to look |
|---|---|
| `doctor` fails on `database` | schema version mismatch: start from a fresh `HL_DATA_DIR`, or open with the matching code version |
| `ingest` shows `rejected` | `scan_intakes.reasons`; the bundle under `data/evidence/runs/<run id>/<attempt>/` |
| work item stuck in `needs_human` | `/issues/<id>` "next action" and `blocked_reason`; the issue's labels |
| Review never completes | `pull_requests.review_status`; controller escalates after `HL_REVIEW_TIMEOUT_MINUTES` |
| session `suspended` | `status_detail`; only `inactivity`/`user_request` are resumable, quota/credit states escalate |
| launch refused | capacity (`HL_MAX_CONCURRENT_SESSIONS`), budget (`HL_GLOBAL_ACU_BUDGET` minus reserved caps), duplicate tagged session, or missing `dispatch:approved` |
