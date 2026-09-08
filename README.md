# Superset Hardening Loop

A controller that turns CVE scan evidence from a Superset fork into bounded Devin remediation
sessions, verifies the pull requests they open, and closes a finding only when a later complete
scan of `main` proves it is gone.

```text
security-scan on fork main  →  evidence bundle (Trivy + Grype raw & policy, SBOM, manifest, checksums)
        ↓ ingest (checksum + source verified, idempotent)
findings → work items → Launch Devin (dashboard) → one capped session → PR to fork main
        ↓ controller verifies: repo/base, diff policy, exact-head CI, Devin Review
you review and merge in GitHub → next scan of main → finding absent → rescan_verified, issue closed
```

Two repositories are involved:

| | |
|---|---|
| `Hunter-1298/superset` | the fork that is scanned and remediated (`main` = Superset `6.1.0`, baseline `c83fb2bb1dcfac41ac51bcebd82471f4a7180d18`). Its `security-scan` workflow runs on every push to `main`, every PR, nightly, and on demand. |
| `Hunter-1298/superset-hardening-loop` | this repository: the controller CLI and dashboard. |

`apache/superset` is never written to. The controller never approves or merges anything.

## Prerequisites

* Python 3.12 (`python3.12 --version`).
* A GitHub fine-grained personal access token scoped to `Hunter-1298/superset` only, with
  Contents, Issues and Pull requests read/write, Actions read, Metadata read.
* A Devin API key (v3) for the org that owns the playbooks.
* Docker only if you want the containerised replay.

## 1. Install

```bash
git clone https://github.com/Hunter-1298/superset-hardening-loop.git
cd superset-hardening-loop
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
hardening-loop --help
```

## 2. Try it without spending anything

The replay runs the whole lifecycle (ingest, issue, session, PR, CI, Review, merge, rescan,
closure, plus the negative cases) against in-memory fakes with outbound network blocked, and
then serves the resulting database:

```bash
hardening-loop replay --out data/replay
hardening-loop serve --replay --db data/replay/replay.sqlite3
```

To click **Launch Devin** yourself without credentials, run operator mode against the
in-memory GitHub and Devin doubles:

```bash
hardening-loop serve --operator --doubles --operator-login you
```

Both serve on `http://127.0.0.1:8080`.

## 3. Run it live

### 3.1 Environment

Settings are read from `HL_`-prefixed environment variables (no `.env` file is read). Export
the two secrets without echoing them, then the bounded profile:

```bash
export HL_GITHUB_TOKEN=…            # never printed; doctor reports set/unset only
export HL_DEVIN_API_KEY=…

export HL_OPERATOR_LOGIN=Hunter-1298
export HL_AUTO_DISPATCH=false        # only a click in the dashboard creates a session
export HL_AUTO_OPEN_ISSUES=false     # the tracking issue is opened at launch, not on every tick
export HL_MAX_CONCURRENT_SESSIONS=1
export HL_GLOBAL_ACU_BUDGET=5        # hard ceiling across all active sessions
export HL_SCAN_GATE_MODE=report
export HL_REPLAY_MODE=false
export HL_DATA_DIR=data/live         # SQLite, evidence bundles and reports land here
export HL_REQUIRED_CHECK_NAMES='["forbid-ignore-files","vex-lint","build-image","scan-lean-raw","scan-lean-policy","scan-ci-raw","policy-gate","lean-smoke","app-runs","scan-manifest"]'
```

`HL_REQUIRED_CHECK_NAMES` matters: left empty, every check on the PR head must pass, and the
fork's unrelated upstream CI (for example the Homebrew `pre-commit` job) would drive retries.
The ten names above are the fork's `security-scan` jobs. Optional: `HL_ACU_COST_USD=<usd>`
populates the cost columns. The full list is in [docs/settings.md](docs/settings.md).

### 3.2 Preflight and assets

```bash
hardening-loop doctor --live                 # fails closed on anything outside the profile
hardening-loop assets sync                   # creates/updates the five playbooks + knowledge note
hardening-loop assets sync --expect-noop     # second pass must change nothing
```

### 3.3 Start the dashboard

```bash
hardening-loop serve --operator --port 8080
```

Open `http://127.0.0.1:8080/`. Operator mode binds to loopback only; it has no login of its
own, so if you need it reachable from elsewhere put an authenticating TLS proxy in front of it.
The poll loop runs inside this process (every `HL_POLL_INTERVAL_SECONDS`, default 60): it
discovers completed `security-scan` runs on fork `main`, verifies and ingests their evidence,
and polls sessions, PRs, checks, Devin Review and rescans. Run exactly one operator process
per database.

To ingest a specific run by hand instead of waiting for the poll:

```bash
hardening-loop ingest --run-id <actions run id>          # second run of the same id is a no-op
```

### 3.4 Fix a CVE

1. **Vulnerabilities** lists every finding from the latest scan; click a CVE to see the
   advisory, CVSS, fix version per scanner, scanner agreement and its sighting history.
2. Follow the link to its **work item** (related CVEs on one package share an item), or open
   **Work items** and filter by kind *Dependency upgrade* for the smallest safe changes.
3. Click **Launch Devin**. The preview page shows exactly what will happen: the tracking issue
   is opened in the fork, one Devin session is created with the kind's ACU cap and playbook,
   and it must open a PR against fork `main`. The launch is refused if a session for that
   item already exists, the concurrency slot is taken, or the budget would be exceeded.
4. Watch the item move through *Devin working → PR in CI → Awaiting your review*. The
   controller records the PR only after it targets the right repo and branch, passes the diff
   policy, has the required checks green on the exact head, and Devin Review has completed
   on that head.
5. Review, approve and merge the PR in GitHub yourself.
6. The merge triggers `security-scan` on `main`. When that run completes, the controller
   ingests it; if neither scanner reports the CVEs any more, the findings become *fixed*, the
   item becomes *Verified*, and the controller closes the tracking issue with the evidence.

If checks fail, the controller sends the failure back to the same session (at most
`HL_RETRIES_PER_WORK_ITEM` times, never past the ACU cap) before parking the item as
*Needs attention*. Adding the `retry` label to the issue and launching again adopts the
existing session rather than creating a new one.

### 3.5 Report

```bash
hardening-loop report --out data/live/reports/report.md [--acu-cost-usd 2.25] [--persist]
```

The same numbers are on the dashboard at `/report` (Markdown at `/report.md`) and as JSON at
`/api/report` and `/api/metrics`.

## Layout

| Path | Purpose |
|---|---|
| `hardening_loop/ingest/` | Syft/Trivy/Grype parsers, normalisation, dedupe, evidence hashing |
| `hardening_loop/classify/` | disjoint kind rules (deployment → disagreement → dependency → no-fix → container), grouping |
| `hardening_loop/orchestrator/` | state machine, dispatch, polling, retries, closure rules, engine |
| `hardening_loop/devin/`, `hardening_loop/github/` | typed v3 lifecycle enums/predicates, client protocols, REST clients, in-memory fakes |
| `hardening_loop/operator.py` | operator runtime: live/doubles orchestrator builders, APScheduler poll loop |
| `hardening_loop/replay/` | synthetic runs, world with manual clock, scenarios, zero-network guard |
| `hardening_loop/dashboard/`, `hardening_loop/report/`, `hardening_loop/metrics.py` | FastAPI UI/JSON (read-only unless `--operator`), CVE pages, DB-backed report, metric queries |
| `scripts/` | pinned scanner install (checksum-verified), image scan, baseline capture |
| `fixtures/` | committed baseline evidence and source pin snapshots |
| `playbooks/`, `knowledge/`, `blueprint/` | Devin playbooks + exported structured-output schemas, knowledge note, fork environment blueprint (`assets sync`) |
| `docs/` | [runbook](docs/runbook.md), [settings](docs/settings.md), [first live run](docs/live-run.md), [Loom script](docs/loom-script.md) |

## Other commands

| Command | Use |
|---|---|
| `hardening-loop evidence-verify <dir> --run-id … --head-sha …` | offline: apply intake's fail-closed checks to a downloaded bundle |
| `hardening-loop gate`, `vex-lint`, `forbid-ignore-files`, `scan-manifest` | run inside the fork's `security-scan` workflow |
| `hardening-loop ci-negative` | operator-triggered negative suite against the fork |
| `hardening-loop metrics`, `schemas` | persisted metric snapshots; structured-output schemas |
| `docker compose run --rm replay` | the replay inside `network_mode: none` |
| `docker compose up dashboard` | read-only dashboard on `http://localhost:8080` |

## Development checks

```bash
ruff format --check . && ruff check . && mypy hardening_loop tests && pytest -q
```
