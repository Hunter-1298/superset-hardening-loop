# Settings

## Controller environment (`HL_*`)

All settings are read from the environment with the `HL_` prefix (`hardening_loop/config.py`,
pydantic-settings; no `.env` file is read). Secrets are `SecretStr` and are redacted from logs,
the dashboard and `doctor` output; `doctor` reports them as `set`/`unset` only.

| Variable | Default | Notes |
|---|---|---|
| `HL_GITHUB_TOKEN` | unset | fine-grained PAT scoped to `Hunter-1298/superset` only: Contents, Issues, Pull requests (read/write), Actions (read), Metadata |
| `HL_DEVIN_API_KEY` | unset | Devin v3 API key (service user preferred) |
| `HL_DEVIN_ORG_ID` | the demo org id | must match the org the key belongs to |
| `HL_DEVIN_API_BASE` | `https://api.devin.ai/v3` | v3 only |
| `HL_GITHUB_API_BASE` | `https://api.github.com` | |
| `HL_FORK_REPO` | `Hunter-1298/superset` | must stay inside the allowlist; `apache/superset` is refused at startup |
| `HL_REMEDIATION_BRANCH` | `main` | |
| `HL_SCAN_GATE_MODE` | `report` | `report` or `enforce`; stay in `report` until policy HIGH/CRITICAL is genuinely zero |
| `HL_MAX_CONCURRENT_SESSIONS` | `2` | live first run: `1` |
| `HL_GLOBAL_ACU_BUDGET` | `60` | live first run: `<= 5`; the unconsumed cap of every active session is reserved against it |
| `HL_RETRIES_PER_WORK_ITEM` | `2` | same-session retries before `failed` + `needs-human` |
| `HL_SESSION_WALL_CLOCK_MAX_HOURS` | `3` | |
| `HL_POLL_INTERVAL_SECONDS` | `60` | operator poll loop |
| `HL_REVIEW_TIMEOUT_MINUTES` | `30` | Devin Review pending/running longer than this escalates to `needs-human` |
| `HL_ACU_COST_USD` | unset | when set, cost columns are populated in metrics, report and snapshots |
| `HL_APPROVER_LOGINS` | `["Hunter-1298"]` | logins whose PR approval and VEX `x-approval` count |
| `HL_REQUIRED_CHECK_NAMES` | `[]` | JSON list. Empty = every check run present on the PR head must pass, including the fork's unrelated upstream CI; live: the ten `security-scan` job names |
| `HL_MAX_DISPATCH_FAILURES` | `3` | |
| `HL_OPERATOR_LOGIN` | unset | required for `serve --operator`; live first run: `Hunter-1298` |
| `HL_AUTO_DISPATCH` | `false` | `true` lets the scheduled loop create sessions on its own; live first run: `false` |
| `HL_AUTO_OPEN_ISSUES` | `true` | with auto-dispatch off, `true` opens a tracking issue for every queued work item on each tick; `false` opens the issue only when an item is launched. Live first run: `false` (exactly one issue for the one launch). Open issues with the controller label and a matching title are adopted, never duplicated |
| `HL_REPLAY_MODE` | `false` | |
| `HL_DATA_DIR` | `./data` | SQLite, evidence bundles, reports |
| `HL_DATABASE_FILE` | `hardening_loop.sqlite3` | |
| `HL_REPO_ROOT` | checkout root | where `fixtures/`, `playbooks/`, `knowledge/`, `blueprint/` live; the image sets `/app` |
| `HL_UPSTREAM_MASTER_SHA` | unset | `upstream-master` SHA whose source snapshot is in `fixtures/` (report comparison) |
| `HL_DASHBOARD_HOST` / `HL_DASHBOARD_PORT` | `127.0.0.1` / `8080` | `--operator` refuses non-loopback hosts |

Per-kind ACU caps are constants, not settings: dependency upgrade 5, no-fix/OpenVEX 8,
container hardening 20, scanner disagreement 3, Helm/deployment 6.

## Bounded first-live-run profile (`doctor --live`)

```
HL_OPERATOR_LOGIN=Hunter-1298
HL_AUTO_DISPATCH=false
HL_AUTO_OPEN_ISSUES=false
HL_MAX_CONCURRENT_SESSIONS=1
HL_GLOBAL_ACU_BUDGET=5
HL_SCAN_GATE_MODE=report
HL_REPLAY_MODE=false
HL_REQUIRED_CHECK_NAMES='["forbid-ignore-files","vex-lint","build-image","scan-lean-raw","scan-lean-policy","scan-ci-raw","policy-gate","lean-smoke","app-runs","scan-manifest"]'
```

plus both credentials set, the database at the current schema, committed assets valid,
exported schemas current, Devin assets synced, and baseline fixtures verified.
`doctor --live` does not check `HL_REQUIRED_CHECK_NAMES`; set it anyway so that only the
security-scan jobs decide whether a PR head is green.

## Fork repository settings (to be applied by a repository admin)

The controller token cannot change repository settings (GitHub returns 403) and the controller
never tries. Apply these in `Hunter-1298/superset`:

1. **Settings → General → Default branch**: `main`.
2. **Branches → Add rule for `main`**: require a pull request before merging, 1 approval,
   dismiss stale approvals on new commits, block force pushes, block deletion. Add required
   status checks only after `security-scan` has completed successfully on `main`; the job names
   are `forbid-ignore-files`, `vex-lint`, `build-image`, `scan-lean-raw`, `scan-lean-policy`,
   `scan-ci-raw`, `policy-gate`, `lean-smoke`, `app-runs`, `scan-manifest`.
3. **Branches → Add rule for `upstream-master`**: block force pushes, block deletion.
4. **Actions → General**: allow GitHub Actions; workflow permissions "Read repository
   contents and packages" (the `security-scan` workflow requests `packages: write`,
   `id-token: write` and `attestations: write` for GHCR pushes and signed build provenance
   explicitly, per job).
5. **Controller pin**: `security-scan.yml` and `evidence-negatives.yml` install the CLI from the
   full commit SHA in their `CONTROLLER_REF`; push, pull request and scheduled runs refuse any
   other ref, and only a manual dispatch may pass `controller_ref` to try a branch (its evidence
   is marked non-reproducible). Bumping the pin is a reviewed pull request in the fork; there is
   no repository variable to set.
6. **Labels**: create `hardening-loop`, `awaiting-dispatch-approval`, `dispatch:approved`,
   `needs-human`, `retry`, `disposition:approved`, `disagreement:resolved`, `risk:high`,
   `kind:dependency-upgrade`, `kind:no-fix-reachability`, `kind:container-hardening`,
   `kind:scanner-disagreement`, `kind:helm-deploy-config`, `severity:critical`,
   `severity:high`, `severity:medium`, `severity:low`. GitHub creates missing labels on first
   use with the token's default colour; pre-creating them only sets colours/descriptions.

## Controller repository settings

1. **Actions → Secrets**: `FORK_TOKEN` — PAT scoped to `Hunter-1298/superset` (Contents,
   Pull requests, Actions read) for the operator-triggered `ci-negative` workflow only.
2. **Branches → `main`**: require a pull request, block force pushes; required check
   `controller-ci` once it has run.

## Devin

* Playbooks and the knowledge note are created/updated by `hardening-loop assets sync`; their
  ids are persisted in `devin_assets` and reused on dispatch.
* The fork's environment blueprint is `blueprint/superset.yaml`; apply it to the
  `Hunter-1298/superset` repository environment in Devin settings (it is not applied by the
  controller).
* Sessions are created as Normal sessions, tagged `wi-<work item id>` for duplicate detection,
  with `max_acu_limit` set to the kind's cap and the kind's structured-output schema attached.
