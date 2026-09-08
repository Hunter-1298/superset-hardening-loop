# Superset Hardening Loop

Event-driven CVE detection and remediation for Apache Superset using Devin.

Controller for the `Hunter-1298/superset` fork: ingests SBOM + Trivy/Grype evidence
from the fork's CI, normalizes/classifies/groups findings into five kinds, opens GitHub
issues, dispatches and monitors Devin (v3 API) sessions with ACU caps and same-session
retries, tracks PR verification (`none → pr_opened → ci_green → review_completed →
human_approved → merged → rescan_verified`), and closes a finding only when a later
complete, source-matching scan of `main` proves it absent.

Baseline: Superset `6.1.0` = `c83fb2bb1dcfac41ac51bcebd82471f4a7180d18` (`fixtures/baseline/`).

## Quick start (no spend)

```bash
python3.12 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

hardening-loop replay --out data/replay      # R0-R20, N1-N5, DEMO; outbound network blocked
hardening-loop serve --replay --db data/replay/replay.sqlite3
# open http://127.0.0.1:8080
```

Or with Docker:

```bash
docker compose run --rm replay               # network_mode: none
HL_ACU_COST_USD=2.25 docker compose up dashboard   # http://localhost:8080, DB mounted :ro
```

`hardening-loop report --db <sqlite> [--upstream-sha <sha>] [--acu-cost-usd <usd>]`
prints the baseline/latest/upstream-master Markdown report.

## Layout

| Path | Purpose |
|---|---|
| `hardening_loop/ingest/` | Syft/Trivy/Grype parsers, normalization, dedupe, evidence hashing |
| `hardening_loop/classify/` | disjoint kind rules (deployment → disagreement → dependency → no-fix → container), grouping |
| `hardening_loop/orchestrator/` | state machine, dispatch, polling, retries, closure rules, engine |
| `hardening_loop/devin/`, `hardening_loop/github/` | typed v3 lifecycle enums/predicates, client protocols, in-memory fakes |
| `hardening_loop/replay/` | synthetic runs, world with manual clock, scenarios, zero-network guard |
| `hardening_loop/dashboard/`, `hardening_loop/report/`, `hardening_loop/metrics.py` | read-only FastAPI UI/JSON, DB-backed report, metric queries |
| `scripts/` | pinned scanner install (checksum-verified), image scan, baseline capture |
| `fixtures/` | committed baseline evidence and source pin snapshots |

## Configuration

All settings are `HL_`-prefixed environment variables (`hardening_loop/config.py`). Secrets
(`HL_DEVIN_API_KEY`, `HL_GITHUB_TOKEN`) are `SecretStr` and never logged. `HL_ACU_COST_USD`
has no default: cost is reported as `n/a` until it is set. `HL_SCAN_GATE_MODE=report|enforce`.

## Checks

```bash
ruff format --check . && ruff check . && mypy hardening_loop tests && pytest -q
```
