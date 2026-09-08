"""`hardening-loop doctor`: every precondition of a live run, checked without spending anything.

No network call is made. Credentials are reported by presence only (`HL_GITHUB_TOKEN: set`), never
by value or length. `--live` additionally requires the bounded first-run profile the runbook
demands: `HL_OPERATOR_LOGIN=Hunter-1298`, `HL_AUTO_DISPATCH=false`, `HL_MAX_CONCURRENT_SESSIONS=1`,
a global ACU budget of at most 5, `SCAN_GATE_MODE=report`, and Devin assets already synced."""

from __future__ import annotations

import sqlite3
from dataclasses import asdict, dataclass, field
from typing import Literal

from sqlmodel import col, func, select

from hardening_loop.config import BASELINE_SHA, REPO_ALLOWLIST, Settings
from hardening_loop.db import SCHEMA_VERSION, open_database, session_scope
from hardening_loop.devin.assets import AssetError, load_assets, persisted_assets
from hardening_loop.devin.schemas import export_schemas
from hardening_loop.domain.enums import GateMode, WorkItemState
from hardening_loop.ingest.evidence import EvidenceError, load_baseline
from hardening_loop.models.tables import ScanRun, Session, WorkItem

LIVE_OPERATOR_LOGIN = "Hunter-1298"
LIVE_MAX_CONCURRENT = 1
LIVE_ACU_BUDGET = 5.0

Level = Literal["ok", "warn", "fail"]


@dataclass(frozen=True)
class Check:
    name: str
    level: Level
    detail: str


@dataclass
class DoctorReport:
    live: bool
    checks: list[Check] = field(default_factory=list)

    def add(self, name: str, level: Level, detail: str) -> None:
        self.checks.append(Check(name, level, detail))

    @property
    def ok(self) -> bool:
        return not any(c.level == "fail" for c in self.checks)

    def to_dict(self) -> dict[str, object]:
        return {"live": self.live, "ok": self.ok, "checks": [asdict(c) for c in self.checks]}

    def render(self) -> str:
        width = max(len(c.name) for c in self.checks) if self.checks else 0
        lines = [f"[{c.level:4}] {c.name.ljust(width)}  {c.detail}" for c in self.checks]
        lines.append("doctor: " + ("all checks passed" if self.ok else "FAILED"))
        return "\n".join(lines)


def run_doctor(settings: Settings, *, live: bool = False) -> DoctorReport:
    r = DoctorReport(live=live)
    _credentials(r, settings, live)
    _profile(r, settings, live)
    _database(r, settings, live)
    _assets(r, settings, live)
    _fixtures(r, settings)
    return r


def _credentials(r: DoctorReport, s: Settings, live: bool) -> None:
    need: Level = "fail" if live else "warn"
    r.add(
        "HL_GITHUB_TOKEN",
        "ok" if s.github_token is not None else need,
        "set" if s.github_token is not None else "unset (required for live runs)",
    )
    r.add(
        "HL_DEVIN_API_KEY",
        "ok" if s.devin_api_key is not None else need,
        "set" if s.devin_api_key is not None else "unset (required for live runs)",
    )
    org_ok = s.devin_org_id.startswith("org-")
    r.add("HL_DEVIN_ORG_ID", "ok" if org_ok else "fail", s.devin_org_id if org_ok else "malformed")
    r.add(
        "HL_DEVIN_API_BASE",
        "ok" if s.devin_api_base.rstrip("/").endswith("/v3") else "fail",
        s.devin_api_base,
    )


def _profile(r: DoctorReport, s: Settings, live: bool) -> None:
    r.add(
        "fork repo",
        "ok" if s.fork_repo in REPO_ALLOWLIST else "fail",
        f"{s.fork_repo} (allowlist {sorted(REPO_ALLOWLIST)})",
    )
    r.add(
        "remediation branch",
        "ok" if s.remediation_branch == "main" else "fail",
        s.remediation_branch,
    )
    r.add("baseline sha", "ok", BASELINE_SHA)

    login_ok = bool(s.operator_login) and (not live or s.operator_login == LIVE_OPERATOR_LOGIN)
    r.add(
        "HL_OPERATOR_LOGIN",
        "ok" if login_ok else ("fail" if live else "warn"),
        s.operator_login or "unset",
    )
    r.add(
        "HL_AUTO_DISPATCH",
        "fail" if (live and s.auto_dispatch) else "ok",
        str(s.auto_dispatch).lower() + (" (live runs require false)" if live else ""),
    )
    r.add(
        "HL_AUTO_OPEN_ISSUES",
        "fail" if (live and s.auto_open_issues) else "ok",
        str(s.auto_open_issues).lower()
        + (" (live runs require false: one issue per explicit launch)" if live else ""),
    )
    conc_ok = not live or s.max_concurrent_sessions == LIVE_MAX_CONCURRENT
    r.add(
        "HL_MAX_CONCURRENT_SESSIONS",
        "ok" if conc_ok else "fail",
        f"{s.max_concurrent_sessions}"
        + (f" (live runs require {LIVE_MAX_CONCURRENT})" if live else ""),
    )
    budget_ok = not live or s.global_acu_budget <= LIVE_ACU_BUDGET
    r.add(
        "HL_GLOBAL_ACU_BUDGET",
        "ok" if budget_ok else "fail",
        f"{s.global_acu_budget:g} ACU"
        + (f" (live runs require <= {LIVE_ACU_BUDGET:g})" if live else ""),
    )
    r.add(
        "SCAN_GATE_MODE",
        "ok" if s.scan_gate_mode is GateMode.report or not live else "fail",
        s.scan_gate_mode.value,
    )
    r.add("replay mode", "fail" if (live and s.replay_mode) else "ok", str(s.replay_mode).lower())
    r.add("approver logins", "ok" if s.approver_logins else "fail", ", ".join(s.approver_logins))


def _database(r: DoctorReport, s: Settings, live: bool) -> None:
    path = s.database_path
    if not path.exists():
        r.add("database", "warn" if not live else "fail", f"{path} does not exist yet")
        return
    try:
        with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as raw:
            row = raw.execute("SELECT MAX(version) FROM schema_version").fetchone()
    except sqlite3.Error as exc:
        r.add("database", "fail", f"{path}: {exc}")
        return
    version = row[0] if row else None
    if version != SCHEMA_VERSION:
        r.add("database", "fail", f"{path}: schema {version} != code {SCHEMA_VERSION}")
        return
    r.add("database", "ok", f"{path} (schema {version})")
    engine = open_database(path)
    with session_scope(engine) as db:
        runs = db.exec(select(func.count(col(ScanRun.id)))).one()
        items = db.exec(select(func.count(col(WorkItem.id)))).one()
        stuck = db.exec(
            select(func.count(col(WorkItem.id))).where(WorkItem.state == WorkItemState.dispatching)
        ).one()
        active = db.exec(
            select(func.count(col(Session.id))).where(col(Session.finished_at).is_(None))
        ).one()
    r.add("scan runs", "ok" if runs else "warn", f"{runs} persisted")
    r.add("work items", "ok", f"{items} total")
    r.add(
        "stuck dispatching",
        "ok" if stuck == 0 else "warn",
        f"{stuck} (recovered on the next tick)" if stuck else "0",
    )
    r.add(
        "active sessions",
        "ok" if active <= s.max_concurrent_sessions else "fail",
        f"{active} of {s.max_concurrent_sessions} allowed",
    )


def _assets(r: DoctorReport, s: Settings, live: bool) -> None:
    try:
        bundle = load_assets(s.repo_root)
    except (AssetError, OSError) as exc:
        r.add("committed assets", "fail", str(exc))
        return
    r.add(
        "committed assets",
        "ok",
        f"{len(bundle.playbooks)} playbooks, {len(bundle.knowledge)} knowledge note(s)",
    )
    blueprint = s.repo_root / "blueprint" / "superset.yaml"
    blueprint_ok = blueprint.is_file() and "initialize:" in blueprint.read_text(encoding="utf-8")
    r.add(
        "fork blueprint",
        "ok" if blueprint_ok else "fail",
        "blueprint/superset.yaml present" if blueprint_ok else f"{blueprint} missing or empty",
    )
    exported = export_schemas(s.repo_root / "playbooks" / "schemas", write=False)
    r.add(
        "exported schemas",
        "ok" if not exported else "fail",
        "match schemas.py" if not exported else f"stale: {sorted(exported)}; run `schemas export`",
    )
    if not s.database_path.exists():
        r.add("devin assets synced", "warn" if not live else "fail", "no database yet")
        return
    try:
        engine = open_database(s.database_path)
    except RuntimeError as exc:
        r.add("devin assets synced", "fail", f"cannot open database: {exc}")
        return
    state = persisted_assets(engine, bundle)
    if state.ok:
        r.add(
            "devin assets synced",
            "ok",
            f"{len(state.playbook_ids)} playbook ids, {len(state.knowledge_ids)} knowledge id(s)",
        )
    else:
        r.add(
            "devin assets synced",
            "fail" if live else "warn",
            f"missing={state.missing} drifted={state.drifted}; run `hardening-loop assets sync`",
        )


def _fixtures(r: DoctorReport, s: Settings) -> None:
    path = s.repo_root / "fixtures" / "baseline" / BASELINE_SHA
    try:
        baseline = load_baseline(path)
    except (EvidenceError, OSError, KeyError, ValueError) as exc:
        r.add("baseline fixtures", "fail", f"{path}: {exc}")
        return
    r.add("baseline fixtures", "ok", f"{len(baseline.jobs)} jobs, checksums verified")


__all__ = ["Check", "DoctorReport", "run_doctor"]
