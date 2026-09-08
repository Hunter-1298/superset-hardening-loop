"""Operator runtime: the writable side of `serve --operator`.

Plain `serve` opens SQLite read-only and rejects every non-GET request. Operator mode instead
owns a real `Orchestrator` (live GitHub + Devin v3 clients, or the fakes for a no-spend demo),
runs the poll loop on an APScheduler background scheduler, and exposes exactly one write to the
dashboard: `OperatorContext.launch()`. One process-wide lock serialises launches against ticks so
the SQLite state machine is never driven from two threads at once.

Replay mode is incompatible with live clients by construction: `build_live_orchestrator` refuses
`replay_mode=True`, and `OperatorContext.for_doubles` is the only way to get fakes in here."""

from __future__ import annotations

import ipaddress
import logging
import secrets
import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy.engine import Engine
from sqlmodel import select

from hardening_loop.config import BASELINE_SHA, Settings
from hardening_loop.db import open_database, session_scope
from hardening_loop.devin.assets import load_assets, persisted_assets
from hardening_loop.devin.fake import FakeDevin
from hardening_loop.devin.rest import DevinRest
from hardening_loop.github.fake import FakeGitHub
from hardening_loop.github.rest import GitHubRest
from hardening_loop.metrics import snapshot_metrics
from hardening_loop.models.tables import ScanRun
from hardening_loop.orchestrator.engine import Orchestrator, TickReport
from hardening_loop.orchestrator.launch import LaunchPreview, LaunchResult
from hardening_loop.replay.synth import CONFIG_SEEDS, SEEDS, SyntheticRun, ingest_synthetic

log = logging.getLogger("hardening_loop.operator")


class OperatorConfigError(RuntimeError):
    pass


def require_loopback_bind(host: str) -> None:
    """The launch route is unauthenticated beyond its CSRF token and is served over plain HTTP,
    so operator mode only binds loopback. Anything else must sit behind an authenticating
    TLS proxy, which is a deliberate deployment decision rather than a default."""
    if host.strip().lower() == "localhost":
        return
    try:
        if ipaddress.ip_address(host.strip().strip("[]")).is_loopback:
            return
    except ValueError:
        pass
    raise OperatorConfigError(
        f"operator mode binds loopback only (got --host {host!r}); the launch route has no "
        "authentication of its own, so put an authenticating TLS proxy in front instead"
    )


def build_live_orchestrator(settings: Settings, *, engine: Engine | None = None) -> Orchestrator:
    """Live clients from settings. Every missing precondition is a hard error with a
    remediation hint; nothing is defaulted or guessed."""
    if settings.replay_mode:
        raise OperatorConfigError("replay mode never talks to GitHub or Devin; drop --replay")
    if settings.github_token is None:
        raise OperatorConfigError("HL_GITHUB_TOKEN is required for operator mode")
    if settings.devin_api_key is None:
        raise OperatorConfigError("HL_DEVIN_API_KEY is required for operator mode")
    if not settings.operator_login:
        raise OperatorConfigError(
            "HL_OPERATOR_LOGIN (the GitHub login recorded on every launch) is required"
        )
    engine = engine or open_database(settings.database_path)
    assets = persisted_assets(engine, load_assets(settings.repo_root))
    if not assets.ok:
        raise OperatorConfigError(
            "Devin assets are not in sync with the committed playbooks/knowledge "
            f"(missing={assets.missing}, drifted={assets.drifted}); "
            "run `hardening-loop assets sync`"
        )
    gh = GitHubRest(settings.github_token, api_base=settings.github_api_base)
    devin = DevinRest(
        settings.devin_api_key, settings.devin_org_id, api_base=settings.devin_api_base
    )
    return Orchestrator(
        engine,
        gh,
        devin,
        settings,
        playbook_ids=assets.playbook_ids,
        knowledge_ids=assets.knowledge_ids,
    )


def build_doubles_orchestrator(settings: Settings, *, engine: Engine | None = None) -> Orchestrator:
    """No-spend operator demo: the same orchestrator over the in-memory GitHub and Devin doubles
    the replay suite uses. An empty database is seeded with the synthetic baseline and its work
    items get issues opened, but nothing is dispatched until an operator launches it."""
    if settings.replay_mode:
        raise OperatorConfigError("replay databases are served read-only; drop --replay")
    if not settings.operator_login:
        raise OperatorConfigError("HL_OPERATOR_LOGIN is required for operator mode")
    engine = engine or open_database(settings.database_path)
    orch = Orchestrator(engine, FakeGitHub(main_head=BASELINE_SHA), FakeDevin(), settings)
    with session_scope(engine) as db:
        empty = db.exec(select(ScanRun.id)).first() is None
    if empty:
        run = SyntheticRun(source_sha=BASELINE_SHA, is_baseline=True).with_seeds(*SEEDS)
        run.with_configs(*CONFIG_SEEDS)
        ingest_synthetic(engine, run, "doubles-baseline")
        orch.tick(auto_dispatch=False)
    return orch


@dataclass
class OperatorContext:
    """What the dashboard needs to offer "Launch Devin" safely."""

    orchestrator: Orchestrator
    login: str
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    lock: threading.Lock = field(default_factory=threading.Lock)
    auto_dispatch: bool = False

    @property
    def engine(self) -> Engine:
        return self.orchestrator.engine

    @property
    def live(self) -> bool:
        return not isinstance(self.orchestrator.gh, FakeGitHub)

    def preview(self, work_item_id: int) -> LaunchPreview:
        with self.lock:
            return self.orchestrator.launch_preview(work_item_id)

    def launch(self, work_item_id: int) -> LaunchResult:
        with self.lock:
            return self.orchestrator.launch(work_item_id, operator=self.login)

    def tick(self) -> TickReport:
        """One control-loop iteration followed by a persisted metrics snapshot, so the trend
        survives restarts even when nothing else changed."""
        with self.lock:
            report = self.orchestrator.tick(auto_dispatch=self.auto_dispatch)
            snapshot_metrics(
                self.engine,
                trigger="tick",
                acu_cost_usd=self.orchestrator.settings.acu_cost_usd,
                now=datetime.now(UTC),
            )
            return report

    @classmethod
    def for_doubles(cls, orchestrator: Orchestrator, *, login: str) -> OperatorContext:
        """Fakes only: the same dashboard action with zero outbound calls. Refuses a live client
        so a misconfiguration cannot spend."""
        if not isinstance(orchestrator.gh, FakeGitHub) or not isinstance(
            orchestrator.devin, FakeDevin
        ):
            raise OperatorConfigError("for_doubles requires FakeGitHub and FakeDevin")
        return cls(orchestrator, login, auto_dispatch=False)


class OperatorRuntime:
    """Runs `ctx.tick()` every `poll_interval_seconds` next to the web server."""

    def __init__(self, ctx: OperatorContext, *, poll_interval_seconds: int) -> None:
        self.ctx = ctx
        self.interval = poll_interval_seconds
        self.scheduler = BackgroundScheduler(timezone="UTC")
        self.ticks = 0
        self.last_error: str | None = None

    def _job(self) -> None:
        try:
            report = self.ctx.tick()
            self.ticks += 1
            self.last_error = None
            log.info("tick %d: %s", self.ticks, report)
        except Exception as exc:  # the loop must survive one bad poll
            self.last_error = f"{exc.__class__.__name__}: {exc}"[:300]
            log.exception("tick failed")

    def start(self) -> None:
        self.scheduler.add_job(
            self._job,
            "interval",
            seconds=self.interval,
            id="tick",
            max_instances=1,
            coalesce=True,
        )
        self.scheduler.start()

    def stop(self) -> None:
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)


__all__ = [
    "OperatorConfigError",
    "OperatorContext",
    "OperatorRuntime",
    "build_doubles_orchestrator",
    "build_live_orchestrator",
]
