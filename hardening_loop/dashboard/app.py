"""Read-only FastAPI dashboard over the controller database.

Every page and API endpoint is a pure read of SQLite; the app rejects any non-safe HTTP method
so it can never approve, merge, dispatch, or mutate state. Approvals stay in GitHub."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy.engine import Engine
from sqlmodel import and_, col, or_, select

from hardening_loop.config import COMPARISON_BRANCH, Settings
from hardening_loop.db import open_database_readonly, session_scope
from hardening_loop.domain.enums import Kind, VerificationLevel
from hardening_loop.metrics import Metrics, compute_metrics
from hardening_loop.models.tables import (
    Event,
    Finding,
    PRCheck,
    PullRequest,
    ScanJob,
    ScanRun,
    Session,
    SessionPoll,
    WorkItem,
)
from hardening_loop.report.run_report import (
    ReportBody,
    build_report,
    latest_persisted_report,
    render_markdown,
    upstream_pins_from_fixture,
)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
TEMPLATES_DIR = Path(__file__).parent / "templates"
MAX_ROWS = 2000


def _kind_label(value: object) -> str:
    try:
        return Kind(int(str(value))).name
    except (ValueError, TypeError):
        return str(value)


def _level_label(value: object) -> str:
    try:
        return VerificationLevel(int(str(value))).label
    except (ValueError, TypeError):
        return str(value)


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def _num(value: float | None, digits: int = 2) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _money(value: float | None) -> str:
    return "n/a" if value is None else f"${value:,.2f}"


def _short(sha: str | None) -> str:
    return (sha or "")[:12]


def _templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    templates.env.filters["kind"] = _kind_label
    templates.env.filters["level"] = _level_label
    templates.env.filters["pct"] = _pct
    templates.env.filters["num"] = _num
    templates.env.filters["money"] = _money
    templates.env.filters["short"] = _short
    return templates


def build_report_for(engine: Engine, settings: Settings, now: datetime) -> ReportBody:
    pins: dict[str, str] | None = None
    source: str | None = None
    problem: str | None = None
    sha = settings.upstream_master_sha
    if sha is not None:
        try:
            pins = upstream_pins_from_fixture(settings.repo_root, sha)
            source = f"fixtures/source/{sha}/requirements-base.txt"
        except (OSError, ValueError) as exc:
            problem = f"upstream-master fixture for {sha[:12]} unreadable: {exc}"
    body = build_report(
        engine,
        fork_repo=settings.fork_repo,
        branch=settings.remediation_branch,
        acu_cost_usd=settings.acu_cost_usd,
        now=now,
        upstream_master_sha=sha,
        upstream_pins=pins,
        upstream_pins_source=source,
    )
    if problem is not None:
        body.notes.append(problem)
    elif sha is None:
        body.notes.append("HL_UPSTREAM_MASTER_SHA unset: no upstream-master comparison")
    return body


def create_app(settings: Settings | None = None, *, engine: Engine | None = None) -> FastAPI:
    settings = settings or Settings()
    engine = engine or open_database_readonly(settings.database_path)
    app = FastAPI(title="Superset hardening loop", docs_url="/api/docs", redoc_url=None)
    app.state.settings = settings
    app.state.engine = engine
    templates = _templates()

    @app.middleware("http")
    async def read_only(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method not in SAFE_METHODS:
            return JSONResponse(
                {"detail": "dashboard is read-only; approvals and merges happen in GitHub"},
                status_code=405,
                headers={"Allow": "GET, HEAD, OPTIONS"},
            )
        return await call_next(request)

    def metrics() -> Metrics:
        return compute_metrics(engine, acu_cost_usd=settings.acu_cost_usd, now=datetime.now(UTC))

    def render(request: Request, name: str, **ctx: Any) -> HTMLResponse:
        base = {
            "request": request,
            "fork_repo": settings.fork_repo,
            "branch": settings.remediation_branch,
            "comparison_branch": COMPARISON_BRANCH,
            "gate_mode": settings.scan_gate_mode.value,
            "replay_mode": settings.replay_mode,
            "database": str(settings.database_path),
        }
        return templates.TemplateResponse(request, name, {**base, **ctx})

    # ------------------------------------------------------------------------------ pages

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        m = metrics()
        return render(request, "index.html", m=m, runs=m.runs[-10:][::-1])

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request) -> HTMLResponse:
        return render(request, "runs.html", runs=metrics().runs[::-1])

    @app.get("/runs/{run_id}", response_class=HTMLResponse)
    def run_page(request: Request, run_id: int) -> HTMLResponse:
        with session_scope(engine) as db:
            run = db.get(ScanRun, run_id)
            if run is None:
                raise HTTPException(404, f"scan run {run_id} not found")
            jobs = db.exec(
                select(ScanJob).where(ScanJob.scan_run_id == run_id).order_by(col(ScanJob.name))
            ).all()
            events = db.exec(
                select(Event)
                .where(Event.entity_type == "scan_run", Event.entity_id == run_id)
                .order_by(col(Event.ts))
            ).all()
            findings = db.exec(
                select(Finding)
                .where(
                    or_(
                        col(Finding.first_seen_run_id) == run_id,
                        col(Finding.closed_by_run_id) == run_id,
                    )
                )
                .order_by(col(Finding.severity), col(Finding.vuln_id))
                .limit(MAX_ROWS)
            ).all()
            m = metrics()
            summary = next((r for r in m.runs if r.id == run_id), None)
            return render(
                request,
                "run.html",
                run=run,
                summary=summary,
                jobs=jobs,
                events=events,
                findings=findings,
            )

    @app.get("/findings", response_class=HTMLResponse)
    def findings_page(
        request: Request,
        kind: int | None = Query(default=None),
        state: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        layer: str | None = Query(default=None),
        run: int | None = Query(default=None),
    ) -> HTMLResponse:
        with session_scope(engine) as db:
            stmt = select(Finding)
            if kind is not None:
                stmt = stmt.where(Finding.kind == Kind(kind))
            if state is not None:
                stmt = stmt.where(col(Finding.state) == state)
            if severity is not None:
                stmt = stmt.where(col(Finding.severity) == severity.upper())
            if layer is not None:
                stmt = stmt.where(col(Finding.layer) == layer)
            if run is not None:
                stmt = stmt.where(Finding.first_seen_run_id == run)
            rows = db.exec(
                stmt.order_by(col(Finding.severity), col(Finding.vuln_id)).limit(MAX_ROWS)
            ).all()
            return render(
                request,
                "findings.html",
                findings=rows,
                filters={
                    "kind": kind,
                    "state": state,
                    "severity": severity,
                    "layer": layer,
                    "run": run,
                },
            )

    @app.get("/issues", response_class=HTMLResponse)
    def issues_page(
        request: Request,
        state: str | None = Query(default=None),
        kind: int | None = Query(default=None),
    ) -> HTMLResponse:
        with session_scope(engine) as db:
            stmt = select(WorkItem)
            if state is not None:
                stmt = stmt.where(col(WorkItem.state) == state)
            if kind is not None:
                stmt = stmt.where(WorkItem.kind == Kind(kind))
            items = db.exec(stmt.order_by(col(WorkItem.id).desc()).limit(MAX_ROWS)).all()
            sessions = db.exec(select(Session)).all()
            acu_by_wi: dict[int, float] = {}
            for s in sessions:
                acu_by_wi[s.work_item_id] = acu_by_wi.get(s.work_item_id, 0.0) + s.acus_consumed
            return render(
                request,
                "issues.html",
                items=items,
                acu_by_wi=acu_by_wi,
                acu_cost_usd=settings.acu_cost_usd,
                filters={"state": state, "kind": kind},
            )

    @app.get("/issues/{wi_id}", response_class=HTMLResponse)
    def issue_page(request: Request, wi_id: int) -> HTMLResponse:
        with session_scope(engine) as db:
            wi = db.get(WorkItem, wi_id)
            if wi is None:
                raise HTTPException(404, f"work item {wi_id} not found")
            members = db.exec(
                select(Finding).where(Finding.work_item_id == wi_id).order_by(col(Finding.vuln_id))
            ).all()
            sessions = db.exec(
                select(Session).where(Session.work_item_id == wi_id).order_by(col(Session.id))
            ).all()
            polls = db.exec(
                select(SessionPoll)
                .where(col(SessionPoll.session_id).in_([s.id for s in sessions if s.id]))
                .order_by(col(SessionPoll.polled_at))
            ).all()
            prs = db.exec(select(PullRequest).where(PullRequest.work_item_id == wi_id)).all()
            checks = db.exec(
                select(PRCheck)
                .where(col(PRCheck.pull_request_id).in_([p.id for p in prs if p.id]))
                .order_by(col(PRCheck.observed_at))
            ).all()
            member_ids = [f.id for f in members if f.id is not None]
            session_ids = [s.id for s in sessions if s.id is not None]
            pr_ids = [p.id for p in prs if p.id is not None]
            events = db.exec(
                select(Event)
                .where(
                    or_(
                        and_(col(Event.entity_type) == "work_item", col(Event.entity_id) == wi_id),
                        and_(
                            col(Event.entity_type) == "finding",
                            col(Event.entity_id).in_(member_ids),
                        ),
                        and_(
                            col(Event.entity_type) == "session",
                            col(Event.entity_id).in_(session_ids),
                        ),
                        and_(
                            col(Event.entity_type) == "pull_request",
                            col(Event.entity_id).in_(pr_ids),
                        ),
                    )
                )
                .order_by(col(Event.ts), col(Event.id))
            ).all()
            acus = sum(s.acus_consumed for s in sessions)
            return render(
                request,
                "issue.html",
                wi=wi,
                members=members,
                sessions=sessions,
                polls=polls,
                prs=prs,
                checks=checks,
                events=events,
                acus=acus,
                cost=acus * settings.acu_cost_usd if settings.acu_cost_usd is not None else None,
            )

    @app.get("/prs", response_class=HTMLResponse)
    def prs_page(request: Request) -> HTMLResponse:
        m = metrics()
        with session_scope(engine) as db:
            prs = db.exec(select(PullRequest).order_by(col(PullRequest.id).desc())).all()
            return render(request, "prs.html", prs=prs, levels=m.pr_levels)

    @app.get("/report", response_class=HTMLResponse)
    def report_page(request: Request, live: bool = Query(default=False)) -> HTMLResponse:
        persisted = None if live else latest_persisted_report(engine)
        if persisted is not None:
            body = ReportBody.model_validate(persisted.body)
            source = f"persisted report #{persisted.id} ({persisted.generated_at.isoformat()})"
        else:
            body = build_report_for(engine, settings, datetime.now(UTC))
            source = "computed now from the database (not persisted)"
        return render(request, "report.html", report=body, source=source)

    @app.get("/report.md", response_class=PlainTextResponse)
    def report_markdown(live: bool = Query(default=False)) -> PlainTextResponse:
        persisted = None if live else latest_persisted_report(engine)
        if persisted is not None:
            return PlainTextResponse(persisted.markdown, media_type="text/markdown")
        body = build_report_for(engine, settings, datetime.now(UTC))
        return PlainTextResponse(render_markdown(body), media_type="text/markdown")

    # -------------------------------------------------------------------------------- api

    @app.get("/healthz")
    def healthz() -> dict[str, Any]:
        with session_scope(engine) as db:
            runs = len(db.exec(select(ScanRun.id)).all())
        return {"ok": True, "runs": runs, "replay_mode": settings.replay_mode, "read_only": True}

    @app.get("/api/metrics", response_model=Metrics)
    def api_metrics() -> Metrics:
        return metrics()

    @app.get("/api/report", response_model=ReportBody)
    def api_report(live: bool = Query(default=False)) -> ReportBody:
        persisted = None if live else latest_persisted_report(engine)
        if persisted is not None:
            return ReportBody.model_validate(persisted.body)
        return build_report_for(engine, settings, datetime.now(UTC))

    @app.get("/api/runs")
    def api_runs() -> list[dict[str, Any]]:
        return [r.model_dump(mode="json") for r in metrics().runs]

    @app.get("/api/work-items")
    def api_work_items(state: str | None = Query(default=None)) -> list[dict[str, Any]]:
        with session_scope(engine) as db:
            stmt = select(WorkItem).order_by(col(WorkItem.id))
            if state is not None:
                stmt = stmt.where(col(WorkItem.state) == state)
            return [w.model_dump(mode="json") for w in db.exec(stmt.limit(MAX_ROWS)).all()]

    @app.get("/api/work-items/{wi_id}/events")
    def api_work_item_events(wi_id: int) -> list[dict[str, Any]]:
        with session_scope(engine) as db:
            if db.get(WorkItem, wi_id) is None:
                raise HTTPException(404, f"work item {wi_id} not found")
            rows = db.exec(
                select(Event)
                .where(Event.entity_type == "work_item", Event.entity_id == wi_id)
                .order_by(col(Event.ts), col(Event.id))
            ).all()
            return [e.model_dump(mode="json") for e in rows]

    @app.get("/api/findings")
    def api_findings(
        kind: int | None = Query(default=None),
        state: str | None = Query(default=None),
        run: int | None = Query(default=None),
    ) -> list[dict[str, Any]]:
        with session_scope(engine) as db:
            stmt = select(Finding).order_by(col(Finding.id))
            if kind is not None:
                stmt = stmt.where(Finding.kind == Kind(kind))
            if state is not None:
                stmt = stmt.where(col(Finding.state) == state)
            if run is not None:
                stmt = stmt.where(Finding.first_seen_run_id == run)
            return [f.model_dump(mode="json") for f in db.exec(stmt.limit(MAX_ROWS)).all()]

    return app
