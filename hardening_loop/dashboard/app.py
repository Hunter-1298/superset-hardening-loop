"""FastAPI dashboard over the controller database.

By default every page and API endpoint is a pure read of SQLite and the app rejects any non-safe
HTTP method, so it can never approve, merge, dispatch, or mutate state. Approvals stay in GitHub.

With an `OperatorContext` (`serve --operator`) exactly one write exists: `POST /operator/launch/
{work_item_id}`, which hands a work item to the orchestrator's guarded dispatch path after an
explicit confirmation step and a CSRF check. Merges and dispositions still happen in GitHub."""

from __future__ import annotations

import hmac
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.engine import Engine
from sqlalchemy.sql import ColumnElement
from sqlmodel import and_, col, or_, select
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from hardening_loop.config import COMPARISON_BRANCH, Settings
from hardening_loop.dashboard import labels
from hardening_loop.dashboard.vuln import vuln_detail
from hardening_loop.db import open_database_readonly, session_scope
from hardening_loop.domain.enums import (
    FindingState,
    Kind,
    Layer,
    LifecycleLevel,
    Severity,
    VerificationDepth,
    WorkItemState,
)
from hardening_loop.metrics import (
    Metrics,
    RunSummary,
    compute_metrics,
    metrics_history,
    summarize_run,
)
from hardening_loop.models.lineage import regression_descendants
from hardening_loop.models.tables import (
    Event,
    Finding,
    PRCheck,
    PullRequest,
    ScanJob,
    ScanRun,
    Session,
    SessionPoll,
    Sighting,
    VerificationCheck,
    WorkItem,
)
from hardening_loop.operator import OperatorContext
from hardening_loop.orchestrator.launch import LaunchBlock, LaunchResult
from hardening_loop.report.run_report import (
    ReportBody,
    build_report,
    latest_persisted_report,
    render_markdown,
    upstream_pins_from_fixture,
)

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
LAUNCH_PATH = re.compile(r"^/operator/launch/\d+$")
CONFIRM_VALUE = "launch"
log = logging.getLogger(__name__)
TEMPLATES_DIR = Path(__file__).parent / "templates"
STATIC_DIR = Path(__file__).parent / "static"
MAX_ROWS = 2000
RECENT_ACTIVITY_ROWS = 12
RECENT_RUNS = 6
QUEUE_ROWS = 8

UNCLASSIFIED = "unclassified"


@dataclass(frozen=True)
class NavItem:
    """One sidebar entry. `prefixes` are the request paths that mark it as current."""

    label: str
    href: str
    prefixes: tuple[str, ...]
    secondary: bool = False


NAV: tuple[NavItem, ...] = (
    NavItem("Overview", "/", ("/",)),
    NavItem("CVEs", "/findings", ("/findings",)),
    NavItem("Work items", "/issues", ("/issues",)),
    NavItem("Scans", "/runs", ("/runs",)),
    NavItem("Pull requests", "/prs", ("/prs",)),
    NavItem("Report", "/report", ("/report",)),
)

LAUNCH_BLOCK_TEXT: dict[LaunchBlock, str] = {
    LaunchBlock.dispatch_in_progress: "A dispatch for this item is already in progress.",
    LaunchBlock.session_in_flight: "A Devin session is already working on this item.",
    LaunchBlock.awaiting_human_merge: "The pull request is waiting for a human review and merge.",
    LaunchBlock.awaiting_rescan: "Merged; waiting for a source-matching rescan of the branch.",
    LaunchBlock.closed: "This item is closed.",
    LaunchBlock.at_capacity: "Every concurrent session slot is in use.",
    LaunchBlock.over_budget: "This item's ACU cap would exceed the global ACU budget.",
    LaunchBlock.scan_pending: (
        "A scan of the branch is still waiting to be evaluated; it may already resolve this item."
    ),
}


def _same_origin(request: Request) -> bool:
    """Browsers send `Origin` on every form POST; when present it must name this server.
    Requests without either header (curl, older clients) are left to the CSRF token."""
    origin = request.headers.get("origin")
    if origin is None:
        return True
    host = request.headers.get("host", "")
    return bool(host) and urlsplit(origin).netloc.lower() == host.lower()


def _launch_block(reason: str) -> LaunchBlock | None:
    try:
        return LaunchBlock(reason)
    except ValueError:
        return None


def nav_current(path: str) -> str | None:
    """The href of the sidebar item that owns `path` (exact match for `/`, prefix otherwise)."""
    for item in NAV:
        for prefix in item.prefixes:
            if prefix == "/" and path == "/":
                return item.href
            if prefix != "/" and (path == prefix or path.startswith(prefix + "/")):
                return item.href
    return None


def _kind_label(value: object) -> str:
    return labels.kind(value).text


def parse_kind(value: str | None) -> Kind | None:
    """`kind` query param: the enum number (`1`), the slug (`dependency_upgrade`) or
    `unclassified` (returned as None). Blank means no filter; anything else is a 422."""
    if not value or value == UNCLASSIFIED:
        return None
    try:
        return Kind(int(value)) if value.isdigit() else Kind[value]
    except (ValueError, KeyError) as exc:
        choices = ", ".join([*(str(k.value) for k in Kind), *(k.slug for k in Kind), UNCLASSIFIED])
        raise HTTPException(
            status_code=422, detail=f"unknown kind {value!r}; one of {choices}"
        ) from exc


def parse_lifecycle(value: str | None) -> LifecycleLevel | None:
    """`level` query param: the number (`6`) or the name (`rescan_verified`). Blank means no
    filter; anything else is a 422."""
    if not value:
        return None
    try:
        return LifecycleLevel(int(value)) if value.isdigit() else LifecycleLevel[value]
    except (ValueError, KeyError) as exc:
        choices = ", ".join(
            [*(str(int(v)) for v in LifecycleLevel), *(v.name for v in LifecycleLevel)]
        )
        raise HTTPException(
            status_code=422, detail=f"unknown lifecycle level {value!r}; one of {choices}"
        ) from exc


def parse_depth(value: str | None) -> VerificationDepth | None:
    """`depth` query param: the rung number (`3`), `L3`, or the name (`immutable_image_runtime`)."""
    if not value:
        return None
    raw = value[1:] if value[:1] in ("L", "l") and value[1:].isdigit() else value
    try:
        return VerificationDepth(int(raw)) if raw.isdigit() else VerificationDepth[raw]
    except (ValueError, KeyError) as exc:
        choices = ", ".join(
            [*(f"L{int(v)}" for v in VerificationDepth), *(v.name for v in VerificationDepth)]
        )
        raise HTTPException(
            status_code=422, detail=f"unknown verification depth {value!r}; one of {choices}"
        ) from exc


def _lifecycle_label(value: object) -> str:
    try:
        return LifecycleLevel(int(str(value))).label
    except (ValueError, TypeError):
        return str(value)


def _depth_code(value: object) -> str:
    """`L3` for a rung given as enum, number or name; a dash when there is no depth yet."""
    if value is None or value == "":
        return "—"
    try:
        raw = str(value)
        depth = VerificationDepth(int(raw)) if raw.isdigit() else VerificationDepth[raw]
    except (ValueError, KeyError):
        return str(value)
    return f"L{int(depth)}"


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.0f}%"


def _num(value: float | None, digits: int = 2) -> str:
    return "n/a" if value is None else f"{value:.{digits}f}"


def _money(value: float | None) -> str:
    return "n/a" if value is None else f"${value:,.2f}"


def _short(sha: str | None) -> str:
    return (sha or "")[:12]


def _dt(value: object) -> str:
    """Compact UTC timestamp for tables: `2026-09-02 14:05`."""
    if value is None or value == "":
        return "—"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M")
    return str(value)


def _hours(value: float | None) -> str:
    if value is None:
        return "n/a"
    if value < 1:
        return f"{value * 60:.0f} min"
    return f"{value:.1f} h"


def _delta(value: int | float | None) -> str:
    if value is None:
        return "n/a"
    if value == 0:
        return "0"
    return f"{value:+d}" if isinstance(value, int) else f"{value:+.1f}"


def _templates() -> Jinja2Templates:
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    env = templates.env
    env.filters["kind"] = _kind_label
    env.filters["level"] = _lifecycle_label
    env.filters["depth_code"] = _depth_code
    env.filters["pct"] = _pct
    env.filters["num"] = _num
    env.filters["money"] = _money
    env.filters["short"] = _short
    env.filters["dt"] = _dt
    env.filters["hours"] = _hours
    env.filters["delta"] = _delta
    env.filters["wi_state"] = labels.work_item_state
    env.filters["finding_state"] = labels.finding_state
    env.filters["kind_label"] = labels.kind
    env.filters["severity_label"] = labels.severity
    env.filters["lifecycle_label"] = labels.lifecycle
    env.filters["depth_label"] = labels.depth
    env.filters["check_status"] = labels.check_status
    env.filters["risk_label"] = labels.risk
    env.filters["run_status"] = labels.run_status
    env.filters["trigger_label"] = labels.trigger
    env.filters["pr_state"] = labels.pr_state
    env.filters["check_label"] = labels.check_conclusion
    env.filters["outcome_label"] = labels.outcome
    env.filters["scanner_label"] = labels.scanner_group
    env.filters["layer_label"] = labels.layer
    env.filters["yes_no"] = labels.yes_no
    env.filters["event_label"] = labels.event
    env.filters["actor_label"] = labels.actor
    env.filters["plain_label"] = labels.plain
    env.filters["relation_label"] = labels.relation
    env.filters["blocked_reason"] = labels.blocked_reason_text
    env.globals["gate_label"] = labels.gate
    env.globals["nav_items"] = NAV
    env.globals["nav_current"] = nav_current
    env.globals["kinds"] = list(Kind)
    env.globals["severities"] = list(Severity)
    env.globals["work_item_states"] = list(WorkItemState)
    env.globals["finding_states"] = list(FindingState)
    env.globals["layers"] = list(Layer)
    env.globals["lifecycle_levels"] = list(LifecycleLevel)
    env.globals["depth_levels"] = list(VerificationDepth)
    env.globals["human_action_states"] = labels.HUMAN_ACTION_STATES
    env.globals["ui"] = env.get_template("_macros.html").module
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


@dataclass(frozen=True)
class HeaderContext:
    """Compact operational context shown in the top bar of every page."""

    latest_run: RunSummary | None
    last_updated: datetime | None


def header_context(engine: Engine, branch: str) -> HeaderContext:
    """Latest scan of the remediation branch (falling back to any branch) and the newest
    timestamp the database knows about, so the header never invents a value."""
    with session_scope(engine) as db:
        run = db.exec(
            select(ScanRun)
            .where(ScanRun.source_branch == branch)
            .order_by(
                col(ScanRun.finished_at).desc(),
                col(ScanRun.ingested_at).desc(),
                col(ScanRun.id).desc(),
            )
        ).first()
        if run is None:
            run = db.exec(
                select(ScanRun).order_by(
                    col(ScanRun.finished_at).desc(),
                    col(ScanRun.ingested_at).desc(),
                    col(ScanRun.id).desc(),
                )
            ).first()
        last_event = db.exec(select(Event.ts).order_by(col(Event.ts).desc())).first()
        if run is not None:
            db.expunge(run)
    summary = summarize_run(engine, run) if run is not None else None
    stamps = [t for t in (last_event, run.ingested_at if run else None) if t is not None]
    return HeaderContext(latest_run=summary, last_updated=max(stamps) if stamps else None)


def _wants_html(request: Request) -> bool:
    """Browsers (Accept: text/html) get an HTML error page on page routes; everything else,
    including the JSON API and scripted clients, keeps FastAPI's JSON `{"detail": ...}`."""
    path = request.url.path
    if path.startswith(("/api/", "/static")) or path in ("/healthz", "/report.md"):
        return False
    return "text/html" in request.headers.get("accept", "")


def create_app(
    settings: Settings | None = None,
    *,
    engine: Engine | None = None,
    operator: OperatorContext | None = None,
) -> FastAPI:
    """Read-only by default. Passing `operator` switches the app to operator mode: it reads through
    the orchestrator's writable engine and accepts `POST /operator/launch/{id}` and nothing else.
    Replay databases are never served in operator mode."""
    settings = settings or Settings()
    if operator is not None and settings.replay_mode:
        raise ValueError("replay mode is read-only; operator launches are disabled")
    if operator is not None:
        engine = operator.engine
    engine = engine or open_database_readonly(settings.database_path)
    app = FastAPI(title="Superset hardening loop", docs_url="/api/docs", redoc_url=None)
    app.state.settings = settings
    app.state.engine = engine
    app.state.operator = operator
    templates = _templates()
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.middleware("http")
    async def read_only(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        if request.method in SAFE_METHODS:
            return await call_next(request)
        if (
            operator is not None
            and request.method == "POST"
            and LAUNCH_PATH.match(request.url.path)
        ):
            return await call_next(request)
        return JSONResponse(
            {"detail": "dashboard is read-only; approvals and merges happen in GitHub"},
            status_code=405,
            headers={"Allow": "GET, HEAD, OPTIONS"},
        )

    def metrics() -> Metrics:
        return compute_metrics(engine, acu_cost_usd=settings.acu_cost_usd, now=datetime.now(UTC))

    def render(request: Request, name: str, status_code: int = 200, **ctx: Any) -> HTMLResponse:
        header = header_context(engine, settings.remediation_branch)
        base = {
            "request": request,
            "fork_repo": settings.fork_repo,
            "branch": settings.remediation_branch,
            "comparison_branch": COMPARISON_BRANCH,
            "gate_mode": settings.scan_gate_mode.value,
            "replay_mode": settings.replay_mode,
            "operator": operator,
            "database": str(settings.database_path),
            "current_path": request.url.path,
            "latest_run": header.latest_run,
            "last_updated": header.last_updated,
        }
        return templates.TemplateResponse(request, name, {**base, **ctx}, status_code=status_code)

    def launch_offer(wi: WorkItem | None) -> Any:
        """Preview for the "Launch Devin" affordance, or None outside operator mode."""
        if operator is None or wi is None or wi.id is None:
            return None
        return operator.preview(wi.id)

    @app.exception_handler(StarletteHTTPException)
    async def html_or_json_error(request: Request, exc: StarletteHTTPException) -> Response:
        if not _wants_html(request):
            return await http_exception_handler(request, exc)
        return render(
            request,
            "error.html",
            status_code=exc.status_code,
            error_status=exc.status_code,
            error_detail=str(exc.detail),
        )

    # ------------------------------------------------------------------------------ pages

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        m = metrics()
        with session_scope(engine) as db:
            queue = sorted(
                db.exec(
                    select(WorkItem).where(
                        col(WorkItem.state).in_([s.value for s in labels.HUMAN_ACTION_STATES])
                    )
                ).all(),
                key=lambda w: (-w.severity.rank, -(w.id or 0)),
            )
            recent_events = db.exec(
                select(Event)
                .where(Event.entity_type == "work_item")
                .order_by(col(Event.ts).desc(), col(Event.id).desc())
                .limit(RECENT_ACTIVITY_ROWS)
            ).all()
            titles = {
                w.id: w.title
                for w in db.exec(
                    select(WorkItem).where(
                        col(WorkItem.id).in_([e.entity_id for e in recent_events])
                    )
                ).all()
            }
            return render(
                request,
                "index.html",
                m=m,
                runs=m.runs[-RECENT_RUNS:][::-1],
                queue=queue[:QUEUE_ROWS],
                queue_total=len(queue),
                recent_events=recent_events,
                titles=titles,
            )

    @app.get("/runs", response_class=HTMLResponse)
    def runs_page(request: Request) -> HTMLResponse:
        m = metrics()
        baseline = next((r for r in m.runs if r.is_baseline), None)
        latest = next((r for r in m.runs if r.id == m.latest_main_run_id), None)
        return render(
            request, "runs.html", runs=m.runs[::-1], baseline=baseline, latest=latest, m=m
        )

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
            opened = [f for f in findings if f.first_seen_run_id == run_id]
            closed = [f for f in findings if f.closed_by_run_id == run_id]
            return render(
                request,
                "run.html",
                run=run,
                summary=summary,
                jobs=jobs,
                events=events,
                findings=findings,
                opened_count=len(opened),
                closed_count=len(closed),
            )

    @app.get("/findings", response_class=HTMLResponse)
    def findings_page(
        request: Request,
        kind: str | None = Query(default=None),
        state: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        layer: str | None = Query(default=None),
        run: int | None = Query(default=None),
    ) -> HTMLResponse:
        kind = kind or None
        state = state or None
        severity = severity or None
        layer = layer or None
        wanted = parse_kind(kind)
        with session_scope(engine) as db:
            stmt = select(Finding)
            if kind is not None:
                stmt = stmt.where(
                    col(Finding.kind).is_(None) if wanted is None else Finding.kind == wanted
                )
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
            total = len(db.exec(select(Finding.id)).all())
            return render(
                request,
                "findings.html",
                findings=rows,
                total=total,
                filters={
                    "kind": kind,
                    "state": state,
                    "severity": severity,
                    "layer": layer,
                    "run": run,
                },
            )

    @app.get("/findings/{finding_id}", response_class=HTMLResponse)
    def finding_page(request: Request, finding_id: int) -> HTMLResponse:
        with session_scope(engine) as db:
            f = db.get(Finding, finding_id)
            if f is None:
                raise HTTPException(404, f"finding {finding_id} not found")
            sightings = db.exec(
                select(Sighting)
                .where(Sighting.finding_id == finding_id)
                .order_by(col(Sighting.scan_run_id), col(Sighting.scanner), col(Sighting.mode))
            ).all()
            run_ids = sorted({s.scan_run_id for s in sightings})
            runs = {
                r.id: r
                for r in db.exec(select(ScanRun).where(col(ScanRun.id).in_(run_ids))).all()
                if r.id is not None
            }
            records: dict[str, dict[str, Any] | None] = {}
            for s in sorted(sightings, key=lambda s: s.scan_run_id):
                if s.present and s.record is not None:
                    records[s.scanner.value] = s.record
            detail = vuln_detail(records)
            wi = db.get(WorkItem, f.work_item_id) if f.work_item_id is not None else None
            sessions = (
                db.exec(
                    select(Session).where(Session.work_item_id == wi.id).order_by(col(Session.id))
                ).all()
                if wi is not None
                else []
            )
            prs = (
                db.exec(
                    select(PullRequest)
                    .where(PullRequest.work_item_id == wi.id)
                    .order_by(col(PullRequest.id))
                ).all()
                if wi is not None
                else []
            )
            events = db.exec(
                select(Event)
                .where(
                    or_(
                        and_(
                            col(Event.entity_type) == "finding", col(Event.entity_id) == finding_id
                        ),
                        and_(
                            col(Event.entity_type) == "work_item",
                            col(Event.entity_id) == (wi.id if wi is not None else -1),
                        ),
                    )
                )
                .order_by(col(Event.ts), col(Event.id))
            ).all()
            same_vuln = db.exec(
                select(Finding)
                .where(Finding.vuln_id == f.vuln_id, Finding.id != finding_id)
                .order_by(col(Finding.id))
                .limit(50)
            ).all()
            history = [
                (runs.get(rid), [s for s in sightings if s.scan_run_id == rid]) for rid in run_ids
            ]
            return render(
                request,
                "finding.html",
                f=f,
                detail=detail,
                history=history[::-1],
                wi=wi,
                sessions=sessions,
                prs=prs,
                events=events,
                same_vuln=same_vuln,
                launch=launch_offer(wi),
                launch_block_text=LAUNCH_BLOCK_TEXT,
                next_action=(
                    labels.next_human_action(wi.state, wi.blocked_reason, wi.pr_url)
                    if wi is not None
                    else None
                ),
            )

    @app.get("/issues", response_class=HTMLResponse)
    def issues_page(
        request: Request,
        state: str | None = Query(default=None),
        kind: str | None = Query(default=None),
        severity: str | None = Query(default=None),
        level: str | None = Query(default=None),
        depth: str | None = Query(default=None),
        q: str | None = Query(default=None),
        queue: bool = Query(default=False),
    ) -> HTMLResponse:
        state = state or None
        severity = severity or None
        wanted = parse_kind(kind)
        wanted_level = parse_lifecycle(level)
        wanted_depth = parse_depth(depth)
        needle = (q or "").strip()
        with session_scope(engine) as db:
            stmt = select(WorkItem)
            if queue:
                stmt = stmt.where(
                    col(WorkItem.state).in_([s.value for s in labels.HUMAN_ACTION_STATES])
                )
            if state:
                stmt = stmt.where(col(WorkItem.state) == state)
            if wanted is not None:
                stmt = stmt.where(WorkItem.kind == wanted)
            if severity:
                stmt = stmt.where(col(WorkItem.severity) == severity.upper())
            if wanted_level is not None:
                stmt = stmt.where(col(WorkItem.lifecycle_level) == wanted_level)
            if wanted_depth is not None:
                stmt = stmt.where(col(WorkItem.verification_depth) == wanted_depth)
            if needle:
                like = f"%{needle}%"
                clauses: list[ColumnElement[bool]] = [
                    col(WorkItem.title).ilike(like),
                    col(WorkItem.group_key).ilike(like),
                    col(WorkItem.blocked_reason).ilike(like),
                ]
                if needle.lstrip("#").isdigit():
                    number = int(needle.lstrip("#"))
                    clauses += [
                        col(WorkItem.id) == number,
                        col(WorkItem.issue_number) == number,
                        col(WorkItem.pr_number) == number,
                    ]
                stmt = stmt.where(or_(*clauses))
            items = db.exec(stmt.order_by(col(WorkItem.id).desc()).limit(MAX_ROWS)).all()
            total = len(db.exec(select(WorkItem.id)).all())
            sessions = db.exec(select(Session)).all()
            acu_by_wi: dict[int, float] = {}
            for s in sessions:
                acu_by_wi[s.work_item_id] = acu_by_wi.get(s.work_item_id, 0.0) + s.acus_consumed
            return render(
                request,
                "issues.html",
                items=items,
                total=total,
                acu_by_wi=acu_by_wi,
                acu_cost_usd=settings.acu_cost_usd,
                filters={
                    "q": needle or None,
                    "state": state or None,
                    "kind": kind or None,
                    "severity": severity or None,
                    "level": level or None,
                    "depth": depth or None,
                    "queue": "1" if queue else None,
                },
            )

    @app.get("/issues/{wi_id}", response_class=HTMLResponse)
    def issue_page(request: Request, wi_id: int) -> HTMLResponse:
        with session_scope(engine) as db:
            wi = db.get(WorkItem, wi_id)
            if wi is None:
                raise HTTPException(404, f"work item {wi_id} not found")
            all_items = db.exec(select(WorkItem)).all()
            lineage_ids = [wi_id, *regression_descendants(all_items, wi_id)]
            members = db.exec(
                select(Finding)
                .where(col(Finding.work_item_id).in_(lineage_ids))
                .order_by(col(Finding.vuln_id))
            ).all()
            regressions = [w for w in all_items if w.id in lineage_ids[1:]]
            origin = (
                db.get(WorkItem, wi.regression_of_work_item_id)
                if wi.regression_of_work_item_id is not None
                else None
            )
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
            current_pr = next((p for p in prs if p.state == "open"), prs[-1] if prs else None)
            depth_checks = (
                db.exec(
                    select(VerificationCheck)
                    .where(
                        VerificationCheck.pull_request_id == current_pr.id,
                        VerificationCheck.head_sha == current_pr.head_sha,
                    )
                    .order_by(col(VerificationCheck.depth), col(VerificationCheck.id))
                ).all()
                if current_pr is not None and current_pr.id is not None
                else []
            )
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
            scan_run_ids = sorted(
                {f.first_seen_run_id for f in members}
                | {f.closed_by_run_id for f in members if f.closed_by_run_id is not None}
            )
            scan_runs = [r for r in metrics().runs if r.id in scan_run_ids] if scan_run_ids else []
            acus = sum(s.acus_consumed for s in sessions)
            retry_events = [e for e in events if "retry" in e.event]
            return render(
                request,
                "issue.html",
                wi=wi,
                members=members,
                regressions=regressions,
                origin=origin,
                sessions=sessions,
                polls=polls,
                prs=prs,
                checks=checks,
                current_pr=current_pr,
                depth_checks=depth_checks,
                events=events,
                retry_events=retry_events,
                scan_runs=scan_runs,
                acus=acus,
                cost=acus * settings.acu_cost_usd if settings.acu_cost_usd is not None else None,
                next_action=labels.next_human_action(wi.state, wi.blocked_reason, wi.pr_url),
                launch=launch_offer(wi),
                launch_block_text=LAUNCH_BLOCK_TEXT,
            )

    # --------------------------------------------------------------------------- operator

    if operator is not None:
        ctx = operator

        def _launch_context(db: Any, wi_id: int) -> dict[str, Any]:
            wi = db.get(WorkItem, wi_id)
            if wi is None:
                raise HTTPException(404, f"work item {wi_id} not found")
            members = db.exec(
                select(Finding).where(Finding.work_item_id == wi_id).order_by(col(Finding.vuln_id))
            ).all()
            return {
                "wi": wi,
                "members": members,
                "preview": ctx.preview(wi_id),
                "launch_block_text": LAUNCH_BLOCK_TEXT,
                "csrf_token": ctx.csrf_token,
                "confirm_value": CONFIRM_VALUE,
                "operator_login": ctx.login,
                "live": ctx.live,
            }

        @app.get("/operator/launch/{wi_id}", response_class=HTMLResponse)
        def launch_confirm(request: Request, wi_id: int) -> HTMLResponse:
            with session_scope(engine) as db:
                return render(request, "launch.html", **_launch_context(db, wi_id))

        @app.post("/operator/launch/{wi_id}", response_class=HTMLResponse)
        async def launch_submit(request: Request, wi_id: int) -> HTMLResponse:
            fetch_site = request.headers.get("sec-fetch-site")
            if fetch_site not in (None, "same-origin", "none"):
                raise HTTPException(403, "cross-site launch request refused")
            if not _same_origin(request):
                raise HTTPException(403, "launch request origin does not match this server")
            if not request.headers.get("content-type", "").startswith(
                "application/x-www-form-urlencoded"
            ):
                raise HTTPException(415, "launch form must be application/x-www-form-urlencoded")
            form = parse_qs((await request.body()).decode("utf-8", errors="replace"))
            token = form.get("csrf", [""])[0]
            if not hmac.compare_digest(token, ctx.csrf_token):
                raise HTTPException(403, "invalid or missing CSRF token")
            if form.get("confirm", [""])[0] != CONFIRM_VALUE:
                raise HTTPException(400, "launch not confirmed")
            try:
                result = await run_in_threadpool(ctx.launch, wi_id)
            except LookupError as exc:
                raise HTTPException(404, str(exc)) from exc
            except Exception as exc:
                log.exception("operator launch of work item %s raised", wi_id)
                result = LaunchResult("failed", wi_id, f"{exc.__class__.__name__}: {exc}"[:300])
            status = 200 if result.ok else (409 if result.outcome == "rejected" else 502)
            with session_scope(engine) as db:
                wi = db.get(WorkItem, wi_id)
                sessions = db.exec(
                    select(Session).where(Session.work_item_id == wi_id).order_by(col(Session.id))
                ).all()
                return render(
                    request,
                    "launch_result.html",
                    status_code=status,
                    wi=wi,
                    result=result,
                    sessions=sessions,
                    launch_block_text=LAUNCH_BLOCK_TEXT,
                    block=_launch_block(result.reason),
                )

    @app.get("/prs", response_class=HTMLResponse)
    def prs_page(request: Request) -> HTMLResponse:
        m = metrics()
        with session_scope(engine) as db:
            prs = db.exec(select(PullRequest).order_by(col(PullRequest.id).desc())).all()
            titles = {
                w.id: w.title
                for w in db.exec(
                    select(WorkItem).where(col(WorkItem.id).in_([p.work_item_id for p in prs]))
                ).all()
            }
            levels = {lv.work_item_id: lv for lv in m.pr_levels}
            return render(request, "prs.html", prs=prs, levels=levels, titles=titles, m=m)

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
        return {
            "ok": True,
            "runs": runs,
            "replay_mode": settings.replay_mode,
            "read_only": operator is None,
            "operator_mode": operator is not None,
        }

    @app.get("/api/metrics", response_model=Metrics)
    def api_metrics() -> Metrics:
        return metrics()

    @app.get("/api/metrics/history")
    def api_metrics_history(limit: int = Query(default=50, ge=1, le=500)) -> list[dict[str, Any]]:
        return [
            s.model_dump(mode="json", exclude={"body"})
            for s in metrics_history(engine, limit=limit)
        ]

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
        kind: str | None = Query(default=None),
        state: str | None = Query(default=None),
        run: int | None = Query(default=None),
    ) -> list[dict[str, Any]]:
        wanted = parse_kind(kind)
        with session_scope(engine) as db:
            stmt = select(Finding).order_by(col(Finding.id))
            if kind is not None:
                stmt = stmt.where(
                    col(Finding.kind).is_(None) if wanted is None else Finding.kind == wanted
                )
            if state is not None:
                stmt = stmt.where(col(Finding.state) == state)
            if run is not None:
                stmt = stmt.where(Finding.first_seen_run_id == run)
            return [f.model_dump(mode="json") for f in db.exec(stmt.limit(MAX_ROWS)).all()]

    return app
