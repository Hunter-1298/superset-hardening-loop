"""Dashboard metrics, read-only routes, and the database-backed run report, all evaluated on the
replay `DEMO` database (real orchestrator, fake GitHub/Devin, zero network)."""

from __future__ import annotations

import re
import statistics
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine
from sqlmodel import col, select

from hardening_loop.config import Settings
from hardening_loop.dashboard.app import build_report_for, create_app
from hardening_loop.dashboard.labels import blocked_reason_text
from hardening_loop.db import open_database, session_scope
from hardening_loop.domain.enums import Kind, Severity, VerificationLevel, WorkItemState
from hardening_loop.metrics import Metrics, compute_metrics
from hardening_loop.models.tables import Finding, PullRequest, Session, WorkItem
from hardening_loop.orchestrator.closer import CLOSING_FINDING_STATES
from hardening_loop.replay.runner import run_scenario
from hardening_loop.report.run_report import (
    latest_persisted_report,
    persist_report,
    render_markdown,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
UPSTREAM_SHA = "c03f3441bd565b9fd5f082d0b875c467eeae441c"
ACU_COST = 2.25
NOW = datetime(2026, 9, 2, tzinfo=UTC)


@pytest.fixture(scope="module")
def demo_db(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("demo")
    result = run_scenario("DEMO", out)
    assert result.passed, [c for c in result.checks if not c.ok]
    return out / "demo.sqlite3"


@pytest.fixture(scope="module")
def engine(demo_db: Path) -> Engine:
    return open_database(demo_db)


@pytest.fixture(scope="module")
def settings(demo_db: Path) -> Settings:
    return Settings(
        data_dir=demo_db.parent,
        database_file=demo_db.name,
        replay_mode=True,
        acu_cost_usd=ACU_COST,
        upstream_master_sha=UPSTREAM_SHA,
        repo_root=REPO_ROOT,
    )


@pytest.fixture(scope="module")
def metrics(engine: Engine) -> Metrics:
    return compute_metrics(engine, acu_cost_usd=ACU_COST, now=NOW)


@pytest.fixture(scope="module")
def client(settings: Settings, engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(settings, engine=engine)) as c:
        yield c


# ------------------------------------------------------------------------------- metrics


def test_findings_by_run_kind_layer_scanner(metrics: Metrics, engine: Engine) -> None:
    assert "replay-baseline" in metrics.findings_by_run
    assert metrics.findings_by_run["replay-baseline"] == {
        "CRITICAL": 2,
        "HIGH": 6,
        "MEDIUM": 1,
        "LOW": 1,
        "UNKNOWN": 0,
    }
    assert set(metrics.findings_by_kind) == {k.name for k in Kind}, "all five kinds present"
    with session_scope(engine) as db:
        findings = db.exec(select(Finding)).all()
    assert sum(metrics.findings_by_kind.values()) == len(findings)
    assert sum(metrics.findings_by_layer.values()) == len(findings)
    assert sum(metrics.findings_by_scanner.values()) == len(findings)
    assert metrics.findings_by_scanner.get("grype_only", 0) == 0


def test_open_high_critical_matches_db(metrics: Metrics, engine: Engine) -> None:
    with session_scope(engine) as db:
        expected = sum(
            1
            for f in db.exec(select(Finding)).all()
            if f.severity in (Severity.high, Severity.critical)
            and f.state not in CLOSING_FINDING_STATES
        )
    assert metrics.open_high_critical == expected > 0


def test_issues_by_state(metrics: Metrics) -> None:
    by_state = metrics.issues_by_state
    assert set(by_state) == {s.value for s in WorkItemState}, "every lifecycle state is listed"
    assert by_state["verified"] == 6
    assert by_state["needs_human"] == 1 == metrics.needs_human
    assert by_state["queued"] == 1, "regression re-queued as a new work item"
    assert metrics.active_sessions == 0


def test_first_try_success_overall_and_by_kind(metrics: Metrics) -> None:
    assert (metrics.first_try_overall.attempted, metrics.first_try_overall.succeeded) == (5, 4)
    assert metrics.first_try_overall.rate == pytest.approx(0.8)
    dep = metrics.first_try_by_kind["dependency_upgrade"]
    assert (dep.attempted, dep.succeeded) == (2, 1), "pillow needed a same-session retry"
    assert metrics.first_try_by_kind["scanner_disagreement"].rate is None, "no PR for kind 4"
    assert metrics.retries_total == 1


def test_median_and_p90_remediation_hours(metrics: Metrics, engine: Engine) -> None:
    with session_scope(engine) as db:
        items = db.exec(select(WorkItem).where(WorkItem.state == WorkItemState.verified)).all()
        hours = sorted(
            (w.verified_at - w.created_at).total_seconds() / 3600
            for w in items
            if w.verified_at is not None
        )
    assert metrics.timing.verified_count == len(hours) == 6
    assert metrics.timing.median_hours == pytest.approx(statistics.median(hours))
    assert metrics.timing.p90_hours is not None
    assert hours[-2] <= metrics.timing.p90_hours <= hours[-1]
    assert set(metrics.timing_by_kind) == {k.name for k in Kind}


def test_acu_and_cost_per_verified_issue(metrics: Metrics, engine: Engine) -> None:
    with session_scope(engine) as db:
        sessions = db.exec(select(Session)).all()
        verified_ids = {
            w.id for w in db.exec(select(WorkItem).where(WorkItem.state == WorkItemState.verified))
        }
        total = sum(s.acus_consumed for s in sessions)
        verified_acu = sum(s.acus_consumed for s in sessions if s.work_item_id in verified_ids)
    assert metrics.cost.acu_total == pytest.approx(total)
    assert metrics.cost.acu_per_verified_issue == pytest.approx(verified_acu / 6)
    assert metrics.cost.estimated_cost_total_usd == pytest.approx(total * ACU_COST)
    assert metrics.cost.estimated_cost_per_verified_issue_usd == pytest.approx(
        verified_acu / 6 * ACU_COST
    )
    no_price = compute_metrics(engine, acu_cost_usd=None, now=NOW)
    assert no_price.cost.estimated_cost_total_usd is None, "no invented ACU price"
    assert no_price.cost.acu_per_verified_issue == metrics.cost.acu_per_verified_issue


def test_highest_verification_level_per_pr(metrics: Metrics, engine: Engine) -> None:
    with session_scope(engine) as db:
        prs = db.exec(select(PullRequest)).all()
    assert len(metrics.pr_levels) == len(prs) == 5
    assert {p.level for p in metrics.pr_levels} == {VerificationLevel.rescan_verified}
    by_wi = {p.work_item_id: p for p in metrics.pr_levels}
    assert by_wi[2].first_head_checks_green is False and by_wi[2].retries_used == 1
    assert all(p.first_head_checks_green for wi, p in by_wi.items() if wi != 2)


def test_throughput_and_gate(metrics: Metrics) -> None:
    assert sum(metrics.throughput.verified_per_day.values()) == 6
    assert sum(metrics.throughput.prs_opened_per_day.values()) == 5
    assert sum(metrics.throughput.sessions_started_per_day.values()) == 7
    assert metrics.gate_ready_for_enforce is False, "policy HIGH findings remain on main"
    assert metrics.latest_main_run_id is not None


# --------------------------------------------------------------------------------- routes

PAGES = [
    "/",
    "/runs",
    "/runs/1",
    "/findings",
    "/findings?kind=1&state=fixed",
    "/findings?kind=dependency_upgrade",
    "/findings?kind=unclassified",
    "/issues",
    "/issues?kind=helm_deploy_config",
    "/issues?state=needs_human",
    "/issues/2",
    "/prs",
    "/report",
    "/report?live=1",
]


@pytest.mark.parametrize("path", PAGES)
def test_html_pages_render(client: TestClient, path: str) -> None:
    r = client.get(path)
    assert r.status_code == 200, r.text[:300]
    assert "text/html" in r.headers["content-type"]
    assert "Replay mode:" in r.text and "No Devin ACUs were spent" in r.text
    assert 'lang="en"' in r.text and 'name="viewport"' in r.text


def test_overview_shows_required_metrics(client: TestClient, metrics: Metrics) -> None:
    html = client.get("/").text
    for label in (
        "Open HIGH/CRITICAL",
        "Gate ready for enforce",
        "First-try success",
        "Median remediation time",
        "ACU per verified issue",
        "Cost per verified issue",
        "Needs attention",
        "Work items by state",
        "Verification level per PR",
        "Recent scans",
        "Recent remediation activity",
        "Findings by kind",
        "Throughput per day",
    ):
        assert label in html
    assert f">{metrics.open_high_critical}<" in html
    assert "80%" in html
    # the six lead metrics come first, breakdowns are folded into disclosures below them
    assert html.index("Open HIGH/CRITICAL") < html.index("Needs attention")
    assert html.index("Needs attention") < html.index("Recent scans")
    assert html.index("Recent scans") < html.index("<details")
    assert html.index("<details") < html.index("Findings by kind")


def test_overview_kind_links_resolve(client: TestClient) -> None:
    html = client.get("/").text
    hrefs = re.findall(r'href="(/findings\?kind=[^"]+)"', html)
    assert hrefs, "overview should link each kind row to the findings page"
    for href in hrefs:
        assert client.get(href).status_code == 200, href
    by_slug = client.get("/api/findings?kind=helm_deploy_config").json()
    assert by_slug == client.get("/api/findings?kind=5").json() and by_slug
    r = client.get("/findings?kind=bogus")
    assert r.status_code == 422 and "unknown kind" in r.json()["detail"]


def test_issue_page_shows_blocked_reason_and_events(client: TestClient, engine: Engine) -> None:
    with session_scope(engine) as db:
        blocked = db.exec(
            select(WorkItem).where(WorkItem.state == WorkItemState.needs_human)
        ).first()
        assert blocked is not None and blocked.blocked_reason
        reason, blocked_id = blocked.blocked_reason, blocked.id
    # the list shows the item, its detail page carries the blocked reason and next action
    listing = client.get("/issues?state=needs_human").text
    assert f'href="/issues/{blocked_id}"' in listing
    assert reason not in listing
    detail = client.get(f"/issues/{blocked_id}").text
    assert reason in detail and "Next human action" in detail
    assert "Retries and blockers" in detail
    html = client.get("/issues/2").text
    for section in ("Lifecycle", "Findings", "Devin sessions", "Pull requests and CI checks"):
        assert section in html
    assert "Verified by rescan" in html and 'class="timeline"' in html


def test_issue_page_lists_session_prs_and_regression_lineage(
    client: TestClient, engine: Engine
) -> None:
    with session_scope(engine) as db:
        sess = db.exec(select(Session).where(Session.work_item_id == 2)).first()
        assert sess is not None and sess.pull_requests
        pr_url = sess.pull_requests[0]["pr_url"]
        regression = db.exec(
            select(WorkItem).where(col(WorkItem.regression_of_work_item_id).is_not(None))
        ).first()
        assert regression is not None and regression.regression_of_work_item_id is not None
        origin_id, regression_id = regression.regression_of_work_item_id, regression.id
        moved = db.exec(select(Finding).where(Finding.work_item_id == regression_id)).all()
        assert moved
    html = client.get("/issues/2").text
    assert f'<a href="{pr_url}" rel="noopener">' in html
    origin_html = client.get(f"/issues/{origin_id}").text
    assert f'href="/issues/{regression_id}"' in origin_html
    assert f'id="findings-heading">Findings <span class="count">{len(moved)}</span>' in origin_html
    assert f'href="/issues/{origin_id}"' in client.get(f"/issues/{regression_id}").text


def test_api_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json()["read_only"] is True
    m = client.get("/api/metrics").json()
    assert m["issues_by_state"]["verified"] == 6
    assert client.get("/api/runs").json()[0]["is_baseline"] is True
    items = client.get("/api/work-items?state=verified").json()
    assert len(items) == 6
    events = client.get(f"/api/work-items/{items[0]['id']}/events").json()
    assert any(e["event"] == "rescan_verified" and e["to_state"] == "verified" for e in events)
    assert client.get("/api/findings?kind=5").json()[0]["layer"] == "helm"
    assert client.get("/api/work-items/9999/events").status_code == 404
    assert client.get("/runs/9999").status_code == 404


@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_dashboard_is_read_only(client: TestClient, method: str) -> None:
    r = client.request(method.upper(), "/issues/2")
    assert r.status_code == 405
    assert "read-only" in r.json()["detail"]
    assert r.headers["allow"] == "GET, HEAD, OPTIONS"


def test_every_route_is_get_only(client: TestClient) -> None:
    """Every registered route (pages, API, static) accepts only safe methods and rejects the
    rest with 405 before any handler runs."""
    from starlette.routing import Mount, Route

    routes = client.app.routes  # type: ignore[attr-defined]
    paths: list[str] = []
    for route in routes:
        if isinstance(route, Route):
            assert route.methods is not None and route.methods <= {"GET", "HEAD"}, route.path
            paths.append(route.path.replace("{run_id}", "1").replace("{wi_id}", "2"))
        elif isinstance(route, Mount):
            paths.append(route.path + "/dashboard.css")
    assert "/" in paths and "/api/metrics" in paths and "/static/dashboard.css" in paths
    for path in paths:
        assert client.get(path).status_code == 200, path
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            r = client.request(method, path)
            assert r.status_code == 405, (method, path)
            assert r.headers["allow"] == "GET, HEAD, OPTIONS"


# ---------------------------------------------------------------------------- redesign UI


def test_layout_navigation_and_header(client: TestClient) -> None:
    html = client.get("/runs").text
    assert '<nav id="primary-nav" aria-label="Primary">' in html
    nav = html[html.index('<nav id="primary-nav"') : html.index("</nav>")]
    labels = re.findall(r"<span>([^<]+)</span></a>", nav)
    assert labels == ["Overview", "Work items", "Scans", "Findings", "Pull requests", "Report"]
    assert 'href="/runs" aria-current="page"' in nav
    assert nav.count('aria-current="page"') == 1
    # compact context header: repository, branch, latest scan status, last updated
    assert 'aria-label="Current context"' in html
    for key in ("Repository", "Branch", "Latest scan", "Last updated"):
        assert key in html
    assert "Hunter-1298/superset" in html and ">main<" in html
    assert re.search(r'href="/runs/\d+"', html)
    assert "<time datetime=" in html
    # accessibility scaffolding
    assert '<a class="skip-link" href="#main">' in html
    assert '<main id="main" tabindex="-1">' in html
    assert 'aria-controls="primary-nav" aria-expanded="false"' in html


@pytest.mark.parametrize(
    ("path", "title"),
    [
        ("/", "Overview"),
        ("/issues", "Work items"),
        ("/runs", "Scans"),
        ("/findings", "Findings"),
        ("/prs", "Pull requests"),
        ("/report", "Run report"),
    ],
)
def test_every_page_has_title_and_lede(client: TestClient, path: str, title: str) -> None:
    html = client.get(path).text
    assert re.search(rf"<h1>\s*{re.escape(title)}\s*</h1>", html), path
    lede = re.search(r'<p class="lede">\s*(.+?)\s*</p>', html, re.S)
    assert lede and len(lede.group(1)) > 20, path
    assert html.count("<h1>") == 1


def test_readable_labels_replace_raw_enums(client: TestClient) -> None:
    def visible(html: str) -> str:
        """Strip attributes, options and secondary/mono spans so only primary text remains."""
        html = re.sub(
            r"<(code|span|div|td)[^>]*class=\"[^\"]*(mono|secondary)[^\"]*\"[^>]*>.*?</\1>",
            "",
            html,
            flags=re.S,
        )
        html = re.sub(r"<option[^>]*>.*?</option>", "", html, flags=re.S)
        html = re.sub(r"<details.*?</details>", "", html, flags=re.S)
        html = re.sub(r"\s(title|value|href)=\"[^\"]*\"", "", html)
        return html

    issues = client.get("/issues").text
    assert "Needs attention" in issues and "Ready for review" in issues and "Verified" in issues
    assert "Dependency upgrade" in issues and "Container hardening" in issues
    for raw in ("needs_human", "ready_for_human", "rescan_verified", "dependency_upgrade"):
        assert not re.search(rf">[^<]*\b{raw}\b[^<]*<", visible(issues)), raw
    detail = client.get("/issues/2").text
    assert "Devin session started" in detail and "Pull request opened" in detail
    for raw in ("session_created", "pr_opened", "in_remediation", "awaiting_rescan"):
        assert not re.search(rf">[^<]*\b{raw}\b[^<]*<", visible(detail)), raw
    runs = client.get("/runs").text
    assert "Complete" in runs and "Gate passed (report)" in runs
    # badges never rely on colour alone: every badge carries readable text
    for badge in re.findall(
        r'<span class="badge badge-[a-z]+"[^>]*>\s*(.*?)\s*</span>', issues, re.S
    ):
        assert badge.strip(), "empty badge"


def test_blocked_reasons_render_without_machine_prefix(client: TestClient, engine: Engine) -> None:
    assert (
        blocked_reason_text("blocked_reason:needs a VEX") == "Devin reported a blocker: needs a VEX"
    )
    assert blocked_reason_text("invalid_transition:queued:pr_opened") == (
        "The controller refused a state transition: queued:pr_opened"
    )
    assert blocked_reason_text("no_change_needed_requires_human_verification") == (
        "No change needed requires human verification"
    )
    assert blocked_reason_text("Plain sentence: with colon") == "Plain sentence: with colon"
    assert blocked_reason_text(None) == ""

    with session_scope(engine) as db:
        blocked = db.exec(
            select(WorkItem).where(col(WorkItem.state) == WorkItemState.needs_human.value)
        ).first()
        assert blocked is not None and blocked.blocked_reason
        blocked_id, reason = blocked.id, blocked.blocked_reason
    assert reason.startswith("blocked_reason:")
    detail_text = reason.split(":", 1)[1][:40]
    for html in (client.get("/").text, client.get(f"/issues/{blocked_id}").text):
        assert detail_text in html
        assert "Devin reported a blocker:" in html
        prose = re.sub(r"<[^>]*class=\"[^\"]*mono[^\"]*\"[^>]*>[^<]*</[^>]+>", "", html)
        assert not re.search(r">\s*blocked_reason:", prose)


def test_report_outcome_cards_name_what_they_count(client: TestClient, engine: Engine) -> None:
    html = client.get("/report").text
    with session_scope(engine) as db:
        states = [w.state for w in db.exec(select(WorkItem)).all()]
    needing_person = sum(
        1
        for s in states
        if s in (WorkItemState.needs_human, WorkItemState.ready_for_human, WorkItemState.failed)
    )
    assert needing_person >= 1
    assert "Findings fixed" in html and "Findings in regression" in html
    assert "Findings closed as blocked" in html
    labels = re.findall(r'<div class="label">([^<]*)</div>', html)
    assert "Blocked on a person" not in labels and "Regressions" not in labels
    card = re.search(
        r"Work items needing a person.*?<div class=\"value[^\"]*\">\s*(\d+)",
        html,
        re.S,
    )
    assert card is not None, "work-item card missing"
    assert int(card.group(1)) == needing_person


def test_work_item_filters_are_server_side(client: TestClient, engine: Engine) -> None:
    def ids(path: str) -> list[int]:
        html = client.get(path).text
        assert html.count("<h1>") == 1
        rows = html[html.index("<tbody") :] if "<tbody" in html else ""
        return sorted({int(i) for i in re.findall(r'href="/issues/(\d+)"', rows)})

    with session_scope(engine) as db:
        items = [(w.id or 0, w) for w in db.exec(select(WorkItem)).all()]
        all_ids = sorted(i for i, _ in items)
        by_state = {i for i, w in items if w.state == WorkItemState.needs_human}
        by_sev = {i for i, w in items if w.severity == Severity.high}
        by_kind = {i for i, w in items if w.kind == Kind.container_hardening}
        by_level = {
            i for i, w in items if w.verification_level == VerificationLevel.rescan_verified
        }
        paramiko = {i for i, w in items if "paramiko" in w.title.lower()}
        queue = {
            i
            for i, w in items
            if w.state in (WorkItemState.needs_human, WorkItemState.ready_for_human)
        }
    assert all((by_state, by_sev, by_kind, by_level, paramiko, queue))
    assert ids("/issues") == all_ids
    assert ids("/issues?state=needs_human") == sorted(by_state)
    assert ids("/issues?severity=high") == sorted(by_sev)
    assert ids("/issues?kind=container_hardening") == ids("/issues?kind=3") == sorted(by_kind)
    assert ids("/issues?level=rescan_verified") == sorted(by_level)
    assert ids("/issues?q=PARAMIKO") == sorted(paramiko)
    assert ids("/issues?queue=1") == sorted(queue)
    assert ids("/issues?severity=high&level=rescan_verified") == sorted(by_sev & by_level)
    # active filters are echoed as readable pills, invalid enum values are rejected
    html = client.get("/issues?state=needs_human&kind=3&q=x").text
    assert "Needs attention" in html and "Container hardening" in html
    assert "Search: <strong>x</strong>" in html
    # submitting the form with every select on "Any" sends blank values: no filter, no 422
    blank = "/issues?q=&state=&severity=&kind=&level="
    assert ids(blank) == all_ids
    assert 'id="f-queue" type="checkbox" name="queue" value="1"' in client.get(blank).text
    assert ids("/issues?q=paramiko&state=&severity=&kind=&level=") == sorted(paramiko)
    assert ids("/issues?queue=1&state=&severity=&kind=&level=") == sorted(queue)
    findings_all = client.get("/findings").text.count("<tr")
    assert client.get("/findings?severity=&state=&kind=&layer=").text.count("<tr") == findings_all
    # unknown state/severity values simply match nothing; kind/level aliases are validated
    for bogus in ("/issues?state=bogus", "/issues?severity=bogus"):
        r = client.get(bogus)
        assert r.status_code == 200 and "No work items match" in r.text, bogus
    assert client.get("/issues?kind=bogus").status_code == 422
    assert client.get("/issues?level=bogus").status_code == 422
    # search text is escaped, never reflected raw
    html = client.get("/issues?q=%3Cscript%3Ealert(1)%3C/script%3E").text
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_work_items_table_structure(client: TestClient) -> None:
    html = client.get("/issues").text
    assert 'class="table-wrap allow-sticky"' in html
    assert '<table class="data">' in html
    head = html[html.index("<thead") : html.index("</thead>")]
    cols = [
        re.sub(r"<[^>]+>", "", c).strip() for c in re.findall(r"<th[^>]*>(.*?)</th>", head, re.S)
    ]
    assert cols[:3] == ["Work item", "Severity", "State"]
    # fingerprints belong to the detail page, not the list
    assert "fingerprint" not in html.lower()


def test_no_results_state(client: TestClient) -> None:
    html = client.get("/issues?q=zzz-no-such-item").text
    assert "No work items match" in html
    assert 'href="/issues"' in html
    findings = client.get("/findings?state=fixed&kind=unclassified").text
    assert "No findings match" in findings


def test_empty_database_states(tmp_path: Path) -> None:
    empty = Settings(
        data_dir=tmp_path,
        database_file="empty.sqlite3",
        replay_mode=True,
        acu_cost_usd=ACU_COST,
        repo_root=REPO_ROOT,
    )
    open_database(empty.database_path).dispose()
    with TestClient(create_app(empty)) as c:
        for path in ("/", "/issues", "/runs", "/findings", "/prs", "/report"):
            r = c.get(path)
            assert r.status_code == 200, path
            assert 'class="empty' in r.text, path
        html = c.get("/").text
        assert "No scans yet" in html and "No work items yet" in html
        assert "Nothing needs attention" in html
        assert "No work items yet" in c.get("/issues").text
        assert "No findings yet" in c.get("/findings").text
        assert c.get("/api/metrics").json()["open_high_critical"] == 0
        assert c.get("/report").text.count("<h1>") == 1


def test_error_pages_are_html_for_browsers_and_json_for_api(client: TestClient) -> None:
    r = client.get("/issues/9999", headers={"accept": "text/html"})
    assert r.status_code == 404 and "text/html" in r.headers["content-type"]
    assert "<h1>" in r.text and "Page not found" in r.text and 'href="/"' in r.text
    r = client.get("/issues/9999", headers={"accept": "application/json"})
    assert r.status_code == 404 and r.json()["detail"]
    # the JSON API never switches to HTML, whatever the client accepts
    r = client.get("/api/work-items/9999/events", headers={"accept": "text/html"})
    assert r.status_code == 404 and r.headers["content-type"].startswith("application/json")


def test_responsive_structure_and_no_inline_styles(client: TestClient) -> None:
    css = client.get("/static/dashboard.css")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]
    text = css.text
    assert "@media (max-width" in text and ".sidebar" in text and ".nav-toggle" in text
    assert "position: sticky" in text
    assert ":focus-visible" in text
    assert "prefers-reduced-motion" in text
    for path in ("/", "/issues", "/issues/2", "/runs", "/runs/1", "/findings", "/prs", "/report"):
        html = client.get(path).text
        assert " style=" not in html, path
        assert "<table" not in html or '<table class="' in html, path


# --------------------------------------------------------------------------------- report


def test_report_selects_baseline_and_latest_closing_run(engine: Engine, settings: Settings) -> None:
    body = build_report_for(engine, settings, NOW)
    assert body.baseline is not None and body.baseline.is_baseline
    assert body.baseline.external_run_id == "replay-baseline"
    assert body.latest is not None and body.latest.id != body.baseline.id
    assert body.latest.source_branch == "main" and body.latest.status == "complete"
    assert body.latest_is_closing_candidate
    assert all(j["success"] for j in body.latest.jobs)
    assert body.baseline.raw_total == 10 and body.baseline.policy_total == 10
    assert body.latest.raw_total > body.latest.policy_total, "approved VEX suppresses in policy"
    assert body.latest.gate_passed and not body.latest.gate_ready_for_enforce
    assert body.baseline.lean_digest != body.latest.lean_digest
    assert body.latest.tools["trivy"] == "0.71.2"


def test_report_deltas_outcomes_and_costs(engine: Engine, settings: Settings) -> None:
    body = build_report_for(engine, settings, NOW)
    high = next(d for d in body.severity_deltas if d.severity == "HIGH")
    assert high.raw_delta < 0 and high.policy_delta <= high.raw_delta
    assert body.outcomes["fixed"] == 5
    assert body.outcomes["approved_disposition"] == 1
    assert body.outcomes_by_kind["no_fix_reachability"] == {"approved_disposition": 1}
    assert body.work_items_by_state["verified"] == 6
    assert body.verified_items == 6 and body.retries_total == 1
    assert body.estimated_cost_total_usd == pytest.approx(body.acu_total * ACU_COST)
    blocked = [w for w in body.work_items if w.blocked_reason]
    assert blocked and blocked[0].state == "needs_human"
    assert {w.verification_label for w in body.work_items if w.state == "verified"} == {
        "L6 rescan_verified"
    }


def test_report_compares_dependencies_with_upstream_master(
    engine: Engine, settings: Settings
) -> None:
    body = build_report_for(engine, settings, NOW)
    assert body.upstream_master_sha == UPSTREAM_SHA
    assert body.upstream_pins_source == f"fixtures/source/{UPSTREAM_SHA}/requirements-base.txt"
    assert not any("unavailable" in n for n in body.notes)
    rows = {d.package: d for d in body.dependencies}
    pillow = rows["pillow"]
    assert pillow.baseline_version == "10.2.0"
    assert pillow.devin_target_version == "10.3.0"
    assert pillow.upstream_master_version == "12.3.0"
    assert pillow.relation_to_upstream == "below"
    assert pillow.min_fixed_version == "10.3.0"
    assert pillow.retries_used == 1 and pillow.verification_label == "L6 rescan_verified"
    assert rows["requests"].relation_to_upstream == "no_target"


def test_report_regression_keeps_package_and_lineage(engine: Engine, settings: Settings) -> None:
    body = build_report_for(engine, settings, NOW)
    crypto = [d for d in body.dependencies if d.package == "cryptography"]
    assert len(crypto) == 2, "verified original plus its regression row"
    verified = next(d for d in crypto if d.verification_label == "L6 rescan_verified")
    regression = next(d for d in crypto if d.state == "queued")
    assert regression.work_item_id != verified.work_item_id
    for row in crypto:
        assert row.upstream_master_version == "50.0.1"
        assert row.baseline_version and row.min_fixed_version and row.vuln_ids
    assert sum(verified.outcome_states.values()) == sum(regression.outcome_states.values())
    wi_rows = {w.work_item_id: w for w in body.work_items}
    assert wi_rows[verified.work_item_id].member_findings >= 1


def test_report_without_upstream_fixture_is_explicit(engine: Engine, settings: Settings) -> None:
    body = build_report_for(
        engine, settings.model_copy(update={"upstream_master_sha": "0" * 40}), NOW
    )
    assert any("unreadable" in n for n in body.notes)
    assert any("unavailable" in n for n in body.notes)
    assert all(d.upstream_master_version is None for d in body.dependencies)
    body = build_report_for(engine, settings.model_copy(update={"upstream_master_sha": None}), NOW)
    assert any("HL_UPSTREAM_MASTER_SHA unset" in n for n in body.notes)


def test_report_markdown_persist_and_serve(
    engine: Engine, settings: Settings, client: TestClient
) -> None:
    body = build_report_for(engine, settings, NOW)
    md = render_markdown(body)
    assert "| pillow | 10.2.0 | 10.3.0 | 12.3.0 | below |" in md
    assert "upstream-master" in md and "rescan_verified" in md
    row_id = persist_report(engine, body, md)
    stored = latest_persisted_report(engine)
    assert stored is not None and stored.id == row_id
    assert stored.baseline_run_id == body.baseline.id if body.baseline else True
    assert client.get("/report.md").text == md
    assert client.get("/api/report").json()["verified_items"] == 6
    assert f"persisted report #{row_id}" in client.get("/report").text
    assert "computed now" in client.get("/report?live=1").text
