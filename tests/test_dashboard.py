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
    assert "REPLAY (no spend)" in r.text


def test_overview_shows_required_metrics(client: TestClient, metrics: Metrics) -> None:
    html = client.get("/").text
    for label in (
        "Open HIGH/CRITICAL",
        "Gate ready for enforce",
        "First-try success",
        "Remediation time",
        "ACU per verified issue",
        "Est. cost per verified issue",
        "Issues by state",
        "Findings by kind",
        "Throughput",
    ):
        assert label in html
    assert f">{metrics.open_high_critical}<" in html
    assert "80%" in html


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


def test_issue_page_shows_blocked_reason_and_events(client: TestClient) -> None:
    html = client.get("/issues?state=needs_human").text
    assert "blocked_reason" in html
    html = client.get("/issues/2").text
    assert "rescan_verified" in html and "Devin sessions" in html and "Events" in html


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
    assert f'<a href="{pr_url}">{pr_url}</a>' in html
    origin_html = client.get(f"/issues/{origin_id}").text
    assert f'href="/issues/{regression_id}"' in origin_html
    assert f"Member findings ({len(moved)})" in origin_html
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
