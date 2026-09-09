"""Operator mode (`serve --operator`): the single write route, its CSRF/confirmation/origin rules,
the launch path through the orchestrator's safeguards, the poll loop, the live-client request
shapes, and the fact that everything else (plain serve, replay) stays read-only.

Everything here runs against the in-memory GitHub/Devin doubles or an `httpx.MockTransport`;
no test can reach the network or spend an ACU."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlmodel import select

from hardening_loop.config import BASELINE_SHA, FORK_REPO, UPSTREAM_REPO, Settings
from hardening_loop.dashboard.app import create_app
from hardening_loop.db import open_database, session_scope
from hardening_loop.devin.enums import DevinStatus, DevinStatusDetail
from hardening_loop.devin.fake import FakeDevin
from hardening_loop.devin.protocol import CreateSessionRequest
from hardening_loop.devin.rest import DevinError, DevinRest
from hardening_loop.domain.enums import Severity, WorkItemState
from hardening_loop.github.fake import FakeGitHub
from hardening_loop.github.rest import GitHubError, GitHubRest
from hardening_loop.models.tables import Event, Session, WorkItem
from hardening_loop.operator import (
    OperatorConfigError,
    OperatorContext,
    OperatorRuntime,
    build_doubles_orchestrator,
    build_live_orchestrator,
    require_loopback_bind,
)
from hardening_loop.orchestrator.engine import AWAITING_DISPATCH_LABEL, Orchestrator
from hardening_loop.orchestrator.launch import LaunchBlock, LaunchResult
from hardening_loop.replay.synth import SyntheticRun, ingest_synthetic

REPO_ROOT = Path(__file__).resolve().parents[1]
LOGIN = "operator-test"


def _settings(db: Path, **kw: Any) -> Settings:
    base: dict[str, Any] = {
        "data_dir": db.parent,
        "database_file": db.name,
        "operator_mode": True,
        "operator_login": LOGIN,
        "repo_root": REPO_ROOT,
        "max_concurrent_sessions": 2,
        "global_acu_budget": 12.0,
    }
    base.update(kw)
    return Settings(**base)


def _text(r: httpx.Response) -> str:
    body = r.text
    if "<main" in body:
        body = body[body.index("<main") :]
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", body))


@pytest.fixture
def world(tmp_path: Path) -> tuple[Settings, Orchestrator, OperatorContext]:
    settings = _settings(tmp_path / "op.sqlite3")
    orch = build_doubles_orchestrator(settings)
    return settings, orch, OperatorContext.for_doubles(orch, login=LOGIN)


@pytest.fixture
def client(world: tuple[Settings, Orchestrator, OperatorContext]) -> Iterator[TestClient]:
    settings, _orch, ctx = world
    with TestClient(create_app(settings, operator=ctx)) as c:
        yield c


def _items(orch: Orchestrator) -> dict[str, WorkItem]:
    with session_scope(orch.engine) as db:
        rows = db.exec(select(WorkItem)).all()
        for row in rows:
            db.refresh(row)
        db.expunge_all()
    return {w.group_key: w for w in rows}


def _devin(orch: Orchestrator) -> FakeDevin:
    assert isinstance(orch.devin, FakeDevin)
    return orch.devin


def _form(ctx: OperatorContext, **extra: str) -> dict[str, str]:
    return {"csrf": ctx.csrf_token, "confirm": "launch", **extra}


# ------------------------------------------------------------------------- building the runtime


def test_doubles_seed_opens_issues_but_dispatches_nothing(
    world: tuple[Settings, Orchestrator, OperatorContext],
) -> None:
    _, orch, ctx = world
    items = _items(orch)
    assert items and all(w.state is WorkItemState.issue_open for w in items.values())
    assert all(w.issue_number is not None for w in items.values())
    assert _devin(orch).created_requests() == []
    assert ctx.live is False and ctx.auto_dispatch is False
    # Opening the same database again does not re-seed.
    again = build_doubles_orchestrator(_settings(Path(orch.engine.url.database or "")))
    assert len(_items(again)) == len(items)


def test_live_builder_fails_closed_on_missing_config(tmp_path: Path) -> None:
    db = tmp_path / "x.sqlite3"
    with pytest.raises(OperatorConfigError, match="replay"):
        build_live_orchestrator(_settings(db, replay_mode=True))
    with pytest.raises(OperatorConfigError, match="HL_GITHUB_TOKEN"):
        build_live_orchestrator(_settings(db))
    with pytest.raises(OperatorConfigError, match="HL_DEVIN_API_KEY"):
        build_live_orchestrator(_settings(db, github_token=SecretStr("t")))
    with pytest.raises(OperatorConfigError, match="HL_OPERATOR_LOGIN"):
        build_live_orchestrator(
            _settings(
                db,
                github_token=SecretStr("t"),
                devin_api_key=SecretStr("k"),
                operator_login=None,
            )
        )
    with pytest.raises(OperatorConfigError, match="replay"):
        build_doubles_orchestrator(_settings(db, replay_mode=True))


def test_doubles_context_refuses_live_clients(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "x.sqlite3")
    engine = open_database(settings.database_path)
    live_gh = GitHubRest(
        SecretStr("t"), transport=httpx.MockTransport(lambda r: httpx.Response(500))
    )
    orch = Orchestrator(engine, live_gh, FakeDevin(), settings)
    with pytest.raises(OperatorConfigError):
        OperatorContext.for_doubles(orch, login=LOGIN)


def test_replay_mode_can_never_carry_an_operator(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "x.sqlite3", replay_mode=True, operator_mode=False)
    engine = open_database(settings.database_path)
    orch = Orchestrator(engine, FakeGitHub(main_head=BASELINE_SHA), FakeDevin(), settings)
    ctx = OperatorContext.for_doubles(orch, login=LOGIN)
    with pytest.raises(ValueError, match="read-only"):
        create_app(settings, operator=ctx)


# ------------------------------------------------------------------------- read-only defaults


def test_plain_serve_rejects_launch_post(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "ro.sqlite3", operator_mode=False)
    build_doubles_orchestrator(settings)  # populate
    with TestClient(create_app(settings)) as c:
        assert c.get("/issues/1").status_code == 200
        assert "Launch Devin" not in c.get("/issues/1").text
        assert c.get("/operator/launch/1").status_code == 404
        r = c.post("/operator/launch/1", data={"csrf": "x", "confirm": "launch"})
        assert r.status_code == 405
        assert r.headers["allow"] == "GET, HEAD, OPTIONS"
        assert c.get("/operator/cancel/1").status_code == 404
        assert (
            c.post("/operator/cancel/1", data={"csrf": "x", "confirm": "stop"}).status_code == 405
        )
        assert c.get("/healthz").json()["operator_mode"] is False


def test_operator_mode_allows_exactly_two_writes(client: TestClient) -> None:
    from starlette.routing import Mount, Route

    writes: list[str] = []
    for route in client.app.routes:  # type: ignore[attr-defined]
        if isinstance(route, Route) and route.methods and not route.methods <= {"GET", "HEAD"}:
            writes.append(route.path)
        elif isinstance(route, Mount):
            assert client.get(route.path + "/dashboard.css").status_code == 200
    assert sorted(writes) == ["/operator/cancel/{wi_id}", "/operator/launch/{wi_id}"]
    for path in ("/", "/issues", "/issues/1", "/findings", "/findings/1", "/runs", "/report"):
        assert client.get(path).status_code == 200, path
        for method in ("POST", "PUT", "PATCH", "DELETE"):
            assert client.request(method, path).status_code == 405, (method, path)
    for method in ("PUT", "PATCH", "DELETE"):
        assert client.request(method, "/operator/launch/1").status_code == 405
        assert client.request(method, "/operator/cancel/1").status_code == 405
    assert client.get("/healthz").json()["operator_mode"] is True


# ------------------------------------------------------------------------- the launch route


def test_confirmation_page_previews_the_launch(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    issue = client.get(f"/issues/{wi.id}")
    assert f'href="/operator/launch/{wi.id}"' in issue.text and "Launch Devin" in issue.text
    r = client.get(f"/operator/launch/{wi.id}")
    assert r.status_code == 200
    body = _text(r)
    assert "Launch Devin for work item" in body
    assert f"existing tracking issue #{wi.issue_number}" in body
    assert "5 ACU" in body and "0 of 2 in use" in body
    assert "stay in GitHub" in body
    assert f'name="csrf" value="{ctx.csrf_token}"' in r.text
    assert 'name="confirm" value="launch"' in r.text
    assert client.get("/operator/launch/9999").status_code == 404


@pytest.mark.parametrize(
    ("form", "headers", "status"),
    [
        ({"confirm": "launch", "csrf": ""}, {}, 403),  # no CSRF token
        ({"confirm": "launch", "csrf": "wrong"}, {}, 403),
        ({}, {}, 400),  # valid token, not confirmed
        ({"confirm": "yes"}, {}, 400),
        ({"confirm": "launch"}, {"sec-fetch-site": "cross-site"}, 403),
        ({"confirm": "launch"}, {"sec-fetch-site": "same-site"}, 403),
        ({"confirm": "launch"}, {"origin": "https://attacker.invalid"}, 403),
        ({"confirm": "launch"}, {"origin": "null"}, 403),
        ({"confirm": "launch"}, {"origin": "http://testserver:9"}, 403),  # wrong port
    ],
)
def test_launch_post_rejections_create_nothing(
    client: TestClient,
    world: tuple[Settings, Orchestrator, OperatorContext],
    form: dict[str, str],
    headers: dict[str, str],
    status: int,
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    data = {"csrf": ctx.csrf_token, **form}
    if data["csrf"] == "":
        del data["csrf"]
    r = client.post(f"/operator/launch/{wi.id}", data=data, headers=headers)
    assert r.status_code == status
    assert _devin(orch).created_requests() == []
    assert _items(orch)["pypi:cryptography"].state is WorkItemState.issue_open


def test_launch_post_accepts_matching_origin(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    r = client.post(
        f"/operator/launch/{wi.id}",
        data=_form(ctx),
        headers={"origin": "http://testserver", "sec-fetch-site": "same-origin"},
    )
    assert r.status_code == 200
    assert len(_devin(orch).created_requests()) == 1


def test_launch_post_requires_form_encoding(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    r = client.post(f"/operator/launch/{wi.id}", json=_form(ctx))
    assert r.status_code == 415
    assert _devin(orch).created_requests() == []


def test_successful_launch_records_the_audit_trail(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    assert wi.severity is Severity.high
    r = client.post(
        f"/operator/launch/{wi.id}", data=_form(ctx), headers={"sec-fetch-site": "same-origin"}
    )
    assert r.status_code == 200
    body = _text(r)
    assert "Devin launched" in body and "Session created" in body
    after = _items(orch)["pypi:cryptography"]
    assert after.state is WorkItemState.session_active
    assert after.active_session_id is not None
    reqs = _devin(orch).created_requests()
    assert len(reqs) == 1
    assert reqs[0].max_acu_limit == after.acu_cap == 5
    assert {"hl", f"wi-{wi.id}"} <= set(reqs[0].tags)
    assert reqs[0].repos == [f"https://github.com/{FORK_REPO}"] or FORK_REPO in " ".join(
        reqs[0].repos
    )
    assert wi.issue_number is not None
    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    issue = gh.issues[wi.issue_number]
    assert any(LOGIN in c and "launched" in c for c in issue.comments)
    assert "dispatch:approved" not in issue.labels  # HIGH never needed approval
    with session_scope(orch.engine) as db:
        events = db.exec(
            select(Event).where(Event.entity_type == "work_item", Event.entity_id == wi.id)
        ).all()
        names = [e.event for e in events]
        assert "operator_launch" in names
        launch = next(e for e in events if e.event == "operator_launch")
        assert launch.actor == "operator" and LOGIN in (launch.reason or "")
        sessions = db.exec(select(Session).where(Session.work_item_id == wi.id)).all()
        assert len(sessions) == 1
    # The work item and CVE pages now show the session and no launch button.
    page = client.get(f"/issues/{wi.id}").text
    assert after.active_session_id in page
    assert f'href="/operator/launch/{wi.id}"' not in page
    assert "already working on this item" in _text(client.get(f"/issues/{wi.id}"))


def test_lower_severity_launch_adds_dispatch_approved(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:requests"]
    assert wi.severity is Severity.medium and wi.issue_number is not None
    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    assert AWAITING_DISPATCH_LABEL in gh.issues[wi.issue_number].labels
    confirm = _text(client.get(f"/operator/launch/{wi.id}"))
    assert "dispatch:approved" in confirm
    r = client.post(f"/operator/launch/{wi.id}", data=_form(ctx))
    assert r.status_code == 200
    labels = gh.issues[wi.issue_number].labels
    assert "dispatch:approved" in labels and AWAITING_DISPATCH_LABEL not in labels
    assert _items(orch)["pypi:requests"].state is WorkItemState.session_active


def test_duplicate_launch_is_refused_without_a_second_session(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    assert client.post(f"/operator/launch/{wi.id}", data=_form(ctx)).status_code == 200
    r = client.post(f"/operator/launch/{wi.id}", data=_form(ctx))
    assert r.status_code == 409
    body = _text(r)
    assert "Launch refused" in body and "already working on this item" in body
    assert len(_devin(orch).created_requests()) == 1
    with session_scope(orch.engine) as db:
        names = [
            e.event
            for e in db.exec(
                select(Event).where(Event.entity_type == "work_item", Event.entity_id == wi.id)
            ).all()
        ]
    assert "operator_launch_refused" in names
    assert client.get(f"/operator/launch/{wi.id}").status_code == 200  # preview still renders


def test_capacity_and_budget_refusals(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    settings, orch, ctx = world
    items = _items(orch)
    a, b, c_ = items["pypi:cryptography"], items["pypi:pillow"], items["pypi:requests"]
    assert client.post(f"/operator/launch/{a.id}", data=_form(ctx)).status_code == 200
    assert client.post(f"/operator/launch/{b.id}", data=_form(ctx)).status_code == 200
    r = client.post(f"/operator/launch/{c_.id}", data=_form(ctx))
    assert r.status_code == 409 and "Every concurrent session slot is in use" in _text(r)
    assert ctx.preview(c_.id or 0).block is LaunchBlock.at_capacity
    assert len(_devin(orch).created_requests()) == 2

    settings.max_concurrent_sessions = 5  # slots free, but 5+5 already committed of 12
    assert ctx.preview(c_.id or 0).block is LaunchBlock.over_budget
    r = client.post(f"/operator/launch/{c_.id}", data=_form(ctx))
    assert r.status_code == 409 and "global ACU budget" in _text(r)
    assert len(_devin(orch).created_requests()) == 2
    assert "budget" in _text(client.get(f"/issues/{c_.id}"))

    # the lists never offer a Launch button the launch page would refuse
    for path in ("/", "/issues?stage=ready"):
        html = client.get(path).text
        assert f'href="/operator/launch/{c_.id}">Launch blocked · Over ACU budget' in html
        assert f'class="btn btn-launch btn-sm" href="/operator/launch/{c_.id}"' not in html


def test_launch_creates_a_missing_issue_first(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    before = set(gh.issues)
    gh.issues[wi.issue_number or 0].state = "closed"  # nothing open to adopt
    with session_scope(orch.engine) as db:
        row = db.get(WorkItem, wi.id)
        assert row is not None
        row.issue_number = None
        row.issue_url = None
        row.state = WorkItemState.queued
        db.add(row)
    assert "Opens the tracking issue" in _text(client.get(f"/operator/launch/{wi.id}"))
    assert client.post(f"/operator/launch/{wi.id}", data=_form(ctx)).status_code == 200
    after = _items(orch)["pypi:cryptography"]
    assert after.issue_number is not None and after.issue_number not in before
    assert after.state is WorkItemState.session_active


def test_launch_adopts_an_existing_open_issue_instead_of_duplicating(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    # Simulate a crash after GitHub created the issue but before the database recorded it.
    orphan = gh.issues[wi.issue_number or 0]
    with session_scope(orch.engine) as db:
        row = db.get(WorkItem, wi.id)
        assert row is not None
        row.issue_number = None
        row.issue_url = None
        row.state = WorkItemState.queued
        db.add(row)
    before = set(gh.issues)
    assert client.post(f"/operator/launch/{wi.id}", data=_form(ctx)).status_code == 200
    after = _items(orch)["pypi:cryptography"]
    assert set(gh.issues) == before, "no second issue for the same title"
    assert after.issue_number is not None and after.issue_number == wi.issue_number
    assert gh.issues[after.issue_number].title == orphan.title
    with session_scope(orch.engine) as db:
        reasons = [
            e.reason
            for e in db.exec(select(Event).where(Event.entity_id == wi.id)).all()
            if e.event == "issue_created"
        ]
    assert any(r and r.startswith("adopted existing ") for r in reasons)


def test_auto_open_issues_off_defers_the_issue_to_launch(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "quiet.sqlite3", auto_open_issues=False)
    orch = build_doubles_orchestrator(settings)
    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    items = _items(orch)
    assert items and all(w.state is WorkItemState.queued for w in items.values())
    assert gh.issues == {}
    orch.tick(auto_dispatch=False)
    assert gh.issues == {}, "ticks never open issues while auto_open_issues is off"
    ctx = OperatorContext.for_doubles(orch, login=LOGIN)
    wi = items["pypi:cryptography"]
    with TestClient(create_app(settings, operator=ctx)) as c:
        assert c.post(f"/operator/launch/{wi.id}", data=_form(ctx)).status_code == 200
    assert len(gh.issues) == 1
    assert _items(orch)["pypi:cryptography"].state is WorkItemState.session_active


def test_relaunch_after_needs_human_reuses_the_same_item(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    assert client.post(f"/operator/launch/{wi.id}", data=_form(ctx)).status_code == 200
    sid = _items(orch)["pypi:cryptography"].active_session_id
    assert sid is not None
    _devin(orch).set_state(sid, DevinStatus.exit, DevinStatusDetail.out_of_credits, acus=1.0)
    ctx.tick()
    stuck = _items(orch)["pypi:cryptography"]
    assert stuck.state is WorkItemState.needs_human and stuck.blocked_reason
    assert "Relaunch Devin" in client.get(f"/issues/{wi.id}").text
    r = client.post(f"/operator/launch/{wi.id}", data=_form(ctx))
    assert r.status_code == 200
    again = _items(orch)["pypi:cryptography"]
    assert again.state is WorkItemState.session_active and again.active_session_id != sid
    assert len(_devin(orch).created_requests()) == 2


def test_launch_unknown_item_is_404(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, _, ctx = world
    assert client.post("/operator/launch/9999", data=_form(ctx)).status_code == 404


def test_launch_failure_at_devin_is_reported_not_swallowed(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    _devin(orch).fail_next["create_session"] = RuntimeError("devin 503")
    r = client.post(f"/operator/launch/{wi.id}", data=_form(ctx))
    assert r.status_code == 502
    assert "No Devin session was created" in _text(r) or "failed" in _text(r).lower()
    assert _devin(orch).created_requests() == []
    assert _items(orch)["pypi:cryptography"].state in (
        WorkItemState.issue_open,
        WorkItemState.needs_human,
    )


def test_failed_audit_comment_revokes_dispatch_approval(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    """Approval granted by a launch that then fails must not leave the item eligible for the
    scheduler: the next auto-dispatch tick creates nothing."""
    _, orch, ctx = world
    wi = _items(orch)["pypi:requests"]
    assert wi.severity is Severity.medium and wi.issue_number is not None
    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    gh.fail_next["comment_issue"] = RuntimeError("github 502")
    r = client.post(f"/operator/launch/{wi.id}", data=_form(ctx))
    assert r.status_code == 502
    labels = gh.issues[wi.issue_number].labels
    assert "dispatch:approved" not in labels and AWAITING_DISPATCH_LABEL in labels
    assert _devin(orch).created_requests() == []
    orch.tick(auto_dispatch=True)  # HIGH items dispatch; the MEDIUM one must not
    assert not any(f"wi-{wi.id}" in req.tags for req in _devin(orch).created_requests())
    assert _items(orch)["pypi:requests"].state is WorkItemState.issue_open


def test_github_failure_after_session_creation_keeps_the_session(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    """Devin accepted the session; a failing 'session started' comment is recorded as an event
    and the launch still reports the session instead of escaping as a 500."""
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    calls = 0

    def flaky(repo: str, number: int, body: str) -> None:
        nonlocal calls
        calls += 1
        if "Devin session started" in body:
            raise RuntimeError("github 502")
        FakeGitHub.comment_issue(gh, repo, number, body)

    gh.comment_issue = flaky  # type: ignore[method-assign]
    r = client.post(f"/operator/launch/{wi.id}", data=_form(ctx))
    assert r.status_code == 200 and calls == 2
    created = _devin(orch).created_requests()
    assert len(created) == 1
    after = _items(orch)["pypi:cryptography"]
    assert after.state is WorkItemState.session_active and after.active_session_id
    with session_scope(orch.engine) as db:
        rows = db.exec(select(Session).where(Session.work_item_id == wi.id)).all()
        assert [s.devin_id for s in rows] == [after.active_session_id]
        names = [
            e.event
            for e in db.exec(
                select(Event).where(Event.entity_type == "work_item", Event.entity_id == wi.id)
            ).all()
        ]
    assert "issue_comment_failed" in names


def test_unexpected_launch_exception_is_a_structured_502(
    client: TestClient, world: tuple[Settings, Orchestrator, OperatorContext]
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]

    def boom(work_item_id: int) -> LaunchResult:
        raise RuntimeError("unexpected")

    ctx.launch = boom  # type: ignore[method-assign]
    r = client.post(f"/operator/launch/{wi.id}", data=_form(ctx))
    assert r.status_code == 502
    assert "RuntimeError" in _text(r)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "[::1]", "127.0.0.2"])
def test_operator_mode_binds_loopback(host: str) -> None:
    require_loopback_bind(host)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "dashboard.example", ""])
def test_operator_mode_refuses_non_loopback_bind(host: str) -> None:
    with pytest.raises(OperatorConfigError, match="loopback"):
        require_loopback_bind(host)


# ------------------------------------------------------------------------- poll loop


def test_runtime_tick_polls_session_to_pr_and_survives_errors(
    world: tuple[Settings, Orchestrator, OperatorContext],
) -> None:
    _, orch, ctx = world
    wi = _items(orch)["pypi:cryptography"]
    assert ctx.launch(wi.id or 0).ok
    sid = _items(orch)["pypi:cryptography"].active_session_id
    assert sid is not None
    runtime = OperatorRuntime(ctx, poll_interval_seconds=5)
    runtime._job()
    assert runtime.ticks == 1 and runtime.last_error is None
    assert _items(orch)["pypi:cryptography"].state is WorkItemState.session_active
    assert len(_devin(orch).created_requests()) == 1  # auto_dispatch off: nothing new

    gh = orch.gh
    assert isinstance(gh, FakeGitHub)
    url = gh.open_pr(
        title="fix: cryptography",
        head_ref="devin/1-dep",
        head_sha="a" * 40,
        files=["pyproject.toml", "requirements/base.txt"],
    )
    _devin(orch).finish(
        sid,
        {
            "outcome": "pr_opened",
            "pr_url": url,
            "base_branch": "main",
            "findings_addressed": ["CVE-2024-26130"],
            "findings_not_addressed": [],
            "tests_run": [{"command": "pytest -q", "exit_code": 0}],
            "packages": [{"name": "cryptography", "from": "42.0.2", "to": "42.0.4"}],
            "regenerated_with": "./scripts/uv-pip-compile.sh",
        },
        acus=2.0,
        pull_requests=[url],
    )
    runtime._job()
    after = _items(orch)["pypi:cryptography"]
    assert after.state is WorkItemState.checks_running and after.pr_number is not None

    _devin(orch).fail_next["get_session"] = RuntimeError("boom")
    gh.fail_next["list_check_runs"] = RuntimeError("boom")
    runtime._job()  # must not raise
    assert runtime.ticks >= 2
    runtime.start()
    assert runtime.scheduler.get_job("tick") is not None
    runtime.stop()
    assert not runtime.scheduler.running


def test_launch_work_item_alias(world: tuple[Settings, Orchestrator, OperatorContext]) -> None:
    _, orch, _ = world
    wi = _items(orch)["pypi:cryptography"]
    res = orch.launch_work_item(wi.id or 0, "alias-user")
    assert res.ok and res.outcome == "created"
    with session_scope(orch.engine) as db:
        ev = db.exec(select(Event).where(Event.event == "operator_launch")).one()
        assert "alias-user" in (ev.reason or "")
    with pytest.raises(LookupError):
        orch.launch_work_item(9999, "alias-user")


# ------------------------------------------------------------------------- live clients


def _devin_transport(calls: list[httpx.Request]) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        path = request.url.path
        if request.method == "POST" and path.endswith("/sessions"):
            body = json.loads(request.content)
            return httpx.Response(
                200,
                json={
                    "session_id": "devin-abc",
                    "url": "https://app.devin.ai/sessions/abc",
                    "status": "new",
                    "status_detail": None,
                    "acus_consumed": 0,
                    "pull_requests": [],
                    "tags": body["tags"],
                    "created_at": 1,
                    "updated_at": 1,
                    "unknown_field": "ignored",
                },
            )
        if request.method == "GET" and path.endswith("/sessions/devin-abc"):
            return httpx.Response(
                200,
                json={
                    "session_id": "devin-abc",
                    "status": "exit",
                    "status_detail": "finished",
                    "acus_consumed": 2.5,
                    "pull_requests": [
                        {"pr_url": "https://github.com/x/y/pull/1", "pr_state": "open"}
                    ],
                    "structured_output": {"outcome": "pr_opened"},
                },
            )
        if request.method == "GET" and path.endswith("/sessions"):
            after = request.url.params.get("after")
            if after is None:
                return httpx.Response(
                    200,
                    json={
                        "items": [{"session_id": "s1", "status": "running", "tags": ["wi-1"]}],
                        "has_next_page": True,
                        "end_cursor": "c1",
                    },
                )
            return httpx.Response(
                200,
                json={
                    "items": [
                        {"session_id": "s2", "status": "exit", "tags": ["wi-1", "hl"]},
                        {"session_id": "s3", "status": "exit", "tags": ["other"]},
                    ],
                    "has_next_page": False,
                    "end_cursor": None,
                },
            )
        if request.method == "DELETE" and path.endswith("/sessions/devin-abc"):
            return httpx.Response(
                200,
                json={
                    "session_id": "devin-abc",
                    "status": "exit",
                    "status_detail": None,
                    "acus_consumed": 1.25,
                    "pull_requests": [],
                },
            )
        if request.method == "DELETE" and path.endswith("/sessions/devin-404"):
            return httpx.Response(404, json={"detail": "no such session"})
        if request.method == "GET" and path.endswith("/sessions/devin-bad"):
            return httpx.Response(200, json={"session_id": "devin-bad", "status": "weird"})
        if request.method == "GET" and path.endswith("/sessions/devin-404"):
            return httpx.Response(404, json={"detail": "no such session"})
        raise AssertionError(f"unexpected {request.method} {path}")

    return httpx.MockTransport(handler)


def test_devin_rest_request_and_response_shapes() -> None:
    calls: list[httpx.Request] = []
    client = DevinRest(
        SecretStr("sk-test"),
        "org-test",
        api_base="https://api.devin.ai/v3",
        transport=_devin_transport(calls),
    )
    req = CreateSessionRequest(
        prompt="fix it",
        repos=["https://github.com/Hunter-1298/superset"],
        title="wi-1",
        tags=["hl", "wi-1"],
        max_acu_limit=5.0,
        structured_output_schema={"type": "object"},
        playbook_id="pb-1",
    )
    snap = client.create_session(req)
    sent = json.loads(calls[-1].content)
    assert calls[-1].url.path == "/v3/organizations/org-test/sessions"
    assert calls[-1].headers["authorization"] == "Bearer sk-test"
    assert sent["max_acu_limit"] == 5 and sent["playbook_id"] == "pb-1"
    assert sent["structured_output_required"] is True and sent["resumable"] is True
    assert "knowledge_ids" not in sent and "attachment_urls" not in sent
    assert snap.session_id == "devin-abc" and snap.status is DevinStatus.new
    assert snap.tags == ["hl", "wi-1"]

    done = client.get_session("devin-abc")
    assert done.is_done and done.status_detail is DevinStatusDetail.finished
    assert done.acus_consumed == 2.5 and done.pull_requests[0].pr_url.endswith("/pull/1")

    listed = client.list_sessions(tags=["wi-1"])
    assert [s.session_id for s in listed] == ["s1", "s2"]
    assert calls[-1].url.params["after"] == "c1"

    stopped = client.terminate_session("devin-abc")
    assert calls[-1].method == "DELETE"
    assert calls[-1].url.path == "/v3/organizations/org-test/sessions/devin-abc"
    assert calls[-1].url.params.get("archive") is None
    assert stopped.status is DevinStatus.exit and stopped.acus_consumed == 1.25
    with pytest.raises(DevinError, match="404"):
        client.terminate_session("devin-404")

    with pytest.raises(DevinError, match="SessionResponse"):
        client.get_session("devin-bad")
    with pytest.raises(DevinError, match="404") as exc:
        client.get_session("devin-404")
    assert "sk-test" not in str(exc.value)
    with pytest.raises(DevinError, match="org-"):
        DevinRest(SecretStr("k"), "not-an-org")


def test_devin_rest_retries_transient_then_gives_up() -> None:
    attempts: list[int] = []
    sleeps: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        return httpx.Response(503, json={"detail": "busy"})

    client = DevinRest(
        SecretStr("k"),
        "org-x",
        transport=httpx.MockTransport(handler),
        sleep=sleeps.append,
    )
    with pytest.raises(DevinError, match="503"):
        client.get_session("devin-abc")
    assert len(attempts) == 4 and sleeps == [1, 2, 4]


def test_github_rest_refuses_upstream_before_any_request() -> None:
    calls: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(
            201,
            json={
                "number": 7,
                "html_url": "u",
                "labels": [],
                "state": "open",
                "title": "t",
                "body": "",
            },
        )

    gh = GitHubRest(SecretStr("ghp_test"), transport=httpx.MockTransport(handler))
    with pytest.raises(GitHubError, match="refusing"):
        gh.create_issue(UPSTREAM_REPO, "t", "b", [])
    with pytest.raises(GitHubError, match="refusing"):
        gh.add_labels(UPSTREAM_REPO, 1, ["dispatch:approved"])
    with pytest.raises(GitHubError, match="refusing"):
        gh.comment_issue(UPSTREAM_REPO, 1, "hi")
    assert calls == []
    gh.create_issue(FORK_REPO, "t", "b", ["hl"])
    assert calls[0].url.path == f"/repos/{FORK_REPO}/issues"
    assert calls[0].headers["authorization"] == "Bearer ghp_test"


def test_orchestrator_cannot_point_at_upstream(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "u.sqlite3", fork_repo=UPSTREAM_REPO)
    engine = open_database(settings.database_path)
    with pytest.raises(PermissionError, match="allowlist"):
        Orchestrator(engine, FakeGitHub(main_head=BASELINE_SHA), FakeDevin(), settings)
    with pytest.raises(PermissionError, match="allowlist"):
        build_doubles_orchestrator(settings)


# ------------------------------------------------------------------------- replay stays sealed


def test_replay_database_serves_read_only_even_with_operator_flag(tmp_path: Path) -> None:
    """`--replay` + `--operator` cannot be combined: both builders refuse, and the app factory
    refuses an operator on a replay settings object."""
    settings = _settings(tmp_path / "r.sqlite3", replay_mode=True)
    engine = open_database(settings.database_path)
    ingest_synthetic(
        engine, SyntheticRun(source_sha=BASELINE_SHA, is_baseline=True).with_seeds("requests"), "x"
    )
    with pytest.raises(OperatorConfigError):
        build_doubles_orchestrator(settings)
    with pytest.raises(OperatorConfigError):
        build_live_orchestrator(settings)
    with TestClient(create_app(settings)) as c:
        assert c.post("/operator/launch/1", data={"confirm": "launch"}).status_code == 405
        assert c.get("/healthz").json()["replay_mode"] is True
