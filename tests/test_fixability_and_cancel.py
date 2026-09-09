"""Fixability-first ordering and the operator "Stop Devin" route.

Ordering: a launchable dependency upgrade outranks a Critical no-fix assessment; blocked items
sink below launchable ones; lifecycle stage still groups a mixed list. Cancel: only an item whose
Devin session is still working and has no recorded PR can be stopped; the remote termination
happens before any local state changes; a remote failure leaves the reservation intact and is
reported as a failure, never as success. Everything runs against the in-memory doubles."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlmodel import col, select

from hardening_loop.config import Settings
from hardening_loop.dashboard import labels
from hardening_loop.dashboard.app import create_app
from hardening_loop.db import session_scope
from hardening_loop.devin.enums import DevinStatus, DevinStatusDetail
from hardening_loop.devin.fake import FakeDevin, FakeDevinError
from hardening_loop.devin.protocol import CreateSessionRequest
from hardening_loop.domain.enums import Kind, WorkItemState
from hardening_loop.github.fake import FakeGitHub
from hardening_loop.models.tables import Event, Session, SessionPoll, WorkItem
from hardening_loop.operator import OperatorContext, build_doubles_orchestrator
from hardening_loop.orchestrator.engine import Orchestrator
from hardening_loop.orchestrator.launch import CancelBlock, LaunchBlock, cancel_block_for

REPO_ROOT = Path(__file__).resolve().parents[1]
LOGIN = "operator-test"
World = tuple[Settings, Orchestrator, OperatorContext]


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
def world(tmp_path: Path) -> World:
    settings = _settings(tmp_path / "op.sqlite3")
    orch = build_doubles_orchestrator(settings)
    return settings, orch, OperatorContext.for_doubles(orch, login=LOGIN)


@pytest.fixture
def client(world: World) -> Iterator[TestClient]:
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


def _gh(orch: Orchestrator) -> FakeGitHub:
    assert isinstance(orch.gh, FakeGitHub)
    return orch.gh


def _launch(client: TestClient, ctx: OperatorContext, wi_id: int | None) -> httpx.Response:
    r: httpx.Response = client.post(
        f"/operator/launch/{wi_id}", data={"csrf": ctx.csrf_token, "confirm": "launch"}
    )
    return r


def _stop(client: TestClient, ctx: OperatorContext, wi_id: int | None, **kw: Any) -> httpx.Response:
    data = {"csrf": ctx.csrf_token, "confirm": "stop"}
    data.update(kw.pop("data", {}))
    r: httpx.Response = client.post(f"/operator/cancel/{wi_id}", data=data, **kw)
    return r


def _events(orch: Orchestrator, wi_id: int | None) -> list[Event]:
    with session_scope(orch.engine) as db:
        rows = db.exec(
            select(Event)
            .where(Event.entity_type == "work_item", Event.entity_id == wi_id)
            .order_by(col(Event.id))
        ).all()
        for row in rows:
            db.refresh(row)
        db.expunge_all()
    return list(rows)


def _launched_active(client: TestClient, world: World, key: str = "pypi:cryptography") -> WorkItem:
    _, orch, ctx = world
    wi = _items(orch)[key]
    assert _launch(client, ctx, wi.id).status_code == 200
    active = _items(orch)[key]
    assert active.state is WorkItemState.session_active and active.active_session_id
    return active


# ------------------------------------------------------------------------- fixability ranking


def test_fixability_of_every_kind_and_of_its_stored_forms() -> None:
    assert labels.fixability_of(Kind.dependency_upgrade) is labels.Fixability.upgrade
    assert labels.fixability_of(Kind.container_hardening) is labels.Fixability.hardening
    assert labels.fixability_of(Kind.helm_deploy_config) is labels.Fixability.hardening
    assert labels.fixability_of(Kind.no_fix_reachability) is labels.Fixability.assessment
    assert labels.fixability_of(Kind.scanner_disagreement) is labels.Fixability.triage
    # the enum arrives from Jinja/SQL as its number or its name
    assert labels.fixability_of("1") is labels.Fixability.upgrade
    assert labels.fixability_of("no_fix_reachability") is labels.Fixability.assessment
    assert labels.fixability_of("nonsense") is labels.Fixability.triage
    assert labels.fixability_of(None) is labels.Fixability.triage
    assert labels.parse_fixability("upgrade") is labels.Fixability.upgrade
    assert labels.parse_fixability("Fix available") is None
    assert labels.parse_fixability(None) is None
    for fix in labels.Fixability:
        kinds = labels.kinds_for_fixability(fix)
        assert kinds and all(labels.fixability_of(k) is fix for k in kinds)
    assert {k for f in labels.Fixability for k in labels.kinds_for_fixability(f)} == set(Kind)


def test_fixability_labels_read_like_english() -> None:
    texts = {f: labels.fixability(f).text for f in labels.Fixability}
    assert texts == {
        labels.Fixability.upgrade: "Fix available",
        labels.Fixability.hardening: "Config change",
        labels.Fixability.assessment: "No fix yet",
        labels.Fixability.triage: "Needs triage",
    }
    assert labels.fixability(Kind.no_fix_reachability).text == "No fix yet"
    assert labels.fixability("hardening").text == "Config change"
    for lab in (labels.fixability(f) for f in labels.Fixability):
        assert lab.hint and not re.search(r"[a-z]_[a-z]", lab.text)


def test_sort_key_prefers_launchable_upgrades_over_critical_no_fix() -> None:
    key = labels.work_item_sort_key
    ready = WorkItemState.queued
    critical, high, medium = 4, 3, 2
    launchable_high_upgrade = key(ready, Kind.dependency_upgrade, high, 10, True)
    critical_no_fix = key(ready, Kind.no_fix_reachability, critical, 1, True)
    blocked_critical_upgrade = key(ready, Kind.dependency_upgrade, critical, 2, False)
    medium_upgrade = key(ready, Kind.dependency_upgrade, medium, 3, True)
    hardening = key(ready, Kind.container_hardening, critical, 4, True)
    triage = key(ready, Kind.scanner_disagreement, critical, 5, True)
    unknown_preview = key(ready, Kind.dependency_upgrade, high, 6, None)
    assert launchable_high_upgrade < medium_upgrade < hardening < critical_no_fix < triage
    assert critical_no_fix < blocked_critical_upgrade  # blocked sinks below every launchable
    assert unknown_preview == key(ready, Kind.dependency_upgrade, high, 6, True)
    # lifecycle stage still comes first; fixability only splits the ready stage
    working = key(WorkItemState.session_active, Kind.no_fix_reachability, medium, 99, False)
    in_ci = key(WorkItemState.checks_running, Kind.dependency_upgrade, critical, 98, True)
    verified = key(WorkItemState.verified, Kind.dependency_upgrade, critical, 97, True)
    assert working < in_ci < launchable_high_upgrade < verified
    assert key(WorkItemState.pr_open, Kind.no_fix_reachability, medium, 1, False) == key(
        WorkItemState.pr_open, Kind.no_fix_reachability, medium, 1, True
    )
    assert labels.fixability_rank(Kind.dependency_upgrade, False) == (1, 0)
    assert labels.fixability_rank(Kind.scanner_disagreement, True) == (0, 3)


def _ids_in_order(html: str, prefix: str) -> list[int]:
    return [int(m) for m in re.findall(rf'href="{prefix}(\d+)"', html)]


def test_work_items_list_puts_launchable_upgrades_first(client: TestClient, world: World) -> None:
    _, orch, ctx = world
    items = _items(orch)
    by_key = {k: w.id for k, w in items.items()}
    assert ctx.preview(by_key["container:dockerfile"] or 0).block is LaunchBlock.over_budget
    assert ctx.preview(by_key["nofix:pypi:paramiko"] or 0).block is None
    html = client.get("/issues?stage=ready").text
    order = _ids_in_order(html, "/issues/")
    seen: list[int] = []
    for i in order:
        if i not in seen:
            seen.append(i)
    expected = [
        by_key["pypi:pillow"],  # Fix available · Critical
        by_key["pypi:cryptography"],  # Fix available · High
        by_key["pypi:requests"],  # Fix available · Medium
        by_key["deploy:helm"],  # Config change, within budget
        by_key["nofix:pypi:paramiko"],  # No fix yet
        by_key["disagreement:deb:linux-libc-dev"],  # Needs triage
        by_key["container:dockerfile"],  # Config change, over budget
        by_key["container:os-packages"],  # Config change, over budget
    ]
    assert seen == expected
    assert "most fixable first" in _text(client.get("/issues"))
    for text in ("Fix available", "Config change", "No fix yet", "Needs triage"):
        assert text in html

    # the overview's "Fix next" list follows the same order and counts the launchable items
    over = client.get("/").text
    top = _ids_in_order(over[over.index("Fix next") :], "/issues/")
    first = [i for n, i in enumerate(top) if i not in top[:n]]
    assert first[:3] == expected[:3]
    assert first.index(by_key["nofix:pypi:paramiko"] or -1) > first.index(
        by_key["deploy:helm"] or -1
    )
    assert "6 of 8 can be launched right now; those come first." in _text(client.get("/"))
    dockerfile = by_key["container:dockerfile"]
    assert f'href="/operator/launch/{dockerfile}">Launch blocked · Over ACU budget' in html
    assert f'class="btn btn-launch btn-sm" href="/operator/launch/{dockerfile}"' not in html
    assert f'class="btn btn-launch btn-sm" href="/operator/launch/{expected[0]}"' in html


def test_fixability_filter_is_server_side_and_validated(client: TestClient, world: World) -> None:
    _, orch, _ = world
    items = _items(orch)
    r = client.get("/issues?fix=upgrade")
    assert r.status_code == 200
    ids = set(_ids_in_order(r.text, "/issues/"))
    assert ids == {w.id for w in items.values() if w.kind is Kind.dependency_upgrade}
    r = client.get("/issues?fix=assessment")
    assert set(_ids_in_order(r.text, "/issues/")) == {items["nofix:pypi:paramiko"].id}
    assert "No fix yet" in _text(r)
    assert client.get("/issues?fix=critical").status_code == 422
    hardening = client.get("/issues?fix=hardening&stage=ready")
    assert set(_ids_in_order(hardening.text, "/issues/")) == {
        items["container:dockerfile"].id,
        items["container:os-packages"].id,
        items["deploy:helm"].id,
    }


def test_issue_page_shows_fixability_next_to_the_stage(client: TestClient, world: World) -> None:
    _, orch, _ = world
    items = _items(orch)
    assert "No fix yet" in _text(client.get(f"/issues/{items['nofix:pypi:paramiko'].id}"))
    assert "Fix available" in _text(client.get(f"/issues/{items['pypi:pillow'].id}"))
    assert "Needs triage" in _text(
        client.get(f"/issues/{items['disagreement:deb:linux-libc-dev'].id}")
    )


# ------------------------------------------------------------------------- cancel eligibility


def test_cancel_preview_is_only_offered_to_a_working_session(
    client: TestClient, world: World
) -> None:
    _, orch, ctx = world
    queued = _items(orch)["pypi:pillow"]
    pv = ctx.cancel_preview(queued.id or 0)
    assert pv.block is CancelBlock.not_active and not pv.eligible
    assert client.get(f"/operator/cancel/{queued.id}").status_code == 200
    assert "Only an item whose Devin session is still working" in _text(
        client.get(f"/operator/cancel/{queued.id}")
    )
    assert f'href="/operator/cancel/{queued.id}"' not in client.get("/").text
    assert f'href="/operator/cancel/{queued.id}"' not in client.get(f"/issues/{queued.id}").text
    assert client.get("/operator/cancel/9999").status_code == 404

    active = _launched_active(client, world)
    pv = ctx.cancel_preview(active.id or 0)
    assert pv.eligible and pv.session_id == active.active_session_id and pv.acu_cap == 5
    page = client.get(f"/issues/{active.id}")
    assert f'href="/operator/cancel/{active.id}"' in page.text and "Stop Devin" in page.text
    assert "Devin is already working on this item" in _text(page)
    for path in ("/", "/issues", "/issues?stage=devin"):
        assert f'href="/operator/cancel/{active.id}"' in client.get(path).text, path
    confirm = client.get(f"/operator/cancel/{active.id}")
    assert confirm.status_code == 200
    body = _text(confirm)
    assert "cannot be resumed" in body and "relaunched later with a fresh session" in body
    assert f'name="csrf" value="{ctx.csrf_token}"' in confirm.text
    assert 'name="confirm" value="stop"' in confirm.text
    assert f'action="/operator/cancel/{active.id}"' in confirm.text


@pytest.mark.parametrize(
    ("form", "headers", "status"),
    [
        ({"confirm": "stop", "csrf": ""}, {}, 403),
        ({"confirm": "stop", "csrf": "wrong"}, {}, 403),
        ({}, {}, 400),
        ({"confirm": "launch"}, {}, 400),
        ({"confirm": "stop"}, {"sec-fetch-site": "cross-site"}, 403),
        ({"confirm": "stop"}, {"origin": "https://attacker.invalid"}, 403),
        ({"confirm": "stop"}, {"origin": "null"}, 403),
    ],
)
def test_cancel_post_rejections_touch_nothing(
    client: TestClient,
    world: World,
    form: dict[str, str],
    headers: dict[str, str],
    status: int,
) -> None:
    _, orch, ctx = world
    active = _launched_active(client, world)
    data = {"csrf": ctx.csrf_token, **form}
    if data["csrf"] == "":
        del data["csrf"]
    r = client.post(f"/operator/cancel/{active.id}", data=data, headers=headers)
    assert r.status_code == status
    after = _items(orch)["pypi:cryptography"]
    assert after.state is WorkItemState.session_active
    assert after.active_session_id == active.active_session_id
    fake = _devin(orch)
    assert fake.sessions[active.active_session_id or ""].status is not DevinStatus.exit
    assert ("terminate_session", active.active_session_id) not in fake.calls
    assert not any(e.event.startswith("operator_cancel") for e in _events(orch, active.id))


def test_cancel_post_requires_form_encoding(client: TestClient, world: World) -> None:
    _, orch, ctx = world
    active = _launched_active(client, world)
    r = client.post(
        f"/operator/cancel/{active.id}", json={"csrf": ctx.csrf_token, "confirm": "stop"}
    )
    assert r.status_code == 415
    assert _items(orch)["pypi:cryptography"].state is WorkItemState.session_active


# ------------------------------------------------------------------------- cancel outcomes


def test_successful_cancel_terminates_remotely_then_releases_the_slot(
    client: TestClient, world: World
) -> None:
    settings, orch, ctx = world
    active = _launched_active(client, world)
    sid = active.active_session_id or ""
    fake = _devin(orch)
    fake.set_state(sid, DevinStatus.running, DevinStatusDetail.working, acus=1.5)
    before_calls = len(fake.calls)
    assert ctx.preview(_items(orch)["pypi:requests"].id or 0).block is None
    settings.max_concurrent_sessions = 1
    assert ctx.preview(_items(orch)["pypi:requests"].id or 0).block is LaunchBlock.at_capacity

    r = _stop(client, ctx, active.id, headers={"sec-fetch-site": "same-origin"})
    assert r.status_code == 200
    body = _text(r)
    assert "Session terminated." in body and "1.50 ACU used" in body
    assert "relaunch it whenever you are ready" in body

    assert fake.calls[before_calls:] == [("terminate_session", sid)]
    assert fake.sessions[sid].status is DevinStatus.exit
    after = _items(orch)["pypi:cryptography"]
    assert after.state is WorkItemState.needs_human
    assert after.blocked_reason and after.blocked_reason.startswith("operator_cancelled:")
    assert LOGIN in after.blocked_reason and "1.50 ACU" in after.blocked_reason
    assert after.active_session_id == sid  # kept for the audit trail; never re-adopted
    # the slot and the budget reservation are free again
    assert ctx.preview(_items(orch)["pypi:requests"].id or 0).block is None

    with session_scope(orch.engine) as db:
        row = db.exec(select(Session).where(Session.devin_id == sid)).one()
        assert row.status == "exit" and row.acus_consumed == 1.5
        assert row.finished_at is not None and row.last_polled_at is not None
        polls = db.exec(select(SessionPoll).where(SessionPoll.session_id == row.id)).all()
        assert any(p.decision == "terminated" and LOGIN in p.reason for p in polls)
    names = [e.event for e in _events(orch, active.id)]
    assert "operator_cancelled" in names and "operator_cancel_failed" not in names
    ev = next(e for e in _events(orch, active.id) if e.event == "operator_cancelled")
    assert ev.actor == "operator" and LOGIN in (ev.reason or "")
    assert active.issue_number is not None
    issue = _gh(orch).issues[active.issue_number]
    assert any("stopped" in c and LOGIN in c for c in issue.comments)

    # the dashboard now says so, and offers a relaunch rather than a stop
    page = client.get(f"/issues/{active.id}")
    assert f'href="/operator/cancel/{active.id}"' not in page.text
    assert "Relaunch Devin" in page.text
    assert "stopped" in _text(page).lower()
    # a second stop is a no-op refusal, not a second termination
    again = _stop(client, ctx, active.id)
    assert again.status_code == 409
    assert fake.calls[before_calls:] == [("terminate_session", sid)]
    assert "operator_cancel_refused" in [e.event for e in _events(orch, active.id)]


def test_relaunch_after_cancel_creates_a_fresh_session(client: TestClient, world: World) -> None:
    _, orch, ctx = world
    active = _launched_active(client, world)
    sid = active.active_session_id
    assert _stop(client, ctx, active.id).status_code == 200
    fake = _devin(orch)
    assert len(fake.created_requests()) == 1
    r = _launch(client, ctx, active.id)
    assert r.status_code == 200
    again = _items(orch)["pypi:cryptography"]
    assert again.state is WorkItemState.session_active
    assert again.active_session_id and again.active_session_id != sid
    assert len(fake.created_requests()) == 2
    assert fake.sessions[sid or ""].status is DevinStatus.exit  # the old one stays terminated
    with session_scope(orch.engine) as db:
        rows = db.exec(select(Session).where(Session.work_item_id == active.id)).all()
        assert {r.devin_id for r in rows} == {sid, again.active_session_id}
    # ...and the fresh session can be stopped too
    assert ctx.cancel_preview(active.id or 0).eligible


def test_remote_failure_is_reported_and_changes_nothing(client: TestClient, world: World) -> None:
    _, orch, ctx = world
    active = _launched_active(client, world)
    sid = active.active_session_id or ""
    fake = _devin(orch)
    fake.fail_next["terminate_session"] = RuntimeError("devin 503")
    r = _stop(client, ctx, active.id)
    assert r.status_code == 502
    body = _text(r)
    assert "Stop failed" in body and "devin 503" in body
    assert "The session may still be running; the work item was not changed." in body
    assert "Session terminated." not in body
    after = _items(orch)["pypi:cryptography"]
    assert after.state is WorkItemState.session_active and after.active_session_id == sid
    assert fake.sessions[sid].status is not DevinStatus.exit
    names = [e.event for e in _events(orch, active.id)]
    assert "operator_cancel_failed" in names and "operator_cancelled" not in names
    with session_scope(orch.engine) as db:
        row = db.exec(select(Session).where(Session.devin_id == sid)).one()
        assert row.status != "exit" and row.finished_at is None
        assert not db.exec(
            select(SessionPoll).where(
                SessionPoll.session_id == row.id, SessionPoll.decision == "terminated"
            )
        ).all()
    # the item is still stoppable once Devin answers again
    assert ctx.cancel_preview(active.id or 0).eligible
    assert _stop(client, ctx, active.id).status_code == 200
    assert _items(orch)["pypi:cryptography"].state is WorkItemState.needs_human


def test_already_exited_session_cannot_be_terminated_twice(world: World) -> None:
    _, orch, _ = world
    fake = _devin(orch)
    snap = fake.create_session(
        CreateSessionRequest(
            prompt="p",
            repos=[],
            title="t",
            tags=["hl"],
            max_acu_limit=1.0,
            structured_output_schema={"type": "object"},
        )
    )
    fake.set_state(snap.session_id, DevinStatus.exit, DevinStatusDetail.finished, acus=0.5)
    with pytest.raises(FakeDevinError, match="already exited"):
        fake.terminate_session(snap.session_id)
    with pytest.raises(KeyError):
        fake.terminate_session("devin-nope")


def test_cancel_is_refused_once_a_pr_is_recorded(client: TestClient, world: World) -> None:
    _, orch, ctx = world
    active = _launched_active(client, world)
    sid = active.active_session_id or ""
    fake = _devin(orch)
    url = _gh(orch).open_pr(
        title="fix: cryptography",
        head_ref="devin/1-dep",
        head_sha="a" * 40,
        files=["pyproject.toml", "requirements/base.txt"],
    )
    fake.finish(
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
    ctx.tick()
    after = _items(orch)["pypi:cryptography"]
    assert after.pr_number is not None and url.endswith(f"/pull/{after.pr_number}")
    assert after.state is WorkItemState.checks_running
    pv = ctx.cancel_preview(active.id or 0)
    assert not pv.eligible and pv.block in (CancelBlock.not_active, CancelBlock.pr_recorded)
    page = client.get(f"/issues/{active.id}")
    assert f'href="/operator/cancel/{active.id}"' not in page.text
    calls_before = len(fake.calls)
    r = _stop(client, ctx, active.id)
    assert r.status_code == 409
    assert len(fake.calls) == calls_before
    assert _items(orch)["pypi:cryptography"].state is after.state


def test_cancel_block_for_matrix() -> None:
    a = WorkItemState.session_active
    assert cancel_block_for(a, has_session=True, has_pr=False) is None
    assert cancel_block_for(a, has_session=False, has_pr=False) is CancelBlock.no_session
    assert cancel_block_for(a, has_session=True, has_pr=True) is CancelBlock.pr_recorded
    for st in WorkItemState:
        if st is a:
            continue
        assert cancel_block_for(st, has_session=True, has_pr=False) is CancelBlock.not_active
