"""Committed Devin assets (five playbooks + knowledge), their idempotent sync through the v3
playbooks/knowledge resources, the `devin_assets` persistence the live orchestrator depends on, the
exported structured-output schemas, and the no-spend `doctor` preflight."""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import httpx
import pytest
from pydantic import SecretStr

from hardening_loop.cli import main
from hardening_loop.config import Settings
from hardening_loop.db import open_database
from hardening_loop.devin.assets import (
    AssetError,
    AssetSyncer,
    load_assets,
    persisted_assets,
)
from hardening_loop.devin.fake import FakeDevin, FakeDevinError
from hardening_loop.devin.protocol import NoteUpsert, PlaybookUpsert
from hardening_loop.devin.rest import DevinError, DevinRest
from hardening_loop.devin.schemas import export_schemas, schema_for
from hardening_loop.doctor import run_doctor
from hardening_loop.domain.enums import Kind
from hardening_loop.operator import OperatorConfigError, build_live_orchestrator

REPO_ROOT = Path(__file__).resolve().parents[1]


def _copy_assets(tmp_path: Path) -> Path:
    root = tmp_path / "repo"
    shutil.copytree(REPO_ROOT / "playbooks", root / "playbooks")
    shutil.copytree(REPO_ROOT / "knowledge", root / "knowledge")
    return root


def _settings(db: Path, **kw: Any) -> Settings:
    base: dict[str, Any] = {
        "data_dir": db.parent,
        "database_file": db.name,
        "repo_root": REPO_ROOT,
    }
    base.update(kw)
    return Settings(**base)


# ------------------------------------------------------------------------- committed bundle


def test_committed_bundle_covers_every_kind_with_matching_schema() -> None:
    bundle = load_assets(REPO_ROOT)
    assert set(bundle.playbooks) == set(Kind)
    for kind, spec in bundle.playbooks.items():
        assert spec.upsert.structured_output_schema == schema_for(kind)
        assert spec.upsert.macro and spec.upsert.macro.startswith("!hl-")
        body = spec.upsert.body
        assert "apache/superset" in body
        if kind is not Kind.scanner_disagreement:
            assert "Hunter-1298/superset" in body and "`main`" in body
        else:
            assert "Open no PR" in body
    assert len(bundle.knowledge) >= 1
    note = bundle.knowledge[0].upsert
    assert note.pinned_repo == "Hunter-1298/superset"
    assert "c83fb2bb1dcfac41ac51bcebd82471f4a7180d18" in note.body


def test_playbooks_forbid_the_forbidden_actions_in_prose() -> None:
    bundle = load_assets(REPO_ROOT)
    for kind, spec in bundle.playbooks.items():
        if kind is Kind.scanner_disagreement:
            continue
        text = spec.upsert.body.lower()
        assert "ignore" in text  # scanner ignore files are named and forbidden
        assert "never claim a test you did not run" in text
        assert "apache/superset" in text  # named so it can be forbidden


def test_content_sha_is_deterministic_and_tracks_body(tmp_path: Path) -> None:
    root = _copy_assets(tmp_path)
    a = load_assets(root).playbooks[Kind.dependency_upgrade]
    b = load_assets(root).playbooks[Kind.dependency_upgrade]
    assert a.content_sha256 == b.content_sha256
    a.path.write_text(a.path.read_text() + "\nextra line\n")
    c = load_assets(root).playbooks[Kind.dependency_upgrade]
    assert c.content_sha256 != a.content_sha256


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda p: p.unlink(), "no playbook for kinds"),
        (
            lambda p: p.write_text(
                p.read_text().replace(
                    "macro: !hl-dependency-upgrade", "macro: !hl-container-hardening", 1
                )
            ),
            "duplicate macros",
        ),
        (
            lambda p: p.write_text(p.read_text().replace("macro: !hl-", "macro: bad ", 1)),
            "macro",
        ),
        (lambda p: p.write_text("no front matter\n"), "front matter"),
        (
            lambda p: p.write_text(
                p.read_text().replace("kind: dependency_upgrade", "kind: nonsense", 1)
            ),
            "kind",
        ),
    ],
)
def test_bundle_validation_fails_closed(tmp_path: Path, mutation: Any, message: str) -> None:
    root = _copy_assets(tmp_path)
    mutation(root / "playbooks" / "pb-dependency-upgrade.md")
    with pytest.raises(AssetError, match=message):
        load_assets(root)


def test_exported_schemas_match_and_check_detects_drift(tmp_path: Path) -> None:
    assert export_schemas(REPO_ROOT / "playbooks" / "schemas", write=False) == []
    out = tmp_path / "schemas"
    assert sorted(export_schemas(out, write=True)) == sorted(
        f"{k.playbook_slug}.json" for k in Kind
    )
    assert export_schemas(out, write=False) == []
    (out / f"{Kind.helm_deploy_config.playbook_slug}.json").write_text("{}\n")
    assert export_schemas(out, write=False) == [f"{Kind.helm_deploy_config.playbook_slug}.json"]
    assert main(["schemas", "export", "--check", "--out", str(out)]) == 1
    assert main(["schemas", "export", "--out", str(out)]) == 0
    assert main(["schemas", "export", "--check", "--out", str(out)]) == 0
    for k in Kind:
        assert json.loads((out / f"{k.playbook_slug}.json").read_text()) == schema_for(k)


# ------------------------------------------------------------------------- sync (fake Devin)


def test_sync_creates_then_repeat_is_noop_then_update_on_local_change(tmp_path: Path) -> None:
    root = _copy_assets(tmp_path)
    engine = open_database(tmp_path / "db.sqlite3")
    devin = FakeDevin()
    bundle = load_assets(root)

    first = AssetSyncer(devin, engine, bundle).sync()
    assert first.writes == 6 and not first.noop
    assert {a.action for a in first.actions} == {"created"}
    assert len(devin.playbooks) == 5 and len(devin.notes) == 1

    second = AssetSyncer(devin, engine, bundle).sync()
    assert second.noop and second.writes == 0
    assert {a.action for a in second.actions} == {"unchanged"}
    assert second.playbook_ids() == first.playbook_ids()
    assert second.knowledge_ids() == first.knowledge_ids()
    assert len(devin.playbooks) == 5 and len(devin.notes) == 1

    state = persisted_assets(engine, bundle)
    assert state.ok
    assert set(state.playbook_ids) == set(Kind)
    assert state.knowledge_ids == first.knowledge_ids()

    pb = bundle.playbooks[Kind.helm_deploy_config].path
    pb.write_text(pb.read_text() + "\nOne more rule.\n")
    changed = load_assets(root)
    drift = persisted_assets(engine, changed)
    assert drift.drifted == ["playbook:pb-helm-security"] and not drift.ok

    third = AssetSyncer(devin, engine, changed).sync()
    assert third.writes == 1
    updated = [a for a in third.actions if a.action == "updated"]
    assert [a.slug for a in updated] == ["pb-helm-security"]
    assert updated[0].remote_id == first.playbook_ids()["pb-helm-security"]
    assert len(devin.playbooks) == 5
    assert persisted_assets(engine, changed).ok


def test_sync_adopts_existing_remote_by_title_instead_of_duplicating(tmp_path: Path) -> None:
    root = _copy_assets(tmp_path)
    engine = open_database(tmp_path / "db.sqlite3")
    devin = FakeDevin()
    bundle = load_assets(root)
    spec = bundle.playbooks[Kind.dependency_upgrade]
    stale = devin.create_playbook(
        PlaybookUpsert(title=spec.upsert.title, body="hand-written old body", macro="!old")
    )
    devin.create_note(NoteUpsert(name=bundle.knowledge[0].upsert.name, body="x", trigger="y"))

    report = AssetSyncer(devin, engine, bundle).sync()
    by_slug = {a.slug: a for a in report.actions}
    assert by_slug["pb-dependency-upgrade"].action == "updated"
    assert by_slug["pb-dependency-upgrade"].remote_id == stale.playbook_id
    assert by_slug[bundle.knowledge[0].slug].action == "updated"
    assert len(devin.playbooks) == 5 and len(devin.notes) == 1
    assert AssetSyncer(devin, engine, bundle).sync().noop


def test_sync_refuses_ambiguous_title_matches(tmp_path: Path) -> None:
    root = _copy_assets(tmp_path)
    engine = open_database(tmp_path / "db.sqlite3")
    devin = FakeDevin()
    bundle = load_assets(root)
    title = bundle.playbooks[Kind.dependency_upgrade].upsert.title
    devin.create_playbook(PlaybookUpsert(title=title, body="a", macro="!a"))
    devin.create_playbook(PlaybookUpsert(title=title, body="b", macro="!b"))
    with pytest.raises(AssetError, match="delete the extras"):
        AssetSyncer(devin, engine, bundle).sync()
    assert persisted_assets(engine, bundle).missing  # nothing persisted on failure


def test_sync_dry_run_writes_nothing(tmp_path: Path) -> None:
    root = _copy_assets(tmp_path)
    engine = open_database(tmp_path / "db.sqlite3")
    devin = FakeDevin()
    bundle = load_assets(root)
    report = AssetSyncer(devin, engine, bundle).sync(dry_run=True)
    assert report.dry_run and report.writes == 0
    assert {a.action for a in report.actions} == {"would_create"}
    assert not devin.playbooks and not devin.notes
    assert len(persisted_assets(engine, bundle).missing) == 6


def test_sync_failure_midway_persists_only_confirmed_assets(tmp_path: Path) -> None:
    root = _copy_assets(tmp_path)
    engine = open_database(tmp_path / "db.sqlite3")
    devin = FakeDevin()
    bundle = load_assets(root)
    devin.fail_next["create_note"] = FakeDevinError("503")
    with pytest.raises(FakeDevinError):
        AssetSyncer(devin, engine, bundle).sync()
    state = persisted_assets(engine, bundle)
    assert state.missing == [f"knowledge:{bundle.knowledge[0].slug}"]
    assert len(state.playbook_ids) == 5
    again = AssetSyncer(devin, engine, bundle).sync()
    assert again.writes == 1 and len(devin.playbooks) == 5
    assert persisted_assets(engine, bundle).ok


def test_live_orchestrator_refuses_missing_or_drifted_assets(tmp_path: Path) -> None:
    root = _copy_assets(tmp_path)
    db = tmp_path / "db.sqlite3"
    settings = _settings(
        db,
        repo_root=root,
        operator_mode=True,
        operator_login="Hunter-1298",
        github_token=SecretStr("t"),
        devin_api_key=SecretStr("k"),
    )
    with pytest.raises(OperatorConfigError, match="missing="):
        build_live_orchestrator(settings)
    engine = open_database(db)
    AssetSyncer(FakeDevin(), engine, load_assets(root)).sync()
    orch = build_live_orchestrator(settings, engine=engine)
    assert set(orch.playbook_ids) == set(Kind)
    assert len(orch.knowledge_ids) == 1
    pb = root / "playbooks" / "pb-no-fix-openvex.md"
    pb.write_text(pb.read_text() + "\nchanged\n")
    with pytest.raises(OperatorConfigError, match="drifted=\\['playbook:pb-no-fix-openvex'\\]"):
        build_live_orchestrator(settings, engine=engine)


# ------------------------------------------------------------------------- CLI


def test_assets_sync_cli_with_doubles_and_expect_noop(tmp_path: Path, capsys: Any) -> None:
    db = tmp_path / "cli.sqlite3"
    assert main(["assets", "sync", "--db", str(db), "--doubles"]) == 0
    out = capsys.readouterr().out
    assert out.count("created ") == 6 and "6 write(s)" in out
    store = db.with_name("fake-devin-assets.json")
    assert store.exists()
    assert main(["assets", "sync", "--db", str(db), "--doubles", "--expect-noop"]) == 0
    out = capsys.readouterr().out
    assert out.count("unchanged ") == 6 and "0 write(s); no-op" in out
    assert main(["assets", "sync", "--db", str(db), "--doubles", "--dry-run"]) == 0
    assert "(dry run)" in capsys.readouterr().out
    # an empty double (no store) cannot honour --expect-noop: it re-creates and says so
    store.unlink()
    assert main(["assets", "sync", "--db", str(db), "--doubles", "--expect-noop"]) == 1
    assert "--expect-noop" in capsys.readouterr().err


def test_assets_sync_cli_requires_key_without_doubles(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any
) -> None:
    monkeypatch.delenv("HL_DEVIN_API_KEY", raising=False)
    assert main(["assets", "sync", "--db", str(tmp_path / "x.sqlite3")]) == 2
    assert "HL_DEVIN_API_KEY" in capsys.readouterr().err


# ------------------------------------------------------------------------- REST contract


def _rest(handler: Any) -> tuple[DevinRest, list[httpx.Request]]:
    calls: list[httpx.Request] = []

    def wrapped(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        resp = handler(request)
        assert isinstance(resp, httpx.Response)
        return resp

    return (
        DevinRest(
            SecretStr("sk-secret"),
            "org-test",
            transport=httpx.MockTransport(wrapped),
            sleep=lambda _s: None,
        ),
        calls,
    )


def _pb(pid: str, title: str) -> dict[str, Any]:
    return {
        "playbook_id": pid,
        "title": title,
        "body": "b",
        "macro": None,
        "structured_output_schema": None,
        "created_at": "2026-09-07T00:00:00Z",
        "unknown_future_field": 1,
    }


def test_rest_playbooks_paginate_and_upsert() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer sk-secret"
        if request.method == "GET":
            assert request.url.path == "/v3/organizations/org-test/playbooks"
            if request.url.params.get("after") == "c1":
                return httpx.Response(200, json={"items": [_pb("p2", "B")], "has_next_page": False})
            return httpx.Response(
                200,
                json={"items": [_pb("p1", "A")], "has_next_page": True, "end_cursor": "c1"},
            )
        if request.method == "POST":
            body = json.loads(request.content)
            assert body["title"] == "C" and body["macro"] == "!c"
            return httpx.Response(201, json=_pb("p3", "C"))
        assert request.method == "PUT"
        assert request.url.path == "/v3/organizations/org-test/playbooks/p1"
        return httpx.Response(200, json=_pb("p1", "A2"))

    client, calls = _rest(handler)
    listed = client.list_playbooks()
    assert [p.playbook_id for p in listed] == ["p1", "p2"]
    created = client.create_playbook(PlaybookUpsert(title="C", body="b", macro="!c"))
    assert created.playbook_id == "p3"
    updated = client.update_playbook("p1", PlaybookUpsert(title="A2", body="b"))
    assert updated.title == "A2"
    assert [c.method for c in calls] == ["GET", "GET", "POST", "PUT"]


def test_rest_notes_and_bad_shapes() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.method == "GET":
            return httpx.Response(
                200,
                json={
                    "items": [
                        {
                            "note_id": "n1",
                            "name": "N",
                            "body": "b",
                            "trigger": "t",
                            "pinned_repo": "Hunter-1298/superset",
                            "is_enabled": True,
                        }
                    ],
                    "has_next_page": False,
                },
            )
        if request.method == "POST":
            return httpx.Response(201, json={"not": "a note"})
        return httpx.Response(
            200, json={"note_id": "n1", "name": "N2", "body": "b", "trigger": "t"}
        )

    client, _ = _rest(handler)
    notes = client.list_notes()
    assert notes[0].note_id == "n1" and notes[0].pinned_repo == "Hunter-1298/superset"
    with pytest.raises(DevinError, match="NoteRecord"):
        client.create_note(NoteUpsert(name="N", body="b", trigger="t"))
    assert client.update_note("n1", NoteUpsert(name="N2", body="b", trigger="t")).name == "N2"


def test_rest_pagination_bound() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"items": [], "has_next_page": True, "end_cursor": "x"})

    client, _ = _rest(handler)
    with pytest.raises(DevinError, match="more than"):
        client.list_playbooks()


# ------------------------------------------------------------------------- doctor


def _names(report: Any, level: str) -> set[str]:
    return {c.name for c in report.checks if c.level == level}


def test_doctor_without_database_is_advisory(tmp_path: Path) -> None:
    s = _settings(
        tmp_path / "none.sqlite3", github_token=None, devin_api_key=None, operator_login=None
    )
    r = run_doctor(s)
    assert r.ok
    assert {"HL_GITHUB_TOKEN", "HL_DEVIN_API_KEY", "HL_OPERATOR_LOGIN", "database"} <= _names(
        r, "warn"
    )
    assert "baseline fixtures" in _names(r, "ok")
    rendered = r.render()
    assert "all checks passed" in rendered
    live = run_doctor(s, live=True)
    assert not live.ok
    assert {"HL_GITHUB_TOKEN", "HL_DEVIN_API_KEY", "HL_OPERATOR_LOGIN", "database"} <= _names(
        live, "fail"
    )


def test_doctor_never_prints_secret_values(tmp_path: Path) -> None:
    s = _settings(
        tmp_path / "x.sqlite3",
        github_token=SecretStr("ghp_ABCDEFsecret"),
        devin_api_key=SecretStr("dv_XYZsecret"),
    )
    text = run_doctor(s).render() + json.dumps(run_doctor(s).to_dict())
    assert "ghp_" not in text and "XYZsecret" not in text
    assert "HL_GITHUB_TOKEN" in text and " set" in text


def test_doctor_live_profile_enforced(tmp_path: Path) -> None:
    db = tmp_path / "live.sqlite3"
    engine = open_database(db)
    AssetSyncer(FakeDevin(), engine, load_assets(REPO_ROOT)).sync()
    common: dict[str, Any] = {
        "github_token": SecretStr("t"),
        "devin_api_key": SecretStr("k"),
        "operator_login": "Hunter-1298",
        "auto_dispatch": False,
        "max_concurrent_sessions": 1,
        "global_acu_budget": 5.0,
    }
    good = run_doctor(_settings(db, **common), live=True)
    assert good.ok, good.render()
    assert "devin assets synced" in _names(good, "ok")

    for bad in (
        {"operator_login": "someone-else"},
        {"auto_dispatch": True},
        {"max_concurrent_sessions": 2},
        {"global_acu_budget": 6.0},
        {"replay_mode": True},
    ):
        r = run_doctor(_settings(db, **{**common, **bad}), live=True)
        assert not r.ok, bad
    # same settings, not live: those are only advisories or fine
    assert run_doctor(_settings(db, **{**common, "max_concurrent_sessions": 2})).ok


def test_doctor_flags_unsynced_assets_and_schema_mismatch(tmp_path: Path) -> None:
    db = tmp_path / "d.sqlite3"
    open_database(db)
    s = _settings(db, github_token=SecretStr("t"), devin_api_key=SecretStr("k"))
    r = run_doctor(s)
    assert r.ok and "devin assets synced" in _names(r, "warn")
    assert "devin assets synced" in _names(run_doctor(s, live=True), "fail")

    import sqlite3

    with sqlite3.connect(db) as raw:
        raw.execute("INSERT INTO schema_version (version, applied_at) VALUES (99, '2026-01-01')")
    broken = run_doctor(s)
    assert not broken.ok and "database" in _names(broken, "fail")


def test_doctor_cli_json_and_exit_codes(tmp_path: Path, capsys: Any) -> None:
    db = tmp_path / "c.sqlite3"
    assert main(["doctor", "--db", str(db), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["ok"] is True and data["live"] is False
    assert {c["name"] for c in data["checks"]} >= {"HL_GITHUB_TOKEN", "baseline fixtures"}
    rc = main(["doctor", "--db", str(db), "--live"])
    out = capsys.readouterr().out
    assert rc == 1 and "doctor: FAILED" in out
