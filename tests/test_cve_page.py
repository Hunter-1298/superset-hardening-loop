"""The CVE detail page (`/findings/{id}`) and the raw-record normaliser behind it, on both the
committed 6.1.0 baseline fixture (real Trivy/Grype records) and the replay `DEMO` database
(synthetic records plus a full remediation lifecycle)."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import Engine
from sqlmodel import select

from hardening_loop.config import BASELINE_SHA, Settings
from hardening_loop.dashboard.app import create_app
from hardening_loop.dashboard.vuln import vuln_detail
from hardening_loop.db import open_database, session_scope
from hardening_loop.domain.enums import ScanMode
from hardening_loop.ingest.evidence import load_baseline
from hardening_loop.ingest.persist import ingest_baseline
from hardening_loop.models.tables import Finding, Sighting, WorkItem
from hardening_loop.replay.runner import run_scenario

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE = REPO_ROOT / "fixtures" / "baseline" / BASELINE_SHA


def _text(html: str) -> str:
    if "<main" in html:
        html = html[html.index("<main") :]
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))


# ------------------------------------------------------------------------- real baseline evidence


@pytest.fixture(scope="module")
def baseline_engine(tmp_path_factory: pytest.TempPathFactory) -> Engine:
    db = tmp_path_factory.mktemp("baseline") / "baseline.sqlite3"
    engine = open_database(db)
    ingest_baseline(engine, load_baseline(FIXTURE))
    return engine


@pytest.fixture(scope="module")
def baseline_client(baseline_engine: Engine) -> Iterator[TestClient]:
    db = Path(baseline_engine.url.database or "")
    settings = Settings(data_dir=db.parent, database_file=db.name, repo_root=REPO_ROOT)
    with TestClient(create_app(settings, engine=baseline_engine)) as c:
        yield c


def _records(
    engine: Engine, vuln_id: str, pkg: str
) -> tuple[Finding, dict[str, dict[str, Any] | None]]:
    with session_scope(engine) as db:
        f = db.exec(
            select(Finding).where(Finding.vuln_id == vuln_id, Finding.pkg_name == pkg)
        ).first()
        assert f is not None, (vuln_id, pkg)
        rows = db.exec(
            select(Sighting).where(Sighting.finding_id == f.id, Sighting.mode == ScanMode.raw)
        ).all()
        records = {s.scanner.value: s.record for s in rows}
        db.expunge_all()
    return f, records


def test_vuln_detail_merges_real_trivy_and_grype_records(baseline_engine: Engine) -> None:
    f, records = _records(baseline_engine, "CVE-2026-10536", "curl")
    assert set(records) == {"trivy", "grype"}
    d = vuln_detail(records)
    assert d.synthetic is False
    assert d.title and "curl" in d.title.lower()
    assert d.description and len(d.description) > 40
    assert "CWE-416" in d.cwes
    assert d.published and d.modified and d.published[:4].isdigit()
    assert d.epss is not None and 0 < d.epss.score < 1 and d.epss.percentile is not None
    versions = {c.version for c in d.cvss}
    assert versions & {"3.1", "4.0"}
    best = d.best_cvss
    assert best is not None and best.base_score is not None and best.vector
    assert best.vector.startswith("CVSS:")
    assert any(c.exploitability_score is not None for c in d.cvss)
    assert d.primary_url and d.primary_url.startswith("http")
    assert len(d.references) >= 3 and all(r.scanners for r in d.references)
    by_scanner = {s.scanner: s for s in d.scanners}
    assert set(by_scanner) == {"trivy", "grype"}
    assert by_scanner["trivy"].severity != by_scanner["grype"].severity  # real disagreement
    assert by_scanner["grype"].data_source and by_scanner["grype"].fix_state == "wont-fix"
    assert by_scanner["grype"].risk is not None
    assert by_scanner["trivy"].data_source == "Debian Security Tracker"
    assert by_scanner["trivy"].data_source_url and by_scanner["trivy"].data_source_url.startswith(
        "https://"
    )
    assert by_scanner["grype"].data_source_url == by_scanner["grype"].data_source
    assert by_scanner["trivy"].layer_id
    assert by_scanner["trivy"].fingerprint  # Trivy's per-match fingerprint survives
    assert by_scanner["grype"].purl and by_scanner["grype"].purl.startswith("pkg:deb/")
    assert f.severity_by_scanner and f.fix_versions_by_scanner is not None


def test_vuln_detail_tolerates_partial_or_missing_records() -> None:
    assert vuln_detail({}).description is None
    assert vuln_detail({"trivy": None, "grype": None}).scanners == ()
    only = vuln_detail({"grype": {"vulnerability": {"id": "X", "severity": "High"}}})
    assert [s.scanner for s in only.scanners] == ["grype"]
    assert only.scanners[0].severity == "High"
    synthetic = vuln_detail({"trivy": {"synthetic": True, "scanner": "trivy", "id": "CVE-1"}})
    assert synthetic.synthetic is True and synthetic.description is None


def test_cve_page_renders_real_evidence(
    baseline_client: TestClient, baseline_engine: Engine
) -> None:
    f, _ = _records(baseline_engine, "CVE-2026-10536", "curl")
    r = baseline_client.get(f"/findings/{f.id}")
    assert r.status_code == 200
    html = r.text
    body = _text(html)
    assert "CVE-2026-10536" in body and "curl" in body and "8.14.1" in body
    for heading in (
        "Description",
        "CVSS",
        "Scanner evidence",
        "References",
        "Package",
        "Sighting history",
    ):
        assert heading in body, heading
    assert "CWE-416" in body and "EPSS" in body
    assert re.search(r"CVSS 3\.1 \d\.\d", body) or re.search(r"CVSS 4\.0 \d\.\d", body)
    assert "CVSS:3.1/" in html
    assert "Trivy" in body and "Grype" in body
    assert "Scanners disagree" in body or "disagree" in body.lower()
    assert "pkg:deb/" in body  # purl
    assert 'rel="noopener"' in html and "https://" in html  # advisory references are links
    assert not re.search(r'href="[^"]*Debian Security Tracker', html)  # names are never hrefs
    for href in re.findall(r'<a href="([^"]+)" rel="noopener"', html):
        assert href.startswith(("http://", "https://")), href
    assert "Replay double" not in body
    assert "fixture:" in body or BASELINE_SHA[:12] in body  # scan run identity
    assert "Not grouped into a work item" in body or "Work item #" in body


def test_cve_page_lists_same_cve_in_other_packages(
    baseline_client: TestClient, baseline_engine: Engine
) -> None:
    with session_scope(baseline_engine) as db:
        rows = db.exec(select(Finding.vuln_id, Finding.id)).all()
    seen: dict[str, list[int]] = {}
    for vid, fid in rows:
        assert fid is not None
        seen.setdefault(vid, []).append(fid)
    vid, ids = next((v, i) for v, i in seen.items() if len(i) > 1)
    body = _text(baseline_client.get(f"/findings/{ids[0]}").text)
    assert vid in body and "elsewhere" in body.lower()
    assert f'href="/findings/{ids[1]}"' in baseline_client.get(f"/findings/{ids[0]}").text


def test_missing_finding_is_404(baseline_client: TestClient) -> None:
    r = baseline_client.get("/findings/999999")
    assert r.status_code == 404
    assert "not found" in r.text.lower()
    assert baseline_client.get("/findings/not-a-number").status_code in (404, 422)


def test_findings_list_links_to_cve_pages(baseline_client: TestClient) -> None:
    html = baseline_client.get("/findings?severity=CRITICAL").text
    links = re.findall(
        r'<a class="primary mono" href="/findings/(\d+)">(CVE-[\d-]+|GHSA-[\w-]+)</a>', html
    )
    assert links, "no clickable CVE identifiers on the list"
    fid, vid = links[0]
    page = baseline_client.get(f"/findings/{fid}")
    assert page.status_code == 200 and vid in page.text
    assert "Vulnerabilities" in _text(html)  # page title


def test_findings_search_is_server_side(baseline_client: TestClient) -> None:
    html = baseline_client.get("/findings?severity=CRITICAL").text
    fid, vid = re.findall(
        r'<a class="primary mono" href="/findings/(\d+)">(CVE-[\d-]+|GHSA-[\w-]+)</a>', html
    )[0]
    hit = baseline_client.get(f"/findings?q={vid.lower()}").text
    assert f'href="/findings/{fid}">{vid}</a>' in hit
    assert "Search: <strong>" in hit and vid.lower() in hit
    # the severity tabs and pager keep the search
    assert f'href="/findings?severity=CRITICAL&amp;q={vid.lower()}"' in hit

    miss = baseline_client.get("/findings?q=zzzz-no-such-cve").text
    assert "No findings match these filters" in _text(miss)
    assert 'href="/findings/' not in miss


# ------------------------------------------------------------------------- replay DEMO lifecycle


@pytest.fixture(scope="module")
def demo(tmp_path_factory: pytest.TempPathFactory) -> tuple[Engine, TestClient]:
    out = tmp_path_factory.mktemp("demo")
    result = run_scenario("DEMO", out)
    assert result.passed, [c for c in result.checks if not c.ok]
    db = out / "demo.sqlite3"
    engine = open_database(db)
    settings = Settings(
        data_dir=db.parent, database_file=db.name, replay_mode=True, repo_root=REPO_ROOT
    )
    client = TestClient(create_app(settings, engine=engine))
    client.__enter__()
    return engine, client


def test_cve_page_shows_lifecycle_for_a_remediated_finding(demo: tuple[Engine, TestClient]) -> None:
    engine, client = demo
    with session_scope(engine) as db:
        f = db.exec(select(Finding).where(Finding.vuln_id == "CVE-2023-50447")).first()
        assert f is not None and f.work_item_id is not None
        wi = db.get(WorkItem, f.work_item_id)
        assert wi is not None and wi.pr_number is not None
        fid, wi_id, pr = f.id, wi.id, wi.pr_number
        sightings = db.exec(select(Sighting).where(Sighting.finding_id == fid)).all()
        runs = {s.scan_run_id for s in sightings}
    r = client.get(f"/findings/{fid}")
    assert r.status_code == 200
    html, body = r.text, _text(r.text)
    assert "Replay double" in body  # synthetic record explained, not misreported
    assert "Fixed" in body and "Sighting history" in body
    assert f'href="/issues/{wi_id}"' in html
    assert f"#{pr}" in body and "Pull request" in body
    assert "Devin session" in body
    for run_id in runs:
        assert f'href="/runs/{run_id}"' in html
    assert "Trivy" in body and "Grype" in body
    assert "Last seen" in body or "last seen" in body.lower()
    assert "Events" in body or "Timeline" in body
    assert "Launch Devin" not in html or 'href="/operator/launch/' not in html


def test_cve_page_marks_unclassified_and_no_fix(demo: tuple[Engine, TestClient]) -> None:
    engine, client = demo
    with session_scope(engine) as db:
        paramiko = db.exec(select(Finding).where(Finding.pkg_name == "paramiko")).first()
        assert paramiko is not None
        pid = paramiko.id
    body = _text(client.get(f"/findings/{pid}").text)
    assert "paramiko" in body
    assert "No fix" in body or "no fixed version" in body.lower() or "OpenVEX" in body


def test_every_demo_finding_page_renders(demo: tuple[Engine, TestClient]) -> None:
    engine, client = demo
    with session_scope(engine) as db:
        ids = db.exec(select(Finding.id)).all()
    assert ids
    for fid in ids:
        r = client.get(f"/findings/{fid}")
        assert r.status_code == 200, fid
        assert client.post(f"/findings/{fid}").status_code == 405


def test_replay_cve_page_has_no_launch_controls(demo: tuple[Engine, TestClient]) -> None:
    _, client = demo
    with session_scope(_) as db:
        fid = db.exec(select(Finding.id)).first()
    html = client.get(f"/findings/{fid}").text
    assert "/operator/launch/" not in html
    assert "read-only" in html.lower()
