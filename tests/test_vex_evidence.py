"""Approved OpenVEX documents travel through real scan evidence (as written by scan_image.sh) into
closure: the job keeps a checksummed copy, `load_scan_job` re-validates source path, checksum,
OpenVEX shape and `x-approval`, and `decide_outcome` only honours an approval that names the
finding's own issue and vulnerability."""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine
from sqlmodel import select

from hardening_loop.config import BASELINE_SHA, FORK_REPO
from hardening_loop.db import open_database, session_scope
from hardening_loop.domain.enums import (
    Ecosystem,
    GateMode,
    ImageTarget,
    Kind,
    Layer,
    Scanner,
    Severity,
    Trigger,
)
from hardening_loop.ingest.evidence import EvidenceError, load_scan_job
from hardening_loop.ingest.persist import RunMeta, ingest_run
from hardening_loop.ingest.vex import APPROVED_DIR, VexEvidenceError
from hardening_loop.models.tables import Evidence, Finding, ScanRun
from hardening_loop.orchestrator.closer import (
    ClosingOutcome,
    RunValidity,
    SightingView,
    decide_outcome,
)
from hardening_loop.replay.synth import approved_vex

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "baseline" / BASELINE_SHA
ISSUE_URL = f"https://github.com/{FORK_REPO}/issues/41"
OTHER_ISSUE_URL = f"https://github.com/{FORK_REPO}/issues/42"
VULN = "CVE-2023-48795"
PURL = "pkg:pypi/paramiko@3.4.0"


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_policy_job(
    tmp_path: Path,
    doc: dict[str, Any],
    *,
    source_path: str = f"{APPROVED_DIR}/{VULN.lower()}.json",
    evidence_file: str = f"vex/{VULN.lower()}.json",
    checksummed: bool = True,
    mode: str = "policy",
) -> Path:
    """Copy the real lean/policy fixture job and add one VEX document the way scan_image.sh does."""
    job_dir = tmp_path / "policy"
    shutil.copytree(FIXTURE / "lean" / "policy", job_dir)
    copy = job_dir / evidence_file
    copy.parent.mkdir(parents=True, exist_ok=True)
    copy.write_text(json.dumps(doc, indent=2))
    job = json.loads((job_dir / "job.json").read_text())
    job["mode"] = mode
    if checksummed:
        job["files"][evidence_file] = _sha(copy)
    job["vex_documents"] = [
        {
            "path": source_path,
            "evidence_file": evidence_file,
            "sha256": _sha(copy),
            "x-approval": doc.get("x-approval"),
            "vulnerabilities": [VULN],
        }
    ]
    (job_dir / "job.json").write_text(json.dumps(job, indent=2, sort_keys=True))
    return job_dir


def _doc(**overrides: Any) -> dict[str, Any]:
    doc = approved_vex(issue_url=ISSUE_URL, vuln_id=VULN, purl=PURL, approver="hayden1298")
    doc.update(overrides)
    return doc


def test_load_scan_job_carries_validated_approval(tmp_path: Path) -> None:
    job = load_scan_job(_write_policy_job(tmp_path, _doc()))
    assert len(job.vex_evidence) == 1
    ev = job.vex_evidence[0]
    assert ev.source_path == f"{APPROVED_DIR}/{VULN.lower()}.json"
    assert ev.evidence_file == f"vex/{VULN.lower()}.json"
    assert ev.approval.issue_url == ISSUE_URL
    assert ev.approval.approved_by == "hayden1298"
    assert ev.vuln_ids == {VULN}
    assert job.files[ev.evidence_file] == ev.sha256
    doc = job.vex_documents[0]
    assert doc["x-approval"] == {"issue_url": ISSUE_URL, "approved_by": "hayden1298"}
    assert doc["x-evidence"] == {
        "source_path": ev.source_path,
        "evidence_file": ev.evidence_file,
        "sha256": ev.sha256,
    }
    assert doc["statements"][0]["vulnerability"]["name"] == VULN


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"source_path": "security/vex/proposed/x.json"}, "not directly under"),
        ({"source_path": f"{APPROVED_DIR}/../proposed/x.json"}, "not directly under"),
        ({"source_path": f"{APPROVED_DIR}/nested/x.json"}, "not directly under"),
        ({"evidence_file": "trivy-vuln.json"}, "not under vex/"),
        ({"checksummed": False}, "not the checksummed evidence file"),
    ],
)
def test_rejects_documents_outside_approved_scope(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    with pytest.raises(VexEvidenceError, match=message):
        load_scan_job(_write_policy_job(tmp_path, _doc(), **kwargs))


def test_rejects_raw_mode_with_vex(tmp_path: Path) -> None:
    with pytest.raises(EvidenceError, match="raw evidence is never suppressed"):
        load_scan_job(_write_policy_job(tmp_path, _doc(), mode="raw"))


def test_tampered_copy_fails_checksum(tmp_path: Path) -> None:
    job_dir = _write_policy_job(tmp_path, _doc())
    copy = job_dir / "vex" / f"{VULN.lower()}.json"
    tampered = json.loads(copy.read_text())
    tampered["x-approval"]["issue_url"] = OTHER_ISSUE_URL
    copy.write_text(json.dumps(tampered))
    with pytest.raises(EvidenceError, match="checksum mismatch"):
        load_scan_job(job_dir)


@pytest.mark.parametrize(
    ("doc", "message"),
    [
        (_doc(**{"x-approval": None}), "lacks a valid x-approval"),
        (_doc(**{"x-approval": {"approved_by": "x"}}), "lacks a valid x-approval"),
        (_doc(**{"x-approval": {"issue_url": "not-a-url", "approved_by": "x"}}), "x-approval"),
        (_doc(**{"x-approval": {"issue_url": ISSUE_URL, "approved_by": " "}}), "x-approval"),
        (_doc(**{"@context": "https://example.com/not-vex"}), "not an OpenVEX"),
        (_doc(statements=[]), "no statements"),
        (
            _doc(
                statements=[
                    {
                        "vulnerability": {"name": VULN},
                        "products": [{"@id": PURL}],
                        "status": "affected",
                    }
                ]
            ),
            "cannot suppress",
        ),
        (
            _doc(
                statements=[{"vulnerability": {}, "products": [{"@id": PURL}], "status": "fixed"}]
            ),
            "no vulnerability.name",
        ),
        (
            _doc(statements=[{"vulnerability": {"name": VULN}, "products": [], "status": "fixed"}]),
            "no products",
        ),
    ],
)
def test_rejects_malformed_documents(tmp_path: Path, doc: dict[str, Any], message: str) -> None:
    with pytest.raises(VexEvidenceError, match=message):
        load_scan_job(_write_policy_job(tmp_path, doc))


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    return open_database(tmp_path / "t.sqlite3")


def _ingest(engine: Engine, tmp_path: Path) -> int:
    raw = load_scan_job(FIXTURE / "lean" / "raw")
    policy = load_scan_job(_write_policy_job(tmp_path, _doc()))
    meta = RunMeta(
        external_run_id="gha:1",
        trigger=Trigger.push,
        source_repo=FORK_REPO,
        source_branch="main",
        source_sha=BASELINE_SHA,
        platform="linux/amd64",
        lean_digest=raw.image_ref.removeprefix("docker:"),
        ci_digest=None,
        ci_layer_delta=None,
        started_at=datetime(2026, 9, 1, tzinfo=UTC),
        finished_at=datetime(2026, 9, 1, 1, tzinfo=UTC),
        scan_gate_mode=GateMode.report,
    )
    with session_scope(engine) as db:
        return ingest_run(
            db, meta, {"lean-raw": raw, "lean-policy": policy}, upper_bounds={}
        ).scan_run_id


def _finding(vuln_id: str = VULN) -> Finding:
    return Finding(
        dedupe_key=f"t:{vuln_id}",
        vuln_id=vuln_id,
        purl=PURL,
        pkg_name="paramiko",
        pkg_version="3.4.0",
        ecosystem=Ecosystem.pypi,
        layer=Layer.python,
        image_target=ImageTarget.lean,
        severity=Severity.high,
        kind=Kind.no_fix_reachability,
        reported_by_trivy=True,
        reported_by_grype=True,
    )


def test_ingested_run_closes_only_the_approved_issue(engine: Engine, tmp_path: Path) -> None:
    run_id = _ingest(engine, tmp_path)
    with session_scope(engine) as db:
        run = db.get(ScanRun, run_id)
        assert run is not None
        assert [d["x-approval"]["issue_url"] for d in run.vex_documents] == [ISSUE_URL]
        assert run.vex_documents[0]["x-evidence"]["evidence_file"] == f"vex/{VULN.lower()}.json"
        vex_rows = db.exec(
            select(Evidence).where(Evidence.scan_run_id == run_id, Evidence.kind == "vex")
        ).all()
        assert [Path(e.path).name for e in vex_rows] == [f"{VULN.lower()}.json"]
        assert vex_rows[0].sha256 == run.vex_documents[0]["x-evidence"]["sha256"]

        suppressed = SightingView(
            raw_present={Scanner.trivy: True, Scanner.grype: True},
            policy_present={Scanner.trivy: False, Scanner.grype: False},
        )

        def outcome(finding: Finding, issue_url: str | None) -> ClosingOutcome:
            return decide_outcome(
                finding,
                run,
                suppressed,
                validity=RunValidity(valid=True),
                disagreement_resolved_by_human=False,
                issue_url=issue_url,
                finding_was_closed=False,
            )

        assert outcome(_finding(), ISSUE_URL) is ClosingOutcome.approved_disposition
        assert outcome(_finding(), OTHER_ISSUE_URL) is ClosingOutcome.still_present
        assert outcome(_finding(), None) is ClosingOutcome.still_present
        assert outcome(_finding("CVE-2024-26130"), ISSUE_URL) is ClosingOutcome.still_present


def test_unvalidated_approval_in_run_is_ignored(engine: Engine, tmp_path: Path) -> None:
    """Closure never trusts an `x-approval` that did not survive evidence validation."""
    run = ScanRun(
        external_run_id="x",
        trigger=Trigger.push,
        source_repo=FORK_REPO,
        source_branch="main",
        source_sha=BASELINE_SHA,
        vex_documents=[
            {"x-approval": {"issue_url": ISSUE_URL, "approved_by": "bot"}},  # not OpenVEX
            _doc(**{"x-approval": {"issue_url": "issues/41", "approved_by": "bot"}}),
        ],
    )
    view = SightingView(
        raw_present={Scanner.trivy: True, Scanner.grype: True},
        policy_present={Scanner.trivy: False, Scanner.grype: False},
    )
    assert (
        decide_outcome(
            _finding(),
            run,
            view,
            validity=RunValidity(valid=True),
            disagreement_resolved_by_human=False,
            issue_url=ISSUE_URL,
            finding_was_closed=False,
        )
        is ClosingOutcome.still_present
    )
