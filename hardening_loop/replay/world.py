"""Replay harness: a real SQLite database + the real `Orchestrator`, wired to the in-memory GitHub,
Devin and CI doubles and a manual clock. Scenarios script the doubles; the orchestrator's behaviour
is the thing under test. Nothing here touches the network."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from sqlmodel import col, select

from hardening_loop.config import Settings
from hardening_loop.db import open_database, session_scope
from hardening_loop.devin.enums import DevinStatus, DevinStatusDetail
from hardening_loop.devin.fake import FakeDevin, FakeDevinError
from hardening_loop.devin.protocol import ReviewStatus
from hardening_loop.domain.enums import Kind, WorkItemState
from hardening_loop.github.fake import FakeGitHub
from hardening_loop.models.tables import (
    Event,
    Finding,
    PullRequest,
    Session,
    WorkItem,
)
from hardening_loop.orchestrator.engine import Orchestrator, TickReport
from hardening_loop.replay.synth import BASELINE_SHA, T0, SyntheticRun, ingest_synthetic

APPROVER = "Hunter-1298"
# Check-run names as the fork's workflows report them (job names; matrix jobs carry their
# values in parentheses). They cover the ladder rungs the fork can prove: L0 (check-python-deps,
# build-image), L1 (lean-smoke), L2 (unit-tests), L3 (app-runs) and L4 (test-*).
DEFAULT_CHECKS = (
    "check-python-deps",
    "build-image",
    "scan-lean-raw",
    "scan-lean-policy",
    "lean-smoke",
    "unit-tests (current)",
    "app-runs",
    "test-postgres",
    "test-mysql",
    "test-sqlite",
)


class ManualClock:
    def __init__(self, start: datetime = T0) -> None:
        self._now = start

    def now(self) -> datetime:
        return self._now

    def advance(self, **kwargs: float) -> datetime:
        self._now += timedelta(**kwargs)
        return self._now


def sha(label: str) -> str:
    """Deterministic 40-hex commit SHA for a label."""
    return hashlib.sha1(label.encode()).hexdigest()  # noqa: S324 - not security-relevant


@dataclass
class Check:
    description: str
    ok: bool
    detail: str = ""


@dataclass
class ScenarioResult:
    name: str
    title: str
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    network_attempts: list[str] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return all(c.ok for c in self.checks) and not self.network_attempts

    def expect(self, description: str, ok: bool, detail: object = "") -> None:
        self.checks.append(Check(description, bool(ok), str(detail)))

    def eq(self, description: str, actual: object, expected: object) -> None:
        self.checks.append(
            Check(description, actual == expected, f"expected={expected!r} actual={actual!r}")
        )


class World:
    def __init__(self, db_path: Path, **settings_overrides: Any) -> None:
        self.db_path = db_path
        self.engine = open_database(db_path)
        self.clock = ManualClock()
        self.gh = FakeGitHub(main_head=BASELINE_SHA)
        self.devin = FakeDevin()
        self.devin.head_resolver = self._pr_head
        overrides: dict[str, Any] = {
            "replay_mode": True,
            "data_dir": db_path.parent,
            "approver_logins": [APPROVER],
            "max_concurrent_sessions": 1,
            "retries_per_work_item": 2,
        }
        overrides.update(settings_overrides)
        self.settings = Settings(**overrides)
        self.orch = Orchestrator(self.engine, self.gh, self.devin, self.settings, clock=self.clock)
        self._runs = 0
        self.run_ids: dict[str, int] = {}

    # ------------------------------------------------------------------ scan runs

    def ingest(self, run: SyntheticRun, label: str | None = None) -> int:
        self._runs += 1
        ext = label or f"replay-{self._runs:03d}"
        run.at = self.clock.now()
        res = ingest_synthetic(self.engine, run, ext)
        self.run_ids[ext] = res.scan_run_id
        return res.scan_run_id

    def baseline(self, *seed_keys: str, configs: Sequence[str] = ()) -> int:
        run = SyntheticRun(source_sha=BASELINE_SHA, is_baseline=True).with_seeds(*seed_keys)
        run.with_configs(*configs)
        return self.ingest(run, "replay-baseline")

    def closing_run(self, source_sha: str, *seed_keys: str, **kw: Any) -> SyntheticRun:
        configs = kw.pop("configs", ())
        run = SyntheticRun(source_sha=source_sha, **kw).with_seeds(*seed_keys)
        run.with_configs(*configs)
        return run

    # ------------------------------------------------------------------ orchestration

    def tick(self, *, minutes: float = 5) -> TickReport:
        self.clock.advance(minutes=minutes)
        return self.orch.tick()

    def apply_run(self, run_id: int) -> dict[str, int]:
        counts = self.orch.apply_scan_run(run_id)
        self.orch.create_work_items(run_id)
        return counts

    # ------------------------------------------------------------------ queries

    def work_items(self, kind: Kind | None = None) -> list[WorkItem]:
        with session_scope(self.engine) as db:
            q = select(WorkItem).order_by(col(WorkItem.id))
            if kind is not None:
                q = q.where(WorkItem.kind == kind)
            items = list(db.exec(q).all())
            for w in items:
                db.expunge(w)
            return items

    def wi(self, wi_id: int) -> WorkItem:
        with session_scope(self.engine) as db:
            w = db.get(WorkItem, wi_id)
            assert w is not None
            db.expunge(w)
            return w

    def only_wi(self, kind: Kind | None = None) -> WorkItem:
        items = self.work_items(kind)
        assert len(items) == 1, f"expected one work item, got {[(w.id, w.kind) for w in items]}"
        return items[0]

    def findings(self, wi_id: int | None = None) -> list[Finding]:
        with session_scope(self.engine) as db:
            q = select(Finding).order_by(col(Finding.id))
            if wi_id is not None:
                q = q.where(Finding.work_item_id == wi_id)
            rows = list(db.exec(q).all())
            for r in rows:
                db.expunge(r)
            return rows

    def finding_by_vuln(self, vuln_id: str) -> Finding:
        with session_scope(self.engine) as db:
            f = db.exec(select(Finding).where(Finding.vuln_id == vuln_id)).first()
            assert f is not None, vuln_id
            db.expunge(f)
            return f

    def sessions(self) -> list[Session]:
        with session_scope(self.engine) as db:
            rows = list(db.exec(select(Session).order_by(col(Session.id))).all())
            for r in rows:
                db.expunge(r)
            return rows

    def pr_row(self, wi_id: int) -> PullRequest | None:
        with session_scope(self.engine) as db:
            row = db.exec(select(PullRequest).where(PullRequest.work_item_id == wi_id)).first()
            if row is not None:
                db.expunge(row)
            return row

    def events(self, entity_type: str | None = None, entity_id: int | None = None) -> list[Event]:
        with session_scope(self.engine) as db:
            q = select(Event).order_by(col(Event.id))
            if entity_type is not None:
                q = q.where(Event.entity_type == entity_type)
            if entity_id is not None:
                q = q.where(Event.entity_id == entity_id)
            rows = list(db.exec(q).all())
            for r in rows:
                db.expunge(r)
            return rows

    def event_names(self, wi_id: int) -> list[str]:
        return [e.event for e in self.events("work_item", wi_id)]

    def issue_labels(self, wi: WorkItem) -> set[str]:
        assert wi.issue_number is not None
        return set(self.gh.issues[wi.issue_number].labels)

    def issue_state(self, wi: WorkItem) -> str:
        assert wi.issue_number is not None
        return self.gh.issues[wi.issue_number].state

    # ------------------------------------------------------------------ scripted Devin/GitHub steps

    def devin_opens_pr(
        self,
        wi: WorkItem,
        output: dict[str, Any],
        *,
        files: list[str],
        acus: float,
        head_label: str | None = None,
    ) -> tuple[str, int]:
        """The fake session finishes with `pr_opened`, having opened a PR in the fake GitHub."""
        assert wi.active_session_id is not None
        head = sha(head_label or f"pr-head-{wi.id}")
        url = self.gh.open_pr(
            title=f"fix: {wi.title}"[:100],
            head_ref=f"devin/{wi.id}-{wi.kind.value}",
            head_sha=head,
            files=files,
        )
        number = int(url.rsplit("/", 1)[1])
        out = {
            "outcome": "pr_opened",
            "pr_url": url,
            "base_branch": "main",
            "findings_addressed": [f.vuln_id for f in self.findings(wi.id)],
            "findings_not_addressed": [],
            "tests_run": [{"command": "pytest -q tests/unit", "exit_code": 0}],
        }
        out.update(output)
        self.devin.finish(wi.active_session_id, out, acus=acus, pull_requests=[url])
        return url, number

    def ci(self, head: str, *, failing: Sequence[str] = (), pending: Sequence[str] = ()) -> None:
        results: dict[str, str | None] = {}
        for name in DEFAULT_CHECKS:
            if name in pending:
                results[name] = None
            elif name in failing:
                results[name] = "failure"
            else:
                results[name] = "success"
        self.gh.set_checks(head, results)

    def _pr_head(self, pr_url: str) -> str | None:
        number = int(pr_url.rsplit("/", 1)[1])
        pr = self.gh.prs.get(number)
        return pr.head_sha if pr else None

    def review_done(self, head: str, status: ReviewStatus = ReviewStatus.completed) -> None:
        """Devin finishes the review the controller triggered for `head`. Raises if the controller
        never asked for one, so a scenario cannot fake its way past the review stage."""
        for (url, sha_), _ in list(self.devin.reviews.items()):
            if sha_ == head:
                self.devin.finish_review(url, head, status)
                return
        raise FakeDevinError(f"controller never triggered a review of {head[:12]}")

    def human_approves_and_merges(self, wi: WorkItem, *, merge_label: str | None = None) -> str:
        assert wi.pr_number is not None
        self.gh.approve(wi.pr_number, APPROVER, at=self.clock.now())
        self.tick()
        merge_sha = sha(merge_label or f"merge-{wi.id}")
        self.gh.merge(wi.pr_number, merge_sha, at=self.clock.now())
        self.tick()
        return merge_sha

    def session_state(
        self,
        wi: WorkItem,
        status: DevinStatus,
        detail: DevinStatusDetail | None,
        **kw: Any,
    ) -> None:
        assert wi.active_session_id is not None
        self.devin.set_state(wi.active_session_id, status, detail, **kw)

    def state_of(self, wi_id: int) -> WorkItemState:
        return self.wi(wi_id).state


__all__ = [
    "APPROVER",
    "DEFAULT_CHECKS",
    "Check",
    "ManualClock",
    "ScenarioResult",
    "World",
    "sha",
]
