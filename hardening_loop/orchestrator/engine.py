"""The orchestrator: findings -> work items -> issues -> Devin sessions -> PRs -> checks -> human
merge -> source-matching rescan -> closure.

One class, driven by `tick()` from APScheduler (live) or by the replay runner (no network). It only
ever talks to `GitHubClient` / `DevinClient` protocols, so live and replay run the exact same code.
Every state change is a row in `events`; every decision about a session is a `session_polls` row.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from sqlalchemy import Engine
from sqlmodel import Session as DbSession
from sqlmodel import col, select

from hardening_loop import verification
from hardening_loop.classify.group import group_key_for, title_for
from hardening_loop.config import FORK_REPO, REMEDIATION_BRANCH, Settings, assert_repo_allowed
from hardening_loop.db import session_scope
from hardening_loop.devin.enums import Outcome, SessionSnapshot
from hardening_loop.devin.protocol import CreateSessionRequest, DevinClient
from hardening_loop.devin.schemas import schema_for, validate_output
from hardening_loop.domain.enums import (
    ACTIVE_WORK_ITEM_STATES,
    FindingState,
    HumanLabel,
    Kind,
    LifecycleLevel,
    Risk,
    Severity,
    WorkItemState,
)
from hardening_loop.github.protocol import CheckRun, CommitStatus, GitHubClient, PullRequestInfo
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
    utcnow,
)
from hardening_loop.orchestrator.assess import Assessment, Decision, SessionFacts, assess
from hardening_loop.orchestrator.closer import (
    CLOSING_FINDING_STATES,
    ClosingOutcome,
    decide_outcome,
    family_key,
    issue_may_close,
    sightings_for,
    validate_closing_run,
)
from hardening_loop.orchestrator.launch import LaunchAction, LaunchPreview, LaunchResult
from hardening_loop.orchestrator.launch import preview as launch_preview_for
from hardening_loop.orchestrator.policy import (
    diff_policy_violations,
    dispatch_allowed,
    parse_pr_url,
    verify_pull_request,
)
from hardening_loop.orchestrator.state import (
    FindingEvent,
    InvalidTransitionError,
    WorkItemEvent,
    next_finding_state,
    next_work_item_state,
)

log = logging.getLogger("hardening_loop.orchestrator")

SESSION_TAG = "hl"
KIND_LABELS: dict[Kind, str] = {
    Kind.dependency_upgrade: "kind:dependency-upgrade",
    Kind.no_fix_reachability: "kind:no-fix-reachability",
    Kind.container_hardening: "kind:container-hardening",
    Kind.scanner_disagreement: "kind:scanner-disagreement",
    Kind.helm_deploy_config: "kind:helm-deploy-config",
}
CONTROLLER_LABEL = "hardening-loop"
AWAITING_DISPATCH_LABEL = "awaiting-dispatch-approval"


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return utcnow()


@dataclass(frozen=True)
class AcuBudgetPosition:
    consumed: float
    outstanding: float

    @property
    def committed(self) -> float:
        return self.consumed + self.outstanding


@dataclass
class TickReport:
    work_items_created: int = 0
    issues_created: int = 0
    sessions_created: int = 0
    sessions_adopted: int = 0
    sessions_polled: int = 0
    prs_polled: int = 0
    labels_applied: int = 0


class Orchestrator:
    def __init__(
        self,
        engine: Engine,
        gh: GitHubClient,
        devin: DevinClient,
        settings: Settings,
        *,
        clock: Clock | None = None,
        playbook_ids: dict[Kind, str] | None = None,
        knowledge_ids: list[str] | None = None,
    ) -> None:
        self.engine = engine
        self.gh = gh
        self.devin = devin
        self.settings = settings
        self.clock = clock or SystemClock()
        self.playbook_ids = playbook_ids or {}
        self.knowledge_ids = knowledge_ids or []
        self.repo = settings.fork_repo
        assert_repo_allowed(self.repo)

    # ------------------------------------------------------------------ tick

    def tick(self, *, auto_dispatch: bool = True) -> TickReport:
        """One control-loop iteration. With `auto_dispatch=False` (operator mode) issues are still
        opened and crashed dispatches recovered, but no new session is created unless an operator
        launches one explicitly."""
        report = TickReport()
        report.work_items_created = len(self.create_work_items())
        if auto_dispatch:
            created, adopted, issues = self.dispatch()
        else:
            issues = self.open_issues()
            created = 0
            with session_scope(self.engine) as db:
                adopted = self._recover_dispatching(db)
        report.sessions_created, report.sessions_adopted, report.issues_created = (
            created,
            adopted,
            issues,
        )
        report.sessions_polled = self.poll_sessions()
        report.prs_polled = self.poll_pull_requests()
        report.labels_applied = self.poll_human_labels()
        return report

    # ------------------------------------------------------------------ events / transitions

    def _event(
        self,
        db: DbSession,
        *,
        entity_type: str,
        entity_id: int,
        event: str,
        from_state: str | None,
        to_state: str | None,
        reason: str | None,
        actor: str = "controller",
        evidence_ids: list[int] | None = None,
    ) -> None:
        db.add(
            Event(
                ts=self.clock.now(),
                actor=actor,
                entity_type=entity_type,
                entity_id=entity_id,
                event=event,
                from_state=from_state,
                to_state=to_state,
                reason=reason,
                evidence_ids=evidence_ids or [],
            )
        )

    def _wi(
        self,
        db: DbSession,
        wi: WorkItem,
        event: WorkItemEvent,
        reason: str,
        *,
        actor: str = "controller",
    ) -> WorkItemState:
        assert wi.id is not None
        before = wi.state
        try:
            after = next_work_item_state(before, event)
        except InvalidTransitionError as exc:
            # Never guess. Record it and escalate if the state can be escalated.
            self._event(
                db,
                entity_type="work_item",
                entity_id=wi.id,
                event="invalid_transition",
                from_state=before.value,
                to_state=before.value,
                reason=f"{exc}; reason={reason}",
            )
            if before is not WorkItemState.needs_human and (
                (before, WorkItemEvent.blocked) in _blockable()
            ):
                wi.blocked_reason = f"invalid_transition:{before.value}:{event.value}"
                return self._wi(db, wi, WorkItemEvent.blocked, wi.blocked_reason)
            return before
        wi.state = after
        wi.updated_at = self.clock.now()
        if event is WorkItemEvent.blocked:
            wi.blocked_reason = reason
        db.add(wi)
        self._event(
            db,
            entity_type="work_item",
            entity_id=wi.id,
            event=event.value,
            from_state=before.value,
            to_state=after.value,
            reason=reason,
            actor=actor,
        )
        self._sync_human_label(wi, before, after)
        return after

    def _finding(
        self,
        db: DbSession,
        f: Finding,
        event: FindingEvent,
        reason: str,
        *,
        actor: str = "controller",
        run_id: int | None = None,
    ) -> bool:
        assert f.id is not None
        before = f.state
        try:
            after = next_finding_state(before, event)
        except InvalidTransitionError as exc:
            self._event(
                db,
                entity_type="finding",
                entity_id=f.id,
                event="invalid_transition",
                from_state=before.value,
                to_state=before.value,
                reason=f"{exc}; reason={reason}",
            )
            return False
        f.state = after
        f.updated_at = self.clock.now()
        if after in CLOSING_FINDING_STATES and run_id is not None:
            f.closed_by_run_id = run_id
        db.add(f)
        self._event(
            db,
            entity_type="finding",
            entity_id=f.id,
            event=event.value,
            from_state=before.value,
            to_state=after.value,
            reason=reason,
            actor=actor,
            evidence_ids=[run_id] if run_id is not None else None,
        )
        return True

    def _sync_human_label(self, wi: WorkItem, before: WorkItemState, after: WorkItemState) -> None:
        if wi.issue_number is None:
            return
        attention = {WorkItemState.needs_human, WorkItemState.failed}
        try:
            if after in attention and before not in attention:
                self.gh.add_labels(self.repo, wi.issue_number, [HumanLabel.needs_human.value])
                body = f"**needs-human** ({after.value}): `{wi.blocked_reason or 'see events'}`"
                self.gh.comment_issue(self.repo, wi.issue_number, body)
            elif before in attention and after not in attention:
                self.gh.remove_label(self.repo, wi.issue_number, HumanLabel.needs_human.value)
        except Exception as exc:
            log.warning("label sync failed for issue #%s: %s", wi.issue_number, exc)

    # ------------------------------------------------------------------ work items

    def create_work_items(self, run_id: int | None = None) -> list[int]:
        """Group open/regressed classified findings of the latest main run into WorkItems."""
        created: list[int] = []
        with session_scope(self.engine) as db:
            run = self._latest_main_run(db, run_id)
            if run is None:
                return created
            assert run.id is not None
            findings = db.exec(
                select(Finding).where(
                    Finding.last_seen_run_id == run.id,
                    col(Finding.kind).is_not(None),
                    col(Finding.state).in_([FindingState.open, FindingState.regression]),
                )
            ).all()
            buckets: dict[tuple[Kind, str], list[Finding]] = defaultdict(list)
            for f in findings:
                assert f.kind is not None
                buckets[
                    (
                        f.kind,
                        group_key_for(
                            f.kind,
                            pkg_name=f.pkg_name,
                            ecosystem=f.ecosystem,
                            layer=f.layer,
                            dedupe_key=f.dedupe_key,
                        ),
                    )
                ].append(f)

            for (kind, key), members in sorted(buckets.items(), key=lambda kv: kv[0]):
                wi, is_new = self._work_item_for_group(db, kind, key, members)
                assert wi.id is not None
                joining = [f for f in members if f.work_item_id != wi.id]
                if is_new:
                    created.append(wi.id)
                elif joining:
                    self._members_joined(db, wi, joining)
                for f in joining:
                    f.work_item_id = wi.id
                    self._finding(db, f, FindingEvent.grouped, f"work_item={wi.id} {wi.group_key}")
        return created

    def _members_joined(self, db: DbSession, wi: WorkItem, joining: list[Finding]) -> None:
        """Findings discovered after the group was opened join the existing work item; closure then
        requires them too. A dispatched item is told about them so the fix can cover them."""
        assert wi.id is not None
        vulns = sorted({f.vuln_id for f in joining})
        self._event(
            db,
            entity_type="work_item",
            entity_id=wi.id,
            event="members_added",
            from_state=wi.state.value,
            to_state=wi.state.value,
            reason=f"{len(joining)} new finding(s): {', '.join(vulns[:8])}",
            actor="scanner",
        )
        if wi.issue_number is None or wi.state is WorkItemState.queued:
            return
        body = (
            f"A later scan added {len(joining)} finding(s) to this group: "
            f"{', '.join(f'`{v}`' for v in vulns[:8])}. They must be remediated here too; "
            "this issue cannot close until every member is resolved."
        )
        self.gh.comment_issue(self.repo, wi.issue_number, body)
        if wi.active_session_id is not None and wi.state in ACTIVE_WORK_ITEM_STATES:
            self.devin.send_message(
                wi.active_session_id,
                f"New findings joined this work item: {', '.join(vulns[:8])}. "
                "Cover them in the same PR and list them in the structured output.",
            )
            sess = db.exec(select(Session).where(Session.devin_id == wi.active_session_id)).first()
            if sess is not None:
                sess.messages_sent += 1
                db.add(sess)

    def _work_item_for_group(
        self, db: DbSession, kind: Kind, key: str, members: list[Finding]
    ) -> tuple[WorkItem, bool]:
        existing = db.exec(
            select(WorkItem).where(
                WorkItem.kind == kind,
                WorkItem.group_key == key,
                WorkItem.source_branch == REMEDIATION_BRANCH,
            )
        ).first()
        regression_of: int | None = None
        if existing is not None:
            if existing.state in (WorkItemState.verified, WorkItemState.abandoned):
                # Closed group came back: a new, explicitly linked regression work item.
                regression_of = existing.id
                n = 1
                while db.exec(select(WorkItem).where(WorkItem.group_key == f"{key}#r{n}")).first():
                    n += 1
                key = f"{key}#r{n}"
            else:
                return existing, False  # still being worked: new members join it
        severity = max((f.severity for f in members), key=lambda s: s.rank)
        risk = Risk.high if any(f.risk is Risk.high for f in members) else Risk.normal
        first = members[0]
        wi = WorkItem(
            kind=kind,
            group_key=key,
            title=title_for(
                kind,
                vuln_ids=[f.vuln_id for f in members],
                pkg_name=first.pkg_name,
                pkg_version=first.pkg_version,
                layer=first.layer,
            ),
            severity=severity,
            risk=risk,
            acu_cap=float(kind.acu_cap),
            regression_of_work_item_id=regression_of,
            created_at=self.clock.now(),
            updated_at=self.clock.now(),
        )
        db.add(wi)
        db.flush()
        assert wi.id is not None
        self._event(
            db,
            entity_type="work_item",
            entity_id=wi.id,
            event="created",
            from_state=None,
            to_state=wi.state.value,
            reason=f"{len(members)} findings; severity={severity.value}; risk={risk.value}"
            + (f"; regression_of={regression_of}" if regression_of else ""),
        )
        return wi, True

    def _latest_main_run(self, db: DbSession, run_id: int | None) -> ScanRun | None:
        if run_id is not None:
            return db.get(ScanRun, run_id)
        return db.exec(
            select(ScanRun)
            .where(ScanRun.source_repo == FORK_REPO, ScanRun.source_branch == REMEDIATION_BRANCH)
            .order_by(col(ScanRun.ingested_at).desc(), col(ScanRun.id).desc())
        ).first()

    # ------------------------------------------------------------------ dispatch

    def dispatch(self) -> tuple[int, int, int]:
        """Create issues for queued items, then sessions for eligible items within capacity."""
        issues = self.open_issues()
        created = adopted = 0
        with session_scope(self.engine) as db:
            adopted += self._recover_dispatching(db)
            active = self._active_session_count(db)
            budget = self._acu_budget_position(db)
            candidates = db.exec(
                select(WorkItem)
                .where(WorkItem.state == WorkItemState.issue_open)
                .order_by(col(WorkItem.severity).desc(), col(WorkItem.id))
            ).all()
            # Order by severity rank (CRITICAL first), then age.
            candidates = sorted(candidates, key=lambda w: (-w.severity.rank, w.id or 0))
            for wi in candidates:
                if active >= self.settings.max_concurrent_sessions:
                    break
                if wi.issue_number is None:
                    continue
                labels = self.gh.get_issue(self.repo, wi.issue_number).labels
                if not dispatch_allowed(wi.severity, labels):
                    continue
                if budget.committed + wi.acu_cap > self.settings.global_acu_budget:
                    self._event(
                        db,
                        entity_type="work_item",
                        entity_id=wi.id or 0,
                        event="budget_deferred",
                        from_state=wi.state.value,
                        to_state=wi.state.value,
                        reason=f"consumed={budget.consumed:.2f}+outstanding="
                        f"{budget.outstanding:.2f}+cap={wi.acu_cap:.0f}>"
                        f"budget={self.settings.global_acu_budget:.0f}",
                    )
                    continue
                outcome = self._dispatch_one(db, wi)
                if outcome == "created":
                    created += 1
                elif outcome == "adopted":
                    adopted += 1
                if outcome in ("created", "adopted"):
                    active += 1
                    budget = self._acu_budget_position(db)
        return created, adopted, issues

    def _recover_dispatching(self, db: DbSession) -> int:
        """Resume work items a crashed dispatch left in `dispatching` (the DB lock is committed
        before any Devin call, so a crash anywhere after it strands the item). `dispatch()` is the
        only writer of that state and ticks are serial, so anything in it at tick start is stale.
        Adopt the `wi-<id>`-tagged session if Devin holds one, otherwise release the lock through
        the normal dispatch-failure path (retryable, bounded by `max_dispatch_failures`)."""
        adopted = 0
        stuck = db.exec(select(WorkItem).where(WorkItem.state == WorkItemState.dispatching)).all()
        for wi in stuck:
            assert wi.id is not None
            self._event(
                db,
                entity_type="work_item",
                entity_id=wi.id,
                event="dispatch_recovery",
                from_state=wi.state.value,
                to_state=wi.state.value,
                reason="found in dispatching at tick start",
            )
            outcome = self._adopt_tagged_session(db, wi)
            if outcome is None:
                outcome = self._dispatch_failed(db, wi, "dispatching_recovered:no_session_at_devin")
            if outcome == "adopted":
                adopted += 1
        return adopted

    def open_issues(self) -> int:
        n = 0
        with session_scope(self.engine) as db:
            queued = db.exec(select(WorkItem).where(WorkItem.state == WorkItemState.queued)).all()
            for wi in queued:
                if self._open_issue(db, wi):
                    n += 1
        return n

    def _open_issue(self, db: DbSession, wi: WorkItem) -> bool:
        assert wi.id is not None
        members = db.exec(select(Finding).where(Finding.work_item_id == wi.id)).all()
        labels = [CONTROLLER_LABEL, KIND_LABELS[wi.kind], f"severity:{wi.severity.value}"]
        if wi.risk is Risk.high:
            labels.append("risk:high")
        if not dispatch_allowed(wi.severity, []):
            labels.append(AWAITING_DISPATCH_LABEL)
        try:
            issue = self.gh.create_issue(
                self.repo,
                f"[hardening-loop] {wi.title}",
                self._issue_body(wi, members),
                labels,
            )
        except Exception as exc:
            self._event(
                db,
                entity_type="work_item",
                entity_id=wi.id,
                event="issue_create_failed",
                from_state=wi.state.value,
                to_state=wi.state.value,
                reason=str(exc)[:300],
            )
            return False
        wi.issue_number = issue.number
        wi.issue_url = issue.url
        wi.issue_opened_at = self.clock.now()
        self._wi(db, wi, WorkItemEvent.issue_created, issue.url)
        return True

    # ------------------------------------------------------------------ operator launch

    def launch_preview(self, work_item_id: int) -> LaunchPreview:
        """What an operator launch of `work_item_id` would do, and why it may be refused."""
        with session_scope(self.engine) as db:
            wi = db.get(WorkItem, work_item_id)
            if wi is None:
                raise LookupError(f"work item {work_item_id} not found")
            return self._launch_preview(db, wi)

    def _launch_preview(self, db: DbSession, wi: WorkItem) -> LaunchPreview:
        assert wi.id is not None
        budget = self._acu_budget_position(db)
        return launch_preview_for(
            work_item_id=wi.id,
            state=wi.state,
            severity=wi.severity,
            has_issue=wi.issue_number is not None,
            acu_cap=wi.acu_cap,
            active_sessions=self._active_session_count(db),
            max_concurrent_sessions=self.settings.max_concurrent_sessions,
            acu_consumed=budget.consumed,
            acu_outstanding=budget.outstanding,
            global_acu_budget=self.settings.global_acu_budget,
            repo=self.repo,
            branch=REMEDIATION_BRANCH,
        )

    def launch(self, work_item_id: int, *, operator: str) -> LaunchResult:
        """Explicit operator dispatch of one work item. Records the decision as an event and as a
        `dispatch:approved` label plus comment on the tracking issue (GitHub stays the audit
        trail), then runs the ordinary `_dispatch_one` path with every safeguard it has."""
        with session_scope(self.engine) as db:
            wi = db.get(WorkItem, work_item_id)
            if wi is None:
                raise LookupError(f"work item {work_item_id} not found")
            pv = self._launch_preview(db, wi)
            if not pv.eligible:
                reason = pv.block.value if pv.block else "ineligible"
                self._event(
                    db,
                    entity_type="work_item",
                    entity_id=work_item_id,
                    event="operator_launch_refused",
                    from_state=wi.state.value,
                    to_state=wi.state.value,
                    reason=f"{reason}; operator={operator}",
                    actor="operator",
                )
                return LaunchResult("rejected", work_item_id, reason, issue_url=wi.issue_url)
            if pv.action is LaunchAction.relaunch:
                if wi.issue_number is not None:
                    try:
                        self.gh.remove_label(self.repo, wi.issue_number, HumanLabel.retry.value)
                    except Exception as exc:
                        log.debug("retry label absent on #%s: %s", wi.issue_number, exc)
                wi.retries_used = 0
                wi.active_session_id = None
                wi.blocked_reason = None
                self._wi(
                    db, wi, WorkItemEvent.human_retry, f"operator={operator}", actor="operator"
                )
            if wi.state is WorkItemState.queued and not self._open_issue(db, wi):
                return LaunchResult("failed", work_item_id, "issue_create_failed")
            if wi.state is not WorkItemState.issue_open or wi.issue_number is None:
                return LaunchResult(
                    "rejected",
                    work_item_id,
                    f"unexpected_state:{wi.state.value}",
                    issue_url=wi.issue_url,
                )
            approved_here = False
            try:
                if pv.needs_dispatch_approval:
                    self.gh.add_labels(
                        self.repo, wi.issue_number, [HumanLabel.dispatch_approved.value]
                    )
                    approved_here = True
                    try:
                        self.gh.remove_label(self.repo, wi.issue_number, AWAITING_DISPATCH_LABEL)
                    except Exception as exc:
                        log.debug("awaiting label absent on #%s: %s", wi.issue_number, exc)
                self.gh.comment_issue(
                    self.repo,
                    wi.issue_number,
                    f"Operator `{operator}` launched Devin from the dashboard "
                    f"(cap {wi.acu_cap:.0f} ACU, base `{REMEDIATION_BRANCH}`).",
                )
            except Exception as exc:
                if approved_here:
                    self._revoke_dispatch_approval(wi.issue_number)
                return self._launch_failed(db, wi, f"github:{exc}")
            self._event(
                db,
                entity_type="work_item",
                entity_id=work_item_id,
                event="operator_launch",
                from_state=wi.state.value,
                to_state=wi.state.value,
                reason=f"operator={operator}; cap={wi.acu_cap:.0f}",
                actor="operator",
            )
            labels = self.gh.get_issue(self.repo, wi.issue_number).labels
            if not dispatch_allowed(wi.severity, labels):
                return self._launch_failed(db, wi, "dispatch_not_allowed_after_labeling")
            outcome = self._dispatch_one(db, wi)
            db.flush()
            row = (
                db.exec(select(Session).where(Session.devin_id == wi.active_session_id)).first()
                if wi.active_session_id
                else None
            )
            reason = outcome
            if outcome == "failed":
                last = db.exec(
                    select(Event)
                    .where(Event.entity_type == "work_item", Event.entity_id == work_item_id)
                    .order_by(col(Event.id).desc())
                ).first()
                reason = (
                    wi.blocked_reason
                    or (last.reason if last is not None and last.reason else None)
                    or "dispatch_failed"
                )[:300]
            return LaunchResult(
                outcome,
                work_item_id,
                reason,
                session_id=row.devin_id if row else None,
                session_url=row.url if row else None,
                issue_url=wi.issue_url,
            )

    def launch_work_item(self, work_item_id: int, operator_actor: str) -> LaunchResult:
        """Alias of `launch` with positional operator identity."""
        return self.launch(work_item_id, operator=operator_actor)

    def _revoke_dispatch_approval(self, issue_number: int) -> None:
        """Undo the approval a failed launch granted so the scheduler cannot dispatch it later."""
        try:
            self.gh.remove_label(self.repo, issue_number, HumanLabel.dispatch_approved.value)
            self.gh.add_labels(self.repo, issue_number, [AWAITING_DISPATCH_LABEL])
        except Exception:
            log.exception("could not revoke dispatch approval on #%s", issue_number)

    def _launch_failed(self, db: DbSession, wi: WorkItem, reason: str) -> LaunchResult:
        assert wi.id is not None
        self._event(
            db,
            entity_type="work_item",
            entity_id=wi.id,
            event="operator_launch_failed",
            from_state=wi.state.value,
            to_state=wi.state.value,
            reason=reason[:300],
            actor="operator",
        )
        return LaunchResult("failed", wi.id, reason[:300], issue_url=wi.issue_url)

    def _issue_body(self, wi: WorkItem, members: Sequence[Finding]) -> str:
        rows = [
            "| id | package | version | layer | severity | trivy | grype | fix versions |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for f in sorted(members, key=lambda m: (-m.severity.rank, m.vuln_id)):
            fixes = sorted({v for vs in f.fix_versions_by_scanner.values() for v in vs})
            rows.append(
                f"| {f.vuln_id} | {f.pkg_name or f.resource or ''} | {f.pkg_version or ''} | "
                f"{f.layer.value} | {f.severity.value} | {'x' if f.reported_by_trivy else ''} | "
                f"{'x' if f.reported_by_grype else ''} | {', '.join(fixes)} |"
            )
        return "\n".join(
            [
                f"**Kind {wi.kind.value}** `{wi.kind.playbook_slug}` - group `{wi.group_key}` - "
                f"ACU cap {wi.acu_cap:.0f} - risk {wi.risk.value}",
                "",
                f"Base branch: `{REMEDIATION_BRANCH}` in `{self.repo}`. "
                "Approvals and merges happen in GitHub only; the controller never merges.",
                "",
                *rows,
                "",
                "_Managed by superset-hardening-loop. Labels: `retry`, `disposition:approved`, "
                "`disagreement:resolved`, `dispatch:approved`; closing this issue abandons the "
                "work item._",
            ]
        )

    def _dispatch_one(self, db: DbSession, wi: WorkItem) -> str:
        assert wi.id is not None and wi.issue_number is not None
        # 1. Take the DB lock: dispatching + flush before any network call.
        self._wi(db, wi, WorkItemEvent.dispatch_started, "capacity available")
        db.flush()
        db.commit()
        # 2. Reconcile: a session already tagged wi-<id> means a previous crash mid-dispatch.
        outcome = self._adopt_tagged_session(db, wi)
        if outcome is not None:
            return outcome
        tag = f"wi-{wi.id}"
        # 3. Create.
        members = db.exec(select(Finding).where(Finding.work_item_id == wi.id)).all()
        try:
            attachment = self.devin.upload_attachment(
                f"findings-wi-{wi.id}.json", self._findings_attachment(wi, members)
            )
            snap = self.devin.create_session(
                CreateSessionRequest(
                    prompt=self._prompt(wi, members, attachment),
                    repos=[f"github.com/{self.repo}"],
                    title=f"[hl wi-{wi.id}] {wi.title}"[:120],
                    tags=[SESSION_TAG, tag, f"kind-{wi.kind.value}"],
                    max_acu_limit=wi.acu_cap,
                    structured_output_schema=schema_for(wi.kind),
                    playbook_id=self.playbook_ids.get(wi.kind),
                    knowledge_ids=list(self.knowledge_ids),
                    attachment_urls=[attachment],
                )
            )
        except Exception as exc:
            return self._dispatch_failed(db, wi, f"create_session:{exc}")
        self._record_session(db, wi, snap, adopted=False)
        self._wi(db, wi, WorkItemEvent.session_created, snap.session_id)
        for f in members:
            self._finding(db, f, FindingEvent.remediation_started, snap.session_id)
        try:
            self.gh.comment_issue(
                self.repo,
                wi.issue_number,
                f"Devin session started: {snap.url or snap.session_id} (cap {wi.acu_cap:.0f} ACU)",
            )
        except Exception as exc:
            self._event(
                db,
                entity_type="work_item",
                entity_id=wi.id,
                event="issue_comment_failed",
                from_state=wi.state.value,
                to_state=wi.state.value,
                reason=str(exc)[:300],
            )
        return "created"

    def _adopt_tagged_session(self, db: DbSession, wi: WorkItem) -> str | None:
        """Bind `wi` to the session Devin already holds for tag `wi-<id>`, if any. A session we
        never recorded (crash between `create_session` and the row insert) is adopted whatever
        its state so its output is still evaluated instead of duplicated; a recorded session is
        only re-adopted while it can still produce work (a finished one means a human retry, which
        gets a fresh session). Returns "adopted", "failed" (lookup error) or None (nothing to
        adopt)."""
        assert wi.id is not None
        known = {
            s.devin_id for s in db.exec(select(Session).where(Session.work_item_id == wi.id)).all()
        }
        try:
            remote = self.devin.list_sessions(tags=[f"wi-{wi.id}"])
        except Exception as exc:
            return self._dispatch_failed(db, wi, f"list_sessions:{exc}")
        adoptable = [s for s in remote if s.is_active or s.session_id not in known]
        if not adoptable:
            return None
        snap = max(adoptable, key=lambda s: (s.is_active, s.created_at))
        self._record_session(db, wi, snap, adopted=True)
        self._wi(db, wi, WorkItemEvent.session_adopted, snap.session_id)
        return "adopted"

    def _dispatch_failed(self, db: DbSession, wi: WorkItem, reason: str) -> str:
        wi.dispatch_failures += 1
        if wi.dispatch_failures >= self.settings.max_dispatch_failures:
            self._wi(db, wi, WorkItemEvent.blocked, f"dispatch_failed_repeatedly:{reason[:200]}")
        else:
            self._wi(db, wi, WorkItemEvent.dispatch_failed, reason[:300])
        return "failed"

    def _record_session(
        self, db: DbSession, wi: WorkItem, snap: SessionSnapshot, *, adopted: bool
    ) -> Session:
        assert wi.id is not None
        row = db.exec(select(Session).where(Session.devin_id == snap.session_id)).first()
        if row is None:
            row = Session(
                devin_id=snap.session_id,
                work_item_id=wi.id,
                url=snap.url,
                playbook_id=self.playbook_ids.get(wi.kind),
                max_acu_limit=wi.acu_cap,
                status=snap.status.value,
                status_detail=snap.status_detail.value if snap.status_detail else None,
                acus_consumed=snap.acus_consumed,
                created_at=self.clock.now(),
            )
            db.add(row)
            db.flush()
        wi.active_session_id = snap.session_id
        wi.budget_warning_sent = False
        db.add(wi)
        assert row.id is not None
        self._event(
            db,
            entity_type="session",
            entity_id=row.id,
            event="adopted" if adopted else "created",
            from_state=None,
            to_state=snap.status.value,
            reason=f"work_item={wi.id} cap={wi.acu_cap}",
        )
        return row

    def _findings_attachment(self, wi: WorkItem, members: Sequence[Finding]) -> bytes:
        payload = {
            "work_item_id": wi.id,
            "kind": wi.kind.value,
            "playbook": wi.kind.playbook_slug,
            "group_key": wi.group_key,
            "acu_cap": wi.acu_cap,
            "findings": [
                {
                    "id": f.vuln_id,
                    "dedupe_key": f.dedupe_key,
                    "package": f.pkg_name,
                    "version": f.pkg_version,
                    "purl": f.purl,
                    "ecosystem": f.ecosystem.value,
                    "layer": f.layer.value,
                    "resource": f.resource,
                    "severity": f.severity.value,
                    "severity_by_scanner": f.severity_by_scanner,
                    "fix_versions_by_scanner": f.fix_versions_by_scanner,
                    "reported_by": [
                        s
                        for s, on in (
                            ("trivy", f.reported_by_trivy),
                            ("grype", f.reported_by_grype),
                        )
                        if on
                    ],
                    "bound_blocked": f.bound_blocked,
                    "title": f.title,
                }
                for f in members
            ],
        }
        return json.dumps(payload, indent=2, sort_keys=True).encode()

    def _prompt(self, wi: WorkItem, members: Sequence[Finding], attachment_url: str) -> str:
        ids = ", ".join(sorted({f.vuln_id for f in members})[:12])
        return "\n".join(
            [
                f"Follow playbook `{wi.kind.playbook_slug}` for work item wi-{wi.id} "
                f"({wi.title}) in {self.repo}.",
                f"Base branch: `{REMEDIATION_BRANCH}`. Never touch apache/superset or other "
                "branches.",
                f"Tracking issue: {wi.issue_url}",
                f"Findings ({len(members)}): {ids}",
                f"Machine-readable findings: {attachment_url}",
                "Rules: never edit generated requirements files by hand (use "
                "./scripts/uv-pip-compile.sh); never add scanner ignore files; never claim tests "
                "you did not run; open at most one PR; finish with the structured output.",
                f"ACU cap for this session: {wi.acu_cap:.0f}.",
            ]
        )

    # ------------------------------------------------------------------ sessions

    def poll_sessions(self) -> int:
        polled = 0
        with session_scope(self.engine) as db:
            items = db.exec(
                select(WorkItem).where(
                    WorkItem.state == WorkItemState.session_active,
                    col(WorkItem.active_session_id).is_not(None),
                )
            ).all()
            for wi in items:
                assert wi.active_session_id is not None
                row = db.exec(
                    select(Session).where(Session.devin_id == wi.active_session_id)
                ).first()
                if row is None:
                    self._wi(db, wi, WorkItemEvent.blocked, "session_row_missing")
                    continue
                try:
                    snap = self.devin.get_session(wi.active_session_id)
                except Exception as exc:
                    log.warning("poll %s failed: %s", wi.active_session_id, exc)
                    continue
                polled += 1
                self._apply_snapshot(db, wi, row, snap)
        return polled

    def _apply_snapshot(
        self, db: DbSession, wi: WorkItem, row: Session, snap: SessionSnapshot
    ) -> Assessment:
        assert wi.id is not None and row.id is not None
        now = self.clock.now()
        row.status = snap.status.value
        row.status_detail = snap.status_detail.value if snap.status_detail else None
        row.acus_consumed = snap.acus_consumed
        row.structured_output = snap.structured_output
        row.pull_requests = [p.model_dump() for p in snap.pull_requests]
        row.last_polled_at = now
        if snap.is_done and row.finished_at is None:
            row.finished_at = now
        db.add(row)

        pr_info: PullRequestInfo | None = None
        pr_verified = False
        diff_ok = False
        diff_violations: list[str] = []
        problems: list[str] = []
        schema_errors = validate_output(wi.kind, snap.structured_output) if snap.is_done else []
        if snap.is_done and not schema_errors and snap.outcome is Outcome.pr_opened:
            pr_info, problems = self._resolve_pr(snap)
            pr_verified = pr_info is not None and not problems
            if pr_info is not None and pr_verified:
                files = self.gh.list_pr_files(self.repo, pr_info.number)
                diff_violations = diff_policy_violations(files, wi.kind)
                diff_ok = not diff_violations
        facts = SessionFacts(
            acu_cap=wi.acu_cap,
            schema_valid=snap.is_done and not schema_errors,
            pr_verified=pr_verified,
            diff_policy_ok=diff_ok,
            wall_clock_exceeded=(now - row.created_at)
            > timedelta(hours=self.settings.session_wall_clock_max_hours),
            budget_warning_sent=wi.budget_warning_sent,
        )
        question = (
            self.devin.last_user_facing_question(snap.session_id)
            if snap.is_waiting_for_user
            else None
        )
        result = assess(snap, facts, pending_question=question)
        detail = result.reason
        if schema_errors and result.decision is Decision.needs_human:
            detail += " | " + "; ".join(schema_errors[:5])
        if problems and result.decision is Decision.needs_human:
            detail += " | " + "; ".join(problems[:5])
        if diff_violations and result.decision is Decision.needs_human:
            detail += " | " + "; ".join(diff_violations[:5])
        db.add(
            SessionPoll(
                session_id=row.id,
                polled_at=now,
                status=snap.status.value,
                status_detail=row.status_detail,
                acus_consumed=snap.acus_consumed,
                decision=result.decision.value,
                reason=detail[:500],
            )
        )

        match result.decision:
            case Decision.continue_polling:
                pass
            case Decision.answer_question:
                assert result.reply is not None
                self.devin.send_message(snap.session_id, result.reply)
                row.messages_sent += 1
            case Decision.budget_warning:
                self.devin.send_message(
                    snap.session_id,
                    f"You have used {snap.acus_consumed:.1f} of {wi.acu_cap:.0f} ACU. Wrap up: "
                    "either open the PR now or finish with outcome=blocked and a blocked_reason.",
                )
                row.messages_sent += 1
                wi.budget_warning_sent = True
                db.add(wi)
            case Decision.needs_human:
                self._wi(db, wi, WorkItemEvent.blocked, detail[:500])
                if snap.is_done and snap.no_change_needed and wi.kind is Kind.scanner_disagreement:
                    self._post_disagreement_verdict(wi, snap)
            case Decision.ready_for_verification:
                assert pr_info is not None
                self._record_pr(db, wi, pr_info)
                self._wi(db, wi, WorkItemEvent.pr_opened, pr_info.url)
                self._wi(db, wi, WorkItemEvent.checks_started, pr_info.head_sha)
                if wi.issue_number is not None:
                    self.gh.comment_issue(self.repo, wi.issue_number, f"PR opened: {pr_info.url}")
        return result

    def _resolve_pr(self, snap: SessionSnapshot) -> tuple[PullRequestInfo | None, list[str]]:
        claimed = None
        if snap.structured_output:
            raw = snap.structured_output.get("pr_url")
            claimed = raw if isinstance(raw, str) else None
        urls = {p.pr_url.rstrip("/") for p in snap.pull_requests}
        if claimed:
            urls.add(claimed.rstrip("/"))
        if len(urls) != 1:
            return None, [f"expected exactly one PR, got {sorted(urls)}"]
        url = next(iter(urls))
        parsed = parse_pr_url(url)
        if parsed is None:
            return None, [f"unparseable PR url {url}"]
        repo, number = parsed
        if repo != self.repo:
            return None, [f"PR repo {repo} is not {self.repo}"]
        try:
            pr = self.gh.get_pull_request(repo, number)
        except Exception as exc:
            return None, [f"get_pull_request failed: {exc}"]
        problems = verify_pull_request(pr, claimed)
        return pr, problems

    def _record_pr(self, db: DbSession, wi: WorkItem, pr: PullRequestInfo) -> PullRequest:
        assert wi.id is not None
        row = db.exec(
            select(PullRequest).where(PullRequest.repo == pr.repo, PullRequest.number == pr.number)
        ).first()
        if row is None:
            row = PullRequest(
                work_item_id=wi.id,
                repo=pr.repo,
                number=pr.number,
                url=pr.url,
                base_branch=pr.base_ref,
                head_branch=pr.head_ref,
                head_sha=pr.head_sha,
                state="open",
                first_head_sha=pr.head_sha,
                diff_policy_ok=True,
                opened_at=self.clock.now(),
                updated_at=self.clock.now(),
            )
            db.add(row)
            db.flush()
        wi.pr_number = pr.number
        wi.pr_url = pr.url
        wi.pr_head_sha = pr.head_sha
        wi.pr_opened_at = wi.pr_opened_at or self.clock.now()
        self._raise_level(db, wi, row, LifecycleLevel.pr_opened, "pr_opened")
        db.add(wi)
        return row

    def _post_disagreement_verdict(self, wi: WorkItem, snap: SessionSnapshot) -> None:
        if wi.issue_number is None or not snap.structured_output:
            return
        out = snap.structured_output
        body = (
            f"Scanner-disagreement analysis finished: verdict=`{out.get('verdict')}`, "
            f"recommended_action=`{out.get('recommended_action')}`.\n\n{out.get('reason', '')}\n\n"
            "Apply label `disagreement:resolved` to accept this verdict; the finding closes only "
            "after the next successful scan of `main` still shows it in exactly one scanner."
        )
        self.gh.comment_issue(self.repo, wi.issue_number, body)

    # ------------------------------------------------------------------ pull requests

    _PR_STATES = (
        WorkItemState.pr_open,
        WorkItemState.checks_running,
        WorkItemState.review_pending,
        WorkItemState.ready_for_human,
        WorkItemState.needs_human,
    )

    def poll_pull_requests(self) -> int:
        n = 0
        with session_scope(self.engine) as db:
            items = db.exec(
                select(WorkItem).where(
                    col(WorkItem.state).in_(list(self._PR_STATES)),
                    col(WorkItem.pr_number).is_not(None),
                )
            ).all()
            for wi in items:
                assert wi.pr_number is not None and wi.id is not None
                pr_row = db.exec(
                    select(PullRequest).where(
                        PullRequest.repo == self.repo, PullRequest.number == wi.pr_number
                    )
                ).first()
                if pr_row is None:
                    continue
                try:
                    pr = self.gh.get_pull_request(self.repo, wi.pr_number)
                except Exception as exc:
                    log.warning("poll PR #%s failed: %s", wi.pr_number, exc)
                    continue
                n += 1
                self._apply_pr(db, wi, pr_row, pr)
        return n

    def _apply_pr(self, db: DbSession, wi: WorkItem, row: PullRequest, pr: PullRequestInfo) -> None:
        assert wi.id is not None and row.id is not None
        now = self.clock.now()
        row.updated_at = now
        if pr.head_sha != row.head_sha:
            self._event(
                db,
                entity_type="pull_request",
                entity_id=row.id,
                event="head_changed",
                from_state=row.head_sha,
                to_state=pr.head_sha,
                reason="new push",
            )
            row.head_sha = pr.head_sha
            wi.pr_head_sha = pr.head_sha
            row.review_status = None
            row.approved_by = None
            if not pr.merged and pr.state != "closed":
                self._reverify_new_head(db, wi, row, pr.head_sha)
        db.add(row)

        if pr.merged:
            row.state = "merged"
            row.merge_sha = pr.merge_commit_sha
            row.merged_at = pr.merged_at or now
            wi.merge_sha = pr.merge_commit_sha
            wi.merged_at = pr.merged_at or now
            if wi.state not in (WorkItemState.ready_for_human, WorkItemState.needs_human):
                self._wi(
                    db, wi, WorkItemEvent.blocked, f"merged_before_verification:{wi.state.value}"
                )
            if wi.state in (WorkItemState.ready_for_human, WorkItemState.needs_human):
                self._wi(
                    db, wi, WorkItemEvent.human_merged, pr.merge_commit_sha or "", actor="human"
                )
                self._raise_level(db, wi, row, LifecycleLevel.merged, "merged")
                for f in db.exec(select(Finding).where(Finding.work_item_id == wi.id)).all():
                    self._finding(db, f, FindingEvent.pr_merged, pr.merge_commit_sha or "")
            return
        if pr.state == "closed":
            row.state = "closed"
            if wi.state is not WorkItemState.needs_human:
                self._wi(db, wi, WorkItemEvent.pr_closed_unmerged, pr.url, actor="human")
            return
        if wi.state is WorkItemState.needs_human:
            return  # a human owns it; we only track merge/close above

        checks = self.gh.list_check_runs(self.repo, pr.head_sha)
        statuses = self.gh.list_commit_statuses(self.repo, pr.head_sha)
        self._record_checks(db, row, pr.head_sha, checks)
        self._record_depth(db, wi, row, pr.head_sha, checks)
        verdict = self._checks_verdict(checks)

        if wi.state is WorkItemState.pr_open:
            self._wi(db, wi, WorkItemEvent.checks_started, pr.head_sha)
        if verdict == "red":
            if wi.state in (
                WorkItemState.checks_running,
                WorkItemState.review_pending,
                WorkItemState.ready_for_human,
            ):
                failed = [
                    c.name for c in checks if c.status == "completed" and c.conclusion != "success"
                ]
                self._wi(db, wi, WorkItemEvent.checks_red, ", ".join(failed), actor="ci")
                self._retry_or_fail(db, wi, row, pr, checks)
            return
        if verdict != "green":
            return
        if wi.state is WorkItemState.checks_running:
            if row.first_head_checks_green is None and pr.head_sha == row.first_head_sha:
                row.first_head_checks_green = True
            self._wi(db, wi, WorkItemEvent.checks_green, pr.head_sha, actor="ci")
            self._raise_level(db, wi, row, LifecycleLevel.ci_green, "ci_green")
        if wi.state is WorkItemState.review_pending:
            self._check_review(db, wi, row, pr, statuses)
        if wi.state is WorkItemState.ready_for_human:
            self._check_approval(db, wi, row, pr)

    def _reverify_new_head(
        self, db: DbSession, wi: WorkItem, row: PullRequest, head_sha: str
    ) -> None:
        """Checks, Devin Review and approval are all evidence about one commit. A push replaces the
        commit, so the item goes back to `checks_running` and earns every level again."""
        if wi.state in (WorkItemState.review_pending, WorkItemState.ready_for_human):
            self._wi(db, wi, WorkItemEvent.new_head_pushed, f"new head {head_sha[:12]}")
        self._reset_level(db, wi, row, LifecycleLevel.pr_opened, f"new head {head_sha[:12]}")
        row.verification_depth = None
        row.depth_rungs = {}
        wi.verification_depth = None

    def _record_checks(
        self, db: DbSession, row: PullRequest, head_sha: str, checks: Iterable[CheckRun]
    ) -> None:
        assert row.id is not None
        for c in checks:
            existing = db.exec(
                select(PRCheck).where(
                    PRCheck.pull_request_id == row.id,
                    PRCheck.head_sha == head_sha,
                    PRCheck.name == c.name,
                )
            ).first()
            if existing is None:
                existing = PRCheck(
                    pull_request_id=row.id, head_sha=head_sha, name=c.name, status=c.status
                )
            existing.status = c.status
            existing.conclusion = c.conclusion
            existing.url = c.url
            existing.observed_at = self.clock.now()
            db.add(existing)

    def _record_depth(
        self, db: DbSession, wi: WorkItem, row: PullRequest, head_sha: str, checks: list[CheckRun]
    ) -> None:
        """Evaluate the L0-L6 ladder for this head from the check runs just observed. Every
        component is persisted, including `unavailable` ones; the work item's depth is the
        highest rung whose components all passed. Devin's own `tests_run` claims are stored as
        informational rows and never move the rung."""
        assert wi.id is not None and row.id is not None
        ev = verification.evaluate(checks)
        sess = (
            db.exec(select(Session).where(Session.devin_id == wi.active_session_id)).first()
            if wi.active_session_id
            else None
        )
        records = ev.records + verification.claims_from_output(
            sess.structured_output if sess is not None else None
        )
        for rec in records:
            existing = db.exec(
                select(VerificationCheck).where(
                    VerificationCheck.pull_request_id == row.id,
                    VerificationCheck.head_sha == head_sha,
                    VerificationCheck.source == rec.source,
                    VerificationCheck.name == rec.name,
                )
            ).first()
            if existing is None:
                existing = VerificationCheck(
                    pull_request_id=row.id,
                    head_sha=head_sha,
                    depth=rec.depth,
                    name=rec.name,
                    source=rec.source,
                    status=rec.status,
                )
            existing.status = rec.status
            existing.detail = rec.detail
            existing.url = rec.url
            existing.observed_at = self.clock.now()
            db.add(existing)
        row.depth_rungs = ev.rung_summary()
        highest = ev.highest_passed
        if highest != row.verification_depth:
            self._event(
                db,
                entity_type="work_item",
                entity_id=wi.id,
                event="verification_depth",
                from_state=None if row.verification_depth is None else row.verification_depth.name,
                to_state=None if highest is None else highest.name,
                reason=f"head {head_sha[:12]}: "
                + ", ".join(f"L{int(d)}={s.value}" for d, s in ev.rungs.items()),
            )
        row.verification_depth = highest
        wi.verification_depth = highest
        db.add(row)
        db.add(wi)

    def _checks_verdict(self, checks: list[CheckRun]) -> str:
        required = set(self.settings.required_check_names)
        relevant = [c for c in checks if not required or c.name in required]
        if required and {c.name for c in relevant} != required:
            return "running"  # a required check has not even been reported yet
        if not relevant:
            return "running"
        if any(c.status == "completed" and c.conclusion != "success" for c in relevant):
            return "red"
        if all(c.status == "completed" and c.conclusion == "success" for c in relevant):
            return "green"
        return "running"

    def _retry_or_fail(
        self,
        db: DbSession,
        wi: WorkItem,
        row: PullRequest,
        pr: PullRequestInfo,
        checks: list[CheckRun],
    ) -> None:
        if row.first_head_checks_green is None and pr.head_sha == row.first_head_sha:
            row.first_head_checks_green = False
        failed = [c for c in checks if c.status == "completed" and c.conclusion != "success"]
        if wi.retries_used >= self.settings.retries_per_work_item or wi.active_session_id is None:
            self._wi(
                db,
                wi,
                WorkItemEvent.retries_exhausted,
                f"{wi.retries_used}/{self.settings.retries_per_work_item} retries used; "
                f"failed: {', '.join(c.name for c in failed)}",
            )
            return
        wi.retries_used += 1
        lines = [
            f"CI failed on {pr.url} (head {pr.head_sha[:12]}). Fix it in this same PR/branch "
            f"(retry {wi.retries_used}/{self.settings.retries_per_work_item}):",
            *[f"- {c.name}: {c.conclusion} {c.url or ''}".rstrip() for c in failed],
            "Push the fix, then update the structured output. Do not open another PR.",
        ]
        self.devin.send_message(wi.active_session_id, "\n".join(lines))
        sess = db.exec(select(Session).where(Session.devin_id == wi.active_session_id)).first()
        if sess is not None:
            sess.messages_sent += 1
            sess.finished_at = None
            db.add(sess)
        self._wi(db, wi, WorkItemEvent.retry_sent, f"retry {wi.retries_used}")
        if wi.issue_number is not None:
            self.gh.comment_issue(
                self.repo,
                wi.issue_number,
                f"Checks failed on {pr.head_sha[:12]} ({', '.join(c.name for c in failed)}); "
                f"asked the same session to fix (retry {wi.retries_used}).",
            )

    def _check_review(
        self,
        db: DbSession,
        wi: WorkItem,
        row: PullRequest,
        pr: PullRequestInfo,
        statuses: list[CommitStatus],
    ) -> None:
        ctx = self.settings.devin_review_status_context
        if ctx is None:
            self._wi(db, wi, WorkItemEvent.review_not_observed, "devin_review_context_unknown")
            return
        matching = [s for s in statuses if s.context == ctx]
        done = [s for s in matching if s.state in ("success", "failure", "error")]
        if done:
            row.review_status = done[0].state
            self._wi(
                db, wi, WorkItemEvent.review_completed, f"{ctx}={done[0].state}", actor="devin"
            )
            self._raise_level(db, wi, row, LifecycleLevel.review_completed, "review_completed")
            return
        green_at = self._last_event_ts(db, wi, WorkItemEvent.checks_green)
        if green_at is not None and self.clock.now() - green_at > timedelta(
            minutes=self.settings.review_timeout_minutes
        ):
            self._wi(
                db,
                wi,
                WorkItemEvent.review_not_observed,
                f"no `{ctx}` status on {pr.head_sha[:12]}",
            )

    def _check_approval(
        self, db: DbSession, wi: WorkItem, row: PullRequest, pr: PullRequestInfo
    ) -> None:
        approvers = set(self.settings.approver_logins)
        for r in self.gh.list_pr_reviews(self.repo, pr.number):
            if r.state == "APPROVED" and r.author in approvers and r.commit_sha == pr.head_sha:
                if row.approved_by != r.author:
                    row.approved_by = r.author
                    self._raise_level(
                        db, wi, row, LifecycleLevel.human_approved, f"approved_by:{r.author}"
                    )
                return

    def _raise_level(
        self, db: DbSession, wi: WorkItem, row: PullRequest, level: LifecycleLevel, why: str
    ) -> None:
        assert wi.id is not None
        if level > wi.lifecycle_level:
            self._event(
                db,
                entity_type="work_item",
                entity_id=wi.id,
                event="lifecycle_level",
                from_state=wi.lifecycle_level.name,
                to_state=level.name,
                reason=why,
            )
            wi.lifecycle_level = level
        if level > row.lifecycle_level:
            row.lifecycle_level = level
        db.add(wi)
        db.add(row)

    def _reset_level(
        self, db: DbSession, wi: WorkItem, row: PullRequest, level: LifecycleLevel, why: str
    ) -> None:
        assert wi.id is not None
        if level < wi.lifecycle_level:
            self._event(
                db,
                entity_type="work_item",
                entity_id=wi.id,
                event="lifecycle_level",
                from_state=wi.lifecycle_level.name,
                to_state=level.name,
                reason=why,
            )
            wi.lifecycle_level = level
        row.lifecycle_level = min(row.lifecycle_level, level)
        db.add(wi)
        db.add(row)

    def _last_event_ts(self, db: DbSession, wi: WorkItem, event: WorkItemEvent) -> datetime | None:
        row = db.exec(
            select(Event)
            .where(
                Event.entity_type == "work_item",
                Event.entity_id == wi.id,
                Event.event == event.value,
            )
            .order_by(col(Event.ts).desc(), col(Event.id).desc())
        ).first()
        return row.ts if row else None

    # ------------------------------------------------------------------ human labels

    def poll_human_labels(self) -> int:
        n = 0
        with session_scope(self.engine) as db:
            items = db.exec(
                select(WorkItem).where(
                    col(WorkItem.state).in_(
                        [
                            WorkItemState.needs_human,
                            WorkItemState.failed,
                            WorkItemState.issue_open,
                            WorkItemState.ready_for_human,
                        ]
                    ),
                    col(WorkItem.issue_number).is_not(None),
                )
            ).all()
            for wi in items:
                assert wi.issue_number is not None and wi.id is not None
                try:
                    issue = self.gh.get_issue(self.repo, wi.issue_number)
                except Exception as exc:
                    log.warning("issue #%s fetch failed: %s", wi.issue_number, exc)
                    continue
                labels = set(issue.labels)
                if issue.state == "closed" and wi.state is not WorkItemState.verified:
                    self._wi(
                        db,
                        wi,
                        WorkItemEvent.human_abandoned,
                        "issue closed by human",
                        actor="human",
                    )
                    for f in db.exec(select(Finding).where(Finding.work_item_id == wi.id)).all():
                        self._finding(
                            db, f, FindingEvent.human_blocked, "issue closed", actor="human"
                        )
                    n += 1
                    continue
                if wi.state in (WorkItemState.needs_human, WorkItemState.failed):
                    if HumanLabel.retry.value in labels:
                        self.gh.remove_label(self.repo, wi.issue_number, HumanLabel.retry.value)
                        wi.retries_used = 0
                        wi.active_session_id = None
                        wi.blocked_reason = None
                        self._wi(db, wi, WorkItemEvent.human_retry, "retry label", actor="human")
                        n += 1
                        continue
                    if (
                        HumanLabel.disposition_approved.value in labels
                        and wi.kind is Kind.no_fix_reachability
                        and wi.human_resolution is None
                    ):
                        wi.human_resolution = HumanLabel.disposition_approved.value
                        self._wi(
                            db,
                            wi,
                            WorkItemEvent.human_resolved,
                            "disposition:approved",
                            actor="human",
                        )
                        n += 1
                        continue
                    if (
                        HumanLabel.disagreement_resolved.value in labels
                        and wi.kind is Kind.scanner_disagreement
                        and wi.human_resolution is None
                    ):
                        wi.human_resolution = HumanLabel.disagreement_resolved.value
                        self._wi(
                            db,
                            wi,
                            WorkItemEvent.human_resolved,
                            "disagreement:resolved",
                            actor="human",
                        )
                        n += 1
                        continue
        return n

    # ------------------------------------------------------------------ closure

    def apply_scan_run(self, run_id: int) -> dict[str, int]:
        """Evaluate one ingested run as a closing run for every finding it could close."""
        counts: dict[str, int] = defaultdict(int)
        with session_scope(self.engine) as db:
            run = db.get(ScanRun, run_id)
            if run is None:
                raise ValueError(f"scan run {run_id} not found")
            jobs = list(db.exec(select(ScanJob).where(ScanJob.scan_run_id == run_id)).all())
            sightings = list(db.exec(select(Sighting).where(Sighting.scan_run_id == run_id)).all())
            closing_wis = db.exec(
                select(WorkItem).where(
                    col(WorkItem.state).in_([WorkItemState.merged, WorkItemState.awaiting_rescan])
                )
            ).all()
            for wi in closing_wis:
                self._close_work_item(db, wi, run, jobs, sightings, counts)
            self._regressions(db, run, jobs, sightings, counts)
            self._drift(db, run, jobs, sightings, counts)
        return dict(counts)

    def _present_families(
        self, db: DbSession, sightings: list[Sighting]
    ) -> set[tuple[str, str, str | None, str]]:
        """Presence is a property of the vulnerability family, not of a versioned finding id: an
        upgrade to another still-vulnerable version reports under a new id, and neither closes the
        old one nor hides a regression."""
        ids = {s.finding_id for s in sightings if s.present}
        if not ids:
            return set()
        rows = db.exec(select(Finding).where(col(Finding.id).in_(list(ids)))).all()
        return {family_key(f) for f in rows}

    def _family_ids(self, db: DbSession, f: Finding) -> frozenset[int]:
        rows = db.exec(
            select(Finding.id).where(
                Finding.vuln_id == f.vuln_id,
                Finding.ecosystem == f.ecosystem,
                Finding.pkg_name == f.pkg_name,
                Finding.layer == f.layer,
            )
        ).all()
        return frozenset(i for i in rows if i is not None)

    def _is_ancestor(self, base: str, head: str) -> bool:
        if base == head:
            return True
        try:
            return self.gh.compare(self.repo, base, head).status in ("ahead", "identical")
        except Exception as exc:
            log.warning("compare %s...%s failed: %s", base[:12], head[:12], exc)
            return False

    def _close_work_item(
        self,
        db: DbSession,
        wi: WorkItem,
        run: ScanRun,
        jobs: list[ScanJob],
        sightings: list[Sighting],
        counts: dict[str, int],
    ) -> None:
        assert wi.id is not None and run.id is not None
        members = db.exec(select(Finding).where(Finding.work_item_id == wi.id)).all()
        require_policy = (
            wi.kind is Kind.no_fix_reachability
            or wi.human_resolution == HumanLabel.disposition_approved.value
        )
        disagreement = wi.human_resolution == HumanLabel.disagreement_resolved.value
        outcomes: list[ClosingOutcome] = []
        invalid_reasons: list[str] = []
        for f in members:
            validity = validate_closing_run(
                run,
                jobs,
                f,
                merge_sha=wi.merge_sha,
                is_ancestor=self._is_ancestor,
                require_policy=require_policy,
            )
            outcome = decide_outcome(
                f,
                run,
                sightings_for(f, run, sightings, family_ids=self._family_ids(db, f)),
                validity=validity,
                disagreement_resolved_by_human=disagreement,
                issue_url=wi.issue_url,
                finding_was_closed=f.state in CLOSING_FINDING_STATES,
            )
            outcomes.append(outcome)
            counts[outcome.value] += 1
            if outcome is ClosingOutcome.not_applicable:
                invalid_reasons.extend(validity.reasons)
                continue
            match outcome:
                case ClosingOutcome.fixed:
                    self._finding(
                        db,
                        f,
                        FindingEvent.closing_absent,
                        f"absent in run {run.external_run_id}",
                        actor="scanner",
                        run_id=run.id,
                    )
                case ClosingOutcome.approved_disposition:
                    self._finding(
                        db,
                        f,
                        FindingEvent.closing_vex,
                        f"approved VEX in run {run.external_run_id}",
                        actor="scanner",
                        run_id=run.id,
                    )
                case ClosingOutcome.scanner_disagreement_resolved:
                    self._finding(
                        db,
                        f,
                        FindingEvent.disagreement_resolved,
                        f"single-scanner in run {run.external_run_id}",
                        actor="human",
                        run_id=run.id,
                    )
                case _:
                    pass

        if any(o is ClosingOutcome.not_applicable for o in outcomes):
            reasons = sorted(set(invalid_reasons))[:6]
            self._wi(
                db,
                wi,
                WorkItemEvent.rescan_started,
                f"run {run.external_run_id} not a valid closing run: " + "; ".join(reasons),
            )
            return
        if wi.state is WorkItemState.merged:
            self._wi(db, wi, WorkItemEvent.rescan_started, f"run {run.external_run_id} evaluated")
        states = [f.state for f in members]
        if issue_may_close(states):
            wi.verified_at = self.clock.now()
            self._wi(
                db, wi, WorkItemEvent.rescan_verified, f"run {run.external_run_id}", actor="scanner"
            )
            pr_row = db.exec(select(PullRequest).where(PullRequest.work_item_id == wi.id)).first()
            if pr_row is not None:
                self._raise_level(
                    db, wi, pr_row, LifecycleLevel.rescan_verified, run.external_run_id
                )
            else:
                wi.lifecycle_level = max(wi.lifecycle_level, LifecycleLevel.rescan_verified)
            if wi.issue_number is not None:
                by_state: dict[str, int] = defaultdict(int)
                for s in states:
                    by_state[s.value] += 1
                self.gh.comment_issue(
                    self.repo,
                    wi.issue_number,
                    f"Verified by scan run `{run.external_run_id}` of `{run.source_branch}` @ "
                    f"`{run.source_sha[:12]}` (lean {run.lean_digest}); "
                    f"outcomes: {dict(by_state)}. "
                    f"Tools: {run.tools}. Closing.",
                )
                self.gh.close_issue(self.repo, wi.issue_number)
            return
        still = [
            f.vuln_id
            for f, o in zip(members, outcomes, strict=True)
            if o is ClosingOutcome.still_present
        ]
        if still:
            self._wi(
                db,
                wi,
                WorkItemEvent.rescan_shows_present,
                f"still present in run {run.external_run_id}: {', '.join(sorted(still)[:8])}",
                actor="scanner",
            )
            for f, o in zip(members, outcomes, strict=True):
                if o is ClosingOutcome.still_present:
                    self._finding(
                        db,
                        f,
                        FindingEvent.human_blocked,
                        f"present after merge in run {run.external_run_id}",
                        actor="scanner",
                    )

    def _regressions(
        self,
        db: DbSession,
        run: ScanRun,
        jobs: list[ScanJob],
        sightings: list[Sighting],
        counts: dict[str, int],
    ) -> None:
        assert run.id is not None
        present = self._present_families(db, sightings)
        if not present:
            return
        closed = db.exec(
            select(Finding).where(col(Finding.state).in_(list(CLOSING_FINDING_STATES)))
        ).all()
        for f in closed:
            if family_key(f) not in present:
                continue
            closing_run = db.get(ScanRun, f.closed_by_run_id) if f.closed_by_run_id else None
            validity = validate_closing_run(
                run,
                jobs,
                f,
                merge_sha=closing_run.source_sha if closing_run else None,
                is_ancestor=self._is_ancestor,
                require_policy=False,
            )
            if not validity.valid:
                continue
            if f.state is FindingState.approved_disposition:
                view = sightings_for(f, run, sightings, family_ids=self._family_ids(db, f))
                if all(not v for v in view.policy_present.values()) and view.policy_present:
                    continue  # still suppressed by approved VEX in policy mode: not a regression
            if self._finding(
                db,
                f,
                FindingEvent.reappeared,
                f"present again in run {run.external_run_id}",
                actor="scanner",
                run_id=run.id,
            ):
                counts["regression"] += 1
                wi = db.get(WorkItem, f.work_item_id) if f.work_item_id else None
                if wi is not None and wi.issue_number is not None:
                    self.gh.reopen_issue(self.repo, wi.issue_number)
                    self.gh.comment_issue(
                        self.repo,
                        wi.issue_number,
                        f"Regression: {f.vuln_id} reappeared in run `{run.external_run_id}` @ "
                        f"`{run.source_sha[:12]}`. A new work item will be created.",
                    )
                f.work_item_id = None
                db.add(f)

    def _drift(
        self,
        db: DbSession,
        run: ScanRun,
        jobs: list[ScanJob],
        sightings: list[Sighting],
        counts: dict[str, int],
    ) -> None:
        """Ungrouped findings absent from a valid complete main run close as fixed (db drift)."""
        assert run.id is not None
        present = self._present_families(db, sightings)
        candidates = db.exec(
            select(Finding).where(
                col(Finding.state).in_(
                    [FindingState.open, FindingState.unclassified, FindingState.grouped]
                ),
                col(Finding.last_seen_run_id) != run.id,
            )
        ).all()
        touched_wis: set[int] = set()
        for f in candidates:
            if family_key(f) in present:
                continue
            if f.state is FindingState.grouped and f.work_item_id is not None:
                wi = db.get(WorkItem, f.work_item_id)
                if wi is None or wi.state not in (WorkItemState.queued, WorkItemState.issue_open):
                    continue
                touched_wis.add(f.work_item_id)
            validity = validate_closing_run(
                run, jobs, f, merge_sha=None, is_ancestor=self._is_ancestor, require_policy=False
            )
            if not validity.valid:
                continue
            if self._finding(
                db,
                f,
                FindingEvent.closing_absent,
                f"absent in run {run.external_run_id} (no remediation)",
                actor="scanner",
                run_id=run.id,
            ):
                counts["fixed_by_drift"] += 1
        for wi_id in touched_wis:
            wi = db.get(WorkItem, wi_id)
            if wi is None:
                continue
            members = db.exec(select(Finding).where(Finding.work_item_id == wi_id)).all()
            if issue_may_close([m.state for m in members]):
                self._wi(
                    db,
                    wi,
                    WorkItemEvent.superseded,
                    f"all members absent in run {run.external_run_id}",
                )
                if wi.issue_number is not None:
                    self.gh.comment_issue(
                        self.repo,
                        wi.issue_number,
                        f"All findings absent in run `{run.external_run_id}` before any session "
                        "ran; closing.",
                    )
                    self.gh.close_issue(self.repo, wi.issue_number)

    # ------------------------------------------------------------------ helpers

    def _active_session_count(self, db: DbSession) -> int:
        return len(
            db.exec(
                select(WorkItem).where(col(WorkItem.state).in_(list(ACTIVE_WORK_ITEM_STATES)))
            ).all()
        )

    def _acu_budget_position(self, db: DbSession) -> AcuBudgetPosition:
        """ACUs already consumed by every session ever created, plus the unconsumed remainder of
        the cap of each session bound to an active work item (Devin may still spend up to its
        `max_acu_limit`, and a same-session retry re-opens a finished one). Consumed ACUs are
        counted exactly once."""
        sessions = db.exec(select(Session)).all()
        reserved_ids = {
            w.active_session_id
            for w in db.exec(
                select(WorkItem).where(col(WorkItem.state).in_(list(ACTIVE_WORK_ITEM_STATES)))
            ).all()
            if w.active_session_id is not None
        }
        consumed = float(sum(s.acus_consumed for s in sessions))
        outstanding = float(
            sum(
                max(0.0, s.max_acu_limit - s.acus_consumed)
                for s in sessions
                if s.devin_id in reserved_ids
            )
        )
        return AcuBudgetPosition(consumed=consumed, outstanding=outstanding)

    def reconcile_sessions(self) -> list[str]:
        """Compare Devin's `hl`-tagged sessions with ours; report strangers, never adopt blindly."""
        remote = self.devin.list_sessions(tags=[SESSION_TAG])
        with session_scope(self.engine) as db:
            known = {s.devin_id for s in db.exec(select(Session)).all()}
        return sorted(s.session_id for s in remote if s.session_id not in known)


def _blockable() -> set[tuple[WorkItemState, WorkItemEvent]]:
    from hardening_loop.orchestrator.state import WORK_ITEM_TRANSITIONS

    return {k for k in WORK_ITEM_TRANSITIONS if k[1] is WorkItemEvent.blocked}


__all__ = ["Clock", "Orchestrator", "Severity", "SystemClock", "TickReport"]
