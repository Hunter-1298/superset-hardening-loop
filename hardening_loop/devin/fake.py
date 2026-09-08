"""In-memory Devin v3 double. Scenarios set each session's state explicitly; the orchestrator only
sees `SessionSnapshot`s. Records every message and every create request (prompt, cap, tags)."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hardening_loop.devin.enums import (
    DevinStatus,
    DevinStatusDetail,
    SessionPullRequest,
    SessionSnapshot,
)
from hardening_loop.devin.protocol import (
    CreateSessionRequest,
    NoteRecord,
    NoteUpsert,
    PlaybookRecord,
    PlaybookUpsert,
    ReviewSnapshot,
    ReviewStatus,
)


class FakeDevinError(RuntimeError):
    pass


class ControllerCrash(BaseException):
    """Simulated process death. Deliberately not an `Exception` so the orchestrator's error
    handling cannot catch it: whatever was committed stays, everything else is lost."""


@dataclass
class _Session:
    session_id: str
    request: CreateSessionRequest
    status: DevinStatus = DevinStatus.new
    status_detail: DevinStatusDetail | None = None
    acus_consumed: float = 0.0
    structured_output: dict[str, Any] | None = None
    pull_requests: list[str] = field(default_factory=list)
    messages: list[str] = field(default_factory=list)
    question: str | None = None
    created_at: int = 0
    updated_at: int = 0


@dataclass
class _Review:
    pr_url: str
    commit_sha: str
    status: ReviewStatus
    created_at: int


class FakeDevin:
    def __init__(self) -> None:
        self.sessions: dict[str, _Session] = {}
        self.attachments: dict[str, bytes] = {}
        self.calls: list[tuple[str, str]] = []
        self._n = 0
        # Reviews always target the PR's current head; the double learns heads from scenarios,
        # either pinned per URL or through a resolver (the replay world points it at FakeGitHub).
        self.pr_heads: dict[str, str] = {}
        self.head_resolver: Callable[[str], str | None] | None = None
        self.reviews: dict[tuple[str, str], _Review] = {}
        self.playbooks: dict[str, PlaybookRecord] = {}
        self.notes: dict[str, NoteRecord] = {}
        self.fail_next: dict[str, Exception] = {}
        # Methods that kill the controller before running / after taking effect (once each).
        self.crash_before: set[str] = set()
        self.crash_after: set[str] = set()
        # method -> callback run once, before that method's next call (scenarios use it to make
        # something happen "while" the controller is talking to Devin).
        self.before_next: dict[str, Callable[[], None]] = {}
        self.clock_seconds = 1_800_000_000

    # ------------------------------------------------------------- scripting API

    def set_state(
        self,
        session_id: str,
        status: DevinStatus,
        detail: DevinStatusDetail | None = None,
        *,
        acus: float | None = None,
        output: dict[str, Any] | None = None,
        pull_requests: list[str] | None = None,
        question: str | None = None,
    ) -> None:
        s = self.sessions[session_id]
        s.status = status
        s.status_detail = detail
        if acus is not None:
            s.acus_consumed = acus
        if output is not None:
            s.structured_output = output
        if pull_requests is not None:
            s.pull_requests = pull_requests
        s.question = question
        self.clock_seconds += 60
        s.updated_at = self.clock_seconds

    def finish(
        self, session_id: str, output: dict[str, Any], *, acus: float, pull_requests: list[str]
    ) -> None:
        self.set_state(
            session_id,
            DevinStatus.exit,
            DevinStatusDetail.finished,
            acus=acus,
            output=output,
            pull_requests=pull_requests,
        )

    def preexisting(self, session_id: str, tags: list[str], *, acus: float = 0.5) -> None:
        """A session that exists at Devin but not in our DB (crash mid-dispatch)."""
        req = CreateSessionRequest(
            prompt="(pre-existing)",
            repos=[],
            title="pre-existing",
            tags=tags,
            max_acu_limit=5,
            structured_output_schema={},
        )
        self.sessions[session_id] = _Session(
            session_id=session_id,
            request=req,
            status=DevinStatus.running,
            status_detail=DevinStatusDetail.working,
            acus_consumed=acus,
        )

    def set_pr_head(self, pr_url: str, commit_sha: str) -> None:
        self.pr_heads[pr_url] = commit_sha

    def review_status(self, pr_url: str, commit_sha: str) -> ReviewStatus | None:
        r = self.reviews.get((pr_url, commit_sha))
        return r.status if r else None

    def finish_review(
        self, pr_url: str, commit_sha: str, status: ReviewStatus = ReviewStatus.completed
    ) -> None:
        """Move a triggered review to a terminal state. A review the controller never asked for
        cannot finish: that catches an orchestrator that skips the trigger."""
        r = self.reviews.get((pr_url, commit_sha))
        if r is None:
            raise FakeDevinError(f"no review was triggered for {pr_url}@{commit_sha[:12]}")
        r.status = status

    def created_requests(self) -> list[CreateSessionRequest]:
        return [s.request for s in self.sessions.values() if s.request.prompt != "(pre-existing)"]

    # ------------------------------------------------------------- protocol

    def _touch(self, method: str, target: str) -> None:
        self.calls.append((method, target))
        hook = self.before_next.pop(method, None)
        if hook is not None:
            hook()
        if method in self.crash_before:
            self.crash_before.discard(method)
            raise ControllerCrash(f"before {method}")
        exc = self.fail_next.pop(method, None)
        if exc is not None:
            raise exc

    def _crash_after(self, method: str) -> None:
        if method in self.crash_after:
            self.crash_after.discard(method)
            raise ControllerCrash(f"after {method}")

    def _snap(self, s: _Session) -> SessionSnapshot:
        return SessionSnapshot(
            session_id=s.session_id,
            url=f"https://app.devin.ai/sessions/{s.session_id.removeprefix('devin-')}",
            status=s.status,
            status_detail=s.status_detail,
            acus_consumed=s.acus_consumed,
            pull_requests=[SessionPullRequest(pr_url=u) for u in s.pull_requests],
            structured_output=s.structured_output,
            tags=list(s.request.tags),
            created_at=s.created_at,
            updated_at=s.updated_at,
        )

    def create_session(self, request: CreateSessionRequest) -> SessionSnapshot:
        self._touch("create_session", request.title)
        if request.max_acu_limit <= 0:
            raise FakeDevinError("max_acu_limit must be positive")
        if not request.structured_output_schema:
            raise FakeDevinError("structured_output_schema required")
        self._n += 1
        sid = f"devin-fake{self._n:04d}"
        self.clock_seconds += 60
        self.sessions[sid] = _Session(
            session_id=sid,
            request=request,
            created_at=self.clock_seconds,
            updated_at=self.clock_seconds,
        )
        self._crash_after("create_session")
        return self._snap(self.sessions[sid])

    def get_session(self, session_id: str) -> SessionSnapshot:
        self._touch("get_session", session_id)
        return self._snap(self.sessions[session_id])

    def send_message(self, session_id: str, message: str) -> None:
        self._touch("send_message", session_id)
        s = self.sessions[session_id]
        s.messages.append(message)
        if s.status is DevinStatus.suspended or s.status is DevinStatus.exit:
            # v3 auto-resumes on message
            s.status = DevinStatus.resuming
            s.status_detail = DevinStatusDetail.working
        elif s.status_detail is DevinStatusDetail.waiting_for_user:
            s.status_detail = DevinStatusDetail.working
            s.question = None

    def list_sessions(self, *, tags: list[str]) -> list[SessionSnapshot]:
        self._touch("list_sessions", ",".join(tags))
        want = set(tags)
        return [self._snap(s) for s in self.sessions.values() if want <= set(s.request.tags)]

    def upload_attachment(self, filename: str, content: bytes) -> str:
        self._touch("upload_attachment", filename)
        url = f"https://attachments.fake.devin/{len(self.attachments) + 1}/{filename}"
        self.attachments[url] = content
        return url

    def last_user_facing_question(self, session_id: str) -> str | None:
        self._touch("last_user_facing_question", session_id)
        return self.sessions[session_id].question

    def trigger_review(self, pr_url: str) -> ReviewSnapshot:
        self._touch("trigger_review", pr_url)
        head = self.pr_heads.get(pr_url)
        if head is None and self.head_resolver is not None:
            head = self.head_resolver(pr_url)
        if head is None:
            raise FakeDevinError(f"unknown pull request {pr_url}")
        self.clock_seconds += 1
        r = self.reviews.get((pr_url, head))
        if r is None or r.status.is_terminal:
            r = _Review(pr_url, head, ReviewStatus.pending, self.clock_seconds)
            self.reviews[(pr_url, head)] = r
        self._crash_after("trigger_review")
        return self._review_snap(r)

    def get_review(self, pr_url: str, commit_sha: str) -> ReviewSnapshot | None:
        self._touch("get_review", f"{pr_url}@{commit_sha}")
        r = self.reviews.get((pr_url, commit_sha))
        if r is None:
            return None
        if r.status is ReviewStatus.pending:
            r.status = ReviewStatus.running
        return self._review_snap(r)

    # ------------------------------------------------------------- assets

    def list_playbooks(self) -> list[PlaybookRecord]:
        self._touch("list_playbooks", "")
        return list(self.playbooks.values())

    def create_playbook(self, spec: PlaybookUpsert) -> PlaybookRecord:
        self._touch("create_playbook", spec.title)
        if spec.macro and any(p.macro == spec.macro for p in self.playbooks.values()):
            raise FakeDevinError(f"macro {spec.macro} already taken (409)")
        pid = f"playbook-fake{len(self.playbooks) + 1:04d}"
        rec = PlaybookRecord(playbook_id=pid, **spec.model_dump())
        self.playbooks[pid] = rec
        self._crash_after("create_playbook")
        return rec

    def update_playbook(self, playbook_id: str, spec: PlaybookUpsert) -> PlaybookRecord:
        self._touch("update_playbook", playbook_id)
        if playbook_id not in self.playbooks:
            raise FakeDevinError(f"unknown playbook {playbook_id} (404)")
        rec = PlaybookRecord(playbook_id=playbook_id, **spec.model_dump())
        self.playbooks[playbook_id] = rec
        return rec

    def list_notes(self) -> list[NoteRecord]:
        self._touch("list_notes", "")
        return list(self.notes.values())

    def create_note(self, spec: NoteUpsert) -> NoteRecord:
        self._touch("create_note", spec.name)
        nid = f"note-fake{len(self.notes) + 1:04d}"
        rec = NoteRecord(note_id=nid, **spec.model_dump())
        self.notes[nid] = rec
        self._crash_after("create_note")
        return rec

    def update_note(self, note_id: str, spec: NoteUpsert) -> NoteRecord:
        self._touch("update_note", note_id)
        if note_id not in self.notes:
            raise FakeDevinError(f"unknown note {note_id} (404)")
        rec = NoteRecord(note_id=note_id, **spec.model_dump())
        self.notes[note_id] = rec
        return rec

    # The asset store can outlive one process so `assets sync --doubles` behaves like the real org
    # across invocations (second run is a no-op) without any network.

    def save_assets(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "playbooks": [p.model_dump() for p in self.playbooks.values()],
                    "notes": [n.model_dump() for n in self.notes.values()],
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def load_assets(self, path: Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text(encoding="utf-8"))
        self.playbooks = {
            p["playbook_id"]: PlaybookRecord.model_validate(p) for p in data.get("playbooks", [])
        }
        self.notes = {n["note_id"]: NoteRecord.model_validate(n) for n in data.get("notes", [])}

    @staticmethod
    def _review_snap(r: _Review) -> ReviewSnapshot:
        prefix, _, number = r.pr_url.rpartition("/pull/")
        return ReviewSnapshot(
            status=r.status,
            repo_path=prefix.removeprefix("https://"),
            pr_number=int(number),
            commit_sha=r.commit_sha,
            created_at=datetime.fromtimestamp(r.created_at, tz=UTC),
        )
