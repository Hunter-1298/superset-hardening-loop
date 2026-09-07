"""In-memory Devin v3 double. Scenarios set each session's state explicitly; the orchestrator only
sees `SessionSnapshot`s. Records every message and every create request (prompt, cap, tags)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hardening_loop.devin.enums import (
    DevinStatus,
    DevinStatusDetail,
    SessionPullRequest,
    SessionSnapshot,
)
from hardening_loop.devin.protocol import CreateSessionRequest


class FakeDevinError(RuntimeError):
    pass


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


class FakeDevin:
    def __init__(self) -> None:
        self.sessions: dict[str, _Session] = {}
        self.attachments: dict[str, bytes] = {}
        self.calls: list[tuple[str, str]] = []
        self._n = 0
        self.fail_next: dict[str, Exception] = {}
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

    def created_requests(self) -> list[CreateSessionRequest]:
        return [s.request for s in self.sessions.values() if s.request.prompt != "(pre-existing)"]

    # ------------------------------------------------------------- protocol

    def _touch(self, method: str, target: str) -> None:
        self.calls.append((method, target))
        exc = self.fail_next.pop(method, None)
        if exc is not None:
            raise exc

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
