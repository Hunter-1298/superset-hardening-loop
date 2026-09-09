"""Devin v3 client protocol: sessions, messages, attachments, PR reviews. Live and fake share it."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any, Protocol

from pydantic import BaseModel, ConfigDict, Field

from hardening_loop.devin.enums import SessionSnapshot


class CreateSessionRequest(BaseModel):
    """Body of `POST /v3/organizations/{org}/sessions` (only the fields we use)."""

    model_config = ConfigDict(frozen=True)

    prompt: str
    repos: list[str]
    title: str
    tags: list[str]
    max_acu_limit: float
    structured_output_schema: dict[str, Any]
    structured_output_required: bool = True
    playbook_id: str | None = None
    knowledge_ids: list[str] = Field(default_factory=list)
    attachment_urls: list[str] = Field(default_factory=list)
    resumable: bool = True


class ReviewStatus(StrEnum):
    """`PrReviewResponse.status` from the v3 OpenAPI document, verbatim."""

    pending = "pending"
    running = "running"
    completed = "completed"
    errored = "errored"
    cancelled = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (ReviewStatus.completed, ReviewStatus.errored, ReviewStatus.cancelled)


class ReviewSnapshot(BaseModel):
    """`PrReviewResponse`: what Devin says about the review of one PR head. It carries no verdict
    and no findings count; the review's comments live on the PR, so "completed" means only that
    Devin finished looking at exactly `commit_sha`."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    status: ReviewStatus
    repo_path: str
    pr_number: int
    commit_sha: str
    created_at: datetime


class PlaybookUpsert(BaseModel):
    """Body of `POST`/`PUT .../playbooks`: exactly the fields the API compares."""

    model_config = ConfigDict(frozen=True)

    title: str
    body: str
    macro: str | None = None
    structured_output_schema: dict[str, Any] | None = None


class PlaybookRecord(BaseModel):
    """`PlaybookResponse` (the fields the syncer reads)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    playbook_id: str
    title: str
    body: str
    macro: str | None = None
    structured_output_schema: dict[str, Any] | None = None

    def matches(self, want: PlaybookUpsert) -> bool:
        return (
            self.title == want.title
            and self.body == want.body
            and (self.macro or None) == (want.macro or None)
            and (self.structured_output_schema or None) == (want.structured_output_schema or None)
        )


class NoteUpsert(BaseModel):
    """Body of `POST`/`PUT .../knowledge/notes`."""

    model_config = ConfigDict(frozen=True)

    name: str
    body: str
    trigger: str
    pinned_repo: str | None = None
    is_enabled: bool = True


class NoteRecord(BaseModel):
    """`KnowledgeNoteResponse` (the fields the syncer reads)."""

    model_config = ConfigDict(frozen=True, extra="ignore")

    note_id: str
    name: str
    body: str
    trigger: str
    pinned_repo: str | None = None
    is_enabled: bool = True

    def matches(self, want: NoteUpsert) -> bool:
        return (
            self.name == want.name
            and self.body == want.body
            and self.trigger == want.trigger
            and (self.pinned_repo or None) == (want.pinned_repo or None)
            and self.is_enabled == want.is_enabled
        )


class DevinClient(Protocol):
    def create_session(self, request: CreateSessionRequest) -> SessionSnapshot: ...
    def get_session(self, session_id: str) -> SessionSnapshot: ...
    def send_message(self, session_id: str, message: str) -> None: ...
    def terminate_session(self, session_id: str) -> SessionSnapshot: ...
    def list_sessions(self, *, tags: list[str]) -> list[SessionSnapshot]: ...
    def upload_attachment(self, filename: str, content: bytes) -> str: ...
    def last_user_facing_question(self, session_id: str) -> str | None: ...
    def trigger_review(self, pr_url: str) -> ReviewSnapshot: ...
    def get_review(self, pr_url: str, commit_sha: str) -> ReviewSnapshot | None: ...
    def list_playbooks(self) -> list[PlaybookRecord]: ...
    def create_playbook(self, spec: PlaybookUpsert) -> PlaybookRecord: ...
    def update_playbook(self, playbook_id: str, spec: PlaybookUpsert) -> PlaybookRecord: ...
    def list_notes(self) -> list[NoteRecord]: ...
    def create_note(self, spec: NoteUpsert) -> NoteRecord: ...
    def update_note(self, note_id: str, spec: NoteUpsert) -> NoteRecord: ...
