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


class DevinClient(Protocol):
    def create_session(self, request: CreateSessionRequest) -> SessionSnapshot: ...
    def get_session(self, session_id: str) -> SessionSnapshot: ...
    def send_message(self, session_id: str, message: str) -> None: ...
    def list_sessions(self, *, tags: list[str]) -> list[SessionSnapshot]: ...
    def upload_attachment(self, filename: str, content: bytes) -> str: ...
    def last_user_facing_question(self, session_id: str) -> str | None: ...
    def trigger_review(self, pr_url: str) -> ReviewSnapshot: ...
    def get_review(self, pr_url: str, commit_sha: str) -> ReviewSnapshot | None: ...
