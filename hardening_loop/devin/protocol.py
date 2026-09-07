"""Devin v3 client protocol (sessions, messages, attachments). Live and fake share it."""

from __future__ import annotations

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


class DevinClient(Protocol):
    def create_session(self, request: CreateSessionRequest) -> SessionSnapshot: ...
    def get_session(self, session_id: str) -> SessionSnapshot: ...
    def send_message(self, session_id: str, message: str) -> None: ...
    def list_sessions(self, *, tags: list[str]) -> list[SessionSnapshot]: ...
    def upload_attachment(self, filename: str, content: bytes) -> str: ...
    def last_user_facing_question(self, session_id: str) -> str | None: ...
