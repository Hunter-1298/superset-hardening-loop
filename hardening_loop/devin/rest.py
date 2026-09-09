"""Live Devin v3 client (service-user bearer token, organization-scoped endpoints).

Endpoints, from the published v3 OpenAPI document:

    POST /v3/organizations/{org_id}/sessions                     -> SessionResponse
    GET  /v3/organizations/{org_id}/sessions                     -> Paginated[SessionResponse]
    GET  /v3/organizations/{org_id}/sessions/{devin_id}          -> SessionResponse
    POST /v3/organizations/{org_id}/sessions/{devin_id}/messages -> SessionResponse
    GET  /v3/organizations/{org_id}/sessions/{devin_id}/messages -> Paginated[SessionMessage]
    POST /v3/organizations/{org_id}/attachments  (multipart)     -> AttachmentResponse
    POST /v3/organizations/{org_id}/pr-reviews                   -> PrReviewResponse
    GET  /v3/organizations/{org_id}/pr-reviews?pr_url&commit_sha -> PrReviewResponse | 404
    GET  /v3/organizations/{org_id}/playbooks                    -> Paginated[PlaybookResponse]
    POST /v3/organizations/{org_id}/playbooks                    -> PlaybookResponse
    PUT  /v3/organizations/{org_id}/playbooks/{playbook_id}      -> PlaybookResponse
    GET  /v3/organizations/{org_id}/knowledge/notes              -> Paginated[KnowledgeNoteResponse]
    POST /v3/organizations/{org_id}/knowledge/notes              -> KnowledgeNoteResponse
    PUT  /v3/organizations/{org_id}/knowledge/notes/{note_id}    -> KnowledgeNoteResponse

Responses are parsed into `SessionSnapshot`, whose enums reject unknown `status`/`status_detail`
values, so an API change surfaces as an error the orchestrator turns into `needs_human` rather than
a silently coerced state. The API key never appears in logs or error messages."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any

import httpx
from pydantic import BaseModel, SecretStr, ValidationError

from hardening_loop.devin.enums import SessionSnapshot
from hardening_loop.devin.protocol import (
    CreateSessionRequest,
    NoteRecord,
    NoteUpsert,
    PlaybookRecord,
    PlaybookUpsert,
    ReviewSnapshot,
)

RETRY_STATUSES = frozenset({429, 502, 503, 504})
PAGE_SIZE = 100
MAX_PAGES = 20


class DevinError(RuntimeError):
    pass


class DevinRest:
    def __init__(
        self,
        api_key: SecretStr,
        org_id: str,
        *,
        api_base: str = "https://api.devin.ai/v3",
        timeout: float = 60.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if not org_id.startswith("org-"):
            raise DevinError(f"organization id must start with 'org-', got {org_id[:8]!r}")
        self._org = org_id
        self._sleep = sleep
        self._client = httpx.Client(
            base_url=api_base.rstrip("/"),
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {api_key.get_secret_value()}",
                "Accept": "application/json",
                "User-Agent": "superset-hardening-loop",
            },
        )

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ protocol

    def create_session(self, request: CreateSessionRequest) -> SessionSnapshot:
        body: dict[str, Any] = {
            "prompt": request.prompt,
            "title": request.title,
            "tags": list(request.tags),
            "max_acu_limit": round(request.max_acu_limit),
            "repos": list(request.repos),
            "structured_output_schema": request.structured_output_schema,
            "structured_output_required": request.structured_output_required,
            "resumable": request.resumable,
        }
        if request.playbook_id:
            body["playbook_id"] = request.playbook_id
        if request.knowledge_ids:
            body["knowledge_ids"] = list(request.knowledge_ids)
        if request.attachment_urls:
            body["attachment_urls"] = list(request.attachment_urls)
        data = self._request("POST", f"/organizations/{self._org}/sessions", json=body).json()
        return _snapshot(data)

    def get_session(self, session_id: str) -> SessionSnapshot:
        data = self._request("GET", f"/organizations/{self._org}/sessions/{session_id}").json()
        return _snapshot(data)

    def send_message(self, session_id: str, message: str) -> None:
        self._request(
            "POST",
            f"/organizations/{self._org}/sessions/{session_id}/messages",
            json={"message": message},
        )

    def terminate_session(self, session_id: str) -> SessionSnapshot:
        """`DELETE .../sessions/{id}`: permanently stops the session (it cannot be resumed) and
        returns its final `SessionResponse`, ACUs included."""
        data = self._request("DELETE", f"/organizations/{self._org}/sessions/{session_id}").json()
        return _snapshot(data)

    def list_sessions(self, *, tags: list[str]) -> list[SessionSnapshot]:
        """All sessions carrying every tag in `tags` (the `SessionsQueryParams.tags` filter),
        following `end_cursor` pagination."""
        out: list[SessionSnapshot] = []
        params: dict[str, Any] = {"tags": list(tags), "first": PAGE_SIZE}
        for _ in range(MAX_PAGES):
            data = self._request(
                "GET", f"/organizations/{self._org}/sessions", params=params
            ).json()
            for item in data.get("items", []):
                snap = _snapshot(item)
                if set(tags) <= set(snap.tags):
                    out.append(snap)
            if not data.get("has_next_page") or not data.get("end_cursor"):
                return out
            params["after"] = data["end_cursor"]
        raise DevinError(f"list_sessions(tags={tags}): more than {MAX_PAGES} pages")

    def upload_attachment(self, filename: str, content: bytes) -> str:
        data = self._request(
            "POST",
            f"/organizations/{self._org}/attachments",
            files={"file": (filename, content, "application/octet-stream")},
        ).json()
        url = data.get("url")
        if not isinstance(url, str) or not url:
            raise DevinError("attachment upload returned no url")
        return url

    def last_user_facing_question(self, session_id: str) -> str | None:
        """Most recent message Devin wrote to the user, if any (what a `waiting_for_user`
        session is asking). Message `source` values other than the user's own count as Devin."""
        params: dict[str, Any] = {"first": PAGE_SIZE}
        latest: tuple[int, str] | None = None
        for _ in range(MAX_PAGES):
            data = self._request(
                "GET", f"/organizations/{self._org}/sessions/{session_id}/messages", params=params
            ).json()
            for item in data.get("items", []):
                source = str(item.get("source", "")).lower()
                text = str(item.get("message", "")).strip()
                if source in ("user", "api", "service_user") or not text:
                    continue
                stamp = int(item.get("created_at") or 0)
                if latest is None or stamp >= latest[0]:
                    latest = (stamp, text)
            if not data.get("has_next_page") or not data.get("end_cursor"):
                break
            params["after"] = data["end_cursor"]
        return latest[1] if latest else None

    def trigger_review(self, pr_url: str) -> ReviewSnapshot:
        """Ask for a Devin Review of the PR. The API always reviews the PR's *current* head; the
        caller compares `commit_sha` with the head it meant and treats a difference as a push."""
        data = self._request(
            "POST", f"/organizations/{self._org}/pr-reviews", json={"pr_url": pr_url}
        ).json()
        return _review(data)

    def get_review(self, pr_url: str, commit_sha: str) -> ReviewSnapshot | None:
        """Latest review of exactly `commit_sha`; `None` when Devin has never reviewed that commit
        (the documented 404)."""
        resp = self._request(
            "GET",
            f"/organizations/{self._org}/pr-reviews",
            params={"pr_url": pr_url, "commit_sha": commit_sha},
            allow_404=True,
        )
        if resp.status_code == 404:
            return None
        return _review(resp.json())

    # ------------------------------------------------------------------ assets

    def list_playbooks(self) -> list[PlaybookRecord]:
        return [
            _parse(PlaybookRecord, item)
            for item in self._pages(f"/organizations/{self._org}/playbooks")
        ]

    def create_playbook(self, spec: PlaybookUpsert) -> PlaybookRecord:
        data = self._request(
            "POST", f"/organizations/{self._org}/playbooks", json=spec.model_dump()
        ).json()
        return _parse(PlaybookRecord, data)

    def update_playbook(self, playbook_id: str, spec: PlaybookUpsert) -> PlaybookRecord:
        data = self._request(
            "PUT", f"/organizations/{self._org}/playbooks/{playbook_id}", json=spec.model_dump()
        ).json()
        return _parse(PlaybookRecord, data)

    def list_notes(self) -> list[NoteRecord]:
        return [
            _parse(NoteRecord, item)
            for item in self._pages(f"/organizations/{self._org}/knowledge/notes")
        ]

    def create_note(self, spec: NoteUpsert) -> NoteRecord:
        data = self._request(
            "POST", f"/organizations/{self._org}/knowledge/notes", json=spec.model_dump()
        ).json()
        return _parse(NoteRecord, data)

    def update_note(self, note_id: str, spec: NoteUpsert) -> NoteRecord:
        data = self._request(
            "PUT", f"/organizations/{self._org}/knowledge/notes/{note_id}", json=spec.model_dump()
        ).json()
        return _parse(NoteRecord, data)

    def _pages(self, path: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        params: dict[str, Any] = {"first": PAGE_SIZE}
        for _ in range(MAX_PAGES):
            data = self._request("GET", path, params=params).json()
            out.extend(data.get("items", []))
            if not data.get("has_next_page") or not data.get("end_cursor"):
                return out
            params["after"] = data["end_cursor"]
        raise DevinError(f"GET {path}: more than {MAX_PAGES} pages")

    # ------------------------------------------------------------------ transport

    def _request(
        self, method: str, path: str, *, allow_404: bool = False, **kwargs: Any
    ) -> httpx.Response:
        resp: httpx.Response | None = None
        for attempt in range(4):
            try:
                resp = self._client.request(method, path, **kwargs)
            except httpx.TransportError as exc:
                if attempt == 3:
                    raise DevinError(f"{method} {path}: {exc.__class__.__name__}") from None
                self._sleep(2**attempt)
                continue
            if resp.status_code in RETRY_STATUSES and attempt < 3:
                self._sleep(2**attempt)
                continue
            if resp.status_code == 404 and allow_404:
                return resp
            if resp.status_code >= 400:
                raise DevinError(f"{method} {path} -> {resp.status_code}: {_problem(resp)}")
            return resp
        assert resp is not None
        raise DevinError(f"{method} {path}: gave up after retries ({resp.status_code})")


def _problem(resp: httpx.Response) -> str:
    """RFC 9457 `detail`/`title` when present; never echoes headers."""
    try:
        data = resp.json()
    except ValueError:
        return resp.text[:300]
    if isinstance(data, dict):
        return str(data.get("detail") or data.get("title") or data)[:300]
    return str(data)[:300]


def _snapshot(data: dict[str, Any]) -> SessionSnapshot:
    try:
        return SessionSnapshot.model_validate(data)
    except ValidationError as exc:
        raise DevinError(f"unexpected SessionResponse shape: {exc.errors()[:3]}") from None


def _review(data: dict[str, Any]) -> ReviewSnapshot:
    return _parse(ReviewSnapshot, data)


def _parse[M: BaseModel](model: type[M], data: dict[str, Any]) -> M:
    try:
        return model.model_validate(data)
    except ValidationError as exc:
        raise DevinError(f"unexpected {model.__name__} shape: {exc.errors()[:3]}") from None


__all__ = ["DevinError", "DevinRest"]
