"""GitHub client protocol. Live and fake implementations share this surface so the orchestrator
never knows which one it talks to."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, ConfigDict, Field


class Issue(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo: str
    number: int
    url: str
    title: str
    state: str  # open | closed
    labels: frozenset[str] = frozenset()


class PullRequestInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    repo: str
    number: int
    url: str
    title: str
    state: str  # open | closed
    merged: bool
    merge_commit_sha: str | None
    base_ref: str
    head_ref: str
    head_repo: str
    head_sha: str
    author: str
    merged_at: datetime | None = None


class CheckRun(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    status: str  # queued | in_progress | completed
    conclusion: str | None  # success | failure | neutral | cancelled | timed_out | action_required
    url: str | None = None


class CommitStatus(BaseModel):
    model_config = ConfigDict(frozen=True)

    context: str
    state: str  # pending | success | failure | error
    description: str | None = None
    target_url: str | None = None


class Review(BaseModel):
    model_config = ConfigDict(frozen=True)

    author: str
    state: str  # APPROVED | CHANGES_REQUESTED | COMMENTED | DISMISSED
    commit_sha: str
    submitted_at: datetime | None = None


class Compare(BaseModel):
    """`GET /repos/{o}/{r}/compare/{base}...{head}` status."""

    model_config = ConfigDict(frozen=True)

    status: str  # identical | ahead | behind | diverged
    ahead_by: int = 0
    behind_by: int = 0


class DiffFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    filename: str
    status: str  # added | removed | modified | renamed
    previous_filename: str | None = None


class BranchFile(BaseModel):
    model_config = ConfigDict(frozen=True)

    path: str
    sha: str
    content: str = Field(repr=False)


class WorkflowRunInfo(BaseModel):
    """One `GET /repos/{o}/{r}/actions/workflows/{file}/runs` entry."""

    model_config = ConfigDict(frozen=True)

    id: int
    run_attempt: int
    event: str
    status: str  # queued | in_progress | completed | ...
    conclusion: str | None  # success | failure | cancelled | ... (None until completed)
    head_branch: str | None
    head_sha: str
    url: str
    updated_at: datetime | None = None


class ArtifactInfo(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: int
    name: str
    size_in_bytes: int
    expired: bool = False
    digest: str | None = None  # GitHub's reported artifact digest, when present


class GitHubClient(Protocol):
    """Everything the orchestrator needs from GitHub. Every call is repo-allowlisted."""

    # issues
    def create_issue(self, repo: str, title: str, body: str, labels: list[str]) -> Issue: ...
    def get_issue(self, repo: str, number: int) -> Issue: ...
    def comment_issue(self, repo: str, number: int, body: str) -> None: ...
    def add_labels(self, repo: str, number: int, labels: list[str]) -> None: ...
    def remove_label(self, repo: str, number: int, label: str) -> None: ...
    def close_issue(self, repo: str, number: int) -> None: ...
    def reopen_issue(self, repo: str, number: int) -> None: ...
    def find_issues(self, repo: str, *, label: str, state: str) -> list[Issue]: ...

    # pull requests
    def get_pull_request(self, repo: str, number: int) -> PullRequestInfo: ...
    def pull_request_from_url(self, url: str) -> PullRequestInfo: ...
    def list_pr_files(self, repo: str, number: int) -> list[DiffFile]: ...
    def list_pr_reviews(self, repo: str, number: int) -> list[Review]: ...
    def comment_pull_request(self, repo: str, number: int, body: str) -> None: ...

    # commits
    def list_check_runs(self, repo: str, sha: str) -> list[CheckRun]: ...
    def list_commit_statuses(self, repo: str, sha: str) -> list[CommitStatus]: ...
    def compare(self, repo: str, base: str, head: str) -> Compare: ...
    def get_file(self, repo: str, path: str, ref: str) -> BranchFile | None: ...
    def branch_head(self, repo: str, branch: str) -> str: ...

    # workflow runs and their evidence artifacts
    def list_workflow_runs(
        self,
        repo: str,
        workflow_file: str,
        *,
        head_sha: str | None = None,
        branch: str | None = None,
        status: str | None = None,
    ) -> Iterator[WorkflowRunInfo]:
        """Newest first; pages are fetched lazily as the iterator is consumed."""
        ...

    def list_run_artifacts(self, repo: str, run_id: int) -> list[ArtifactInfo]: ...
    def download_artifact(self, repo: str, artifact_id: int, dest: Path) -> Path: ...
