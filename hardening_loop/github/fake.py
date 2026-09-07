"""In-memory GitHub + CI double for no-spend replay and tests.

Scenarios script it directly (`open_pr`, `set_checks`, `approve`, `merge`, `label`) and the
orchestrator observes the results through the `GitHubClient` protocol only. Every call is logged so
tests can assert which operations happened and that nothing left the allowlisted repos.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from hardening_loop.config import FORK_REPO, REMEDIATION_BRANCH, assert_repo_allowed
from hardening_loop.github.protocol import (
    BranchFile,
    CheckRun,
    CommitStatus,
    Compare,
    DiffFile,
    Issue,
    PullRequestInfo,
    Review,
)


class FakeGitHubError(RuntimeError):
    pass


@dataclass
class _Issue:
    number: int
    title: str
    body: str
    labels: set[str]
    state: str = "open"
    comments: list[str] = field(default_factory=list)


@dataclass
class _PR:
    number: int
    title: str
    base_ref: str
    head_ref: str
    head_sha: str
    author: str
    files: list[DiffFile]
    state: str = "open"
    merged: bool = False
    merge_commit_sha: str | None = None
    merged_at: datetime | None = None
    reviews: list[Review] = field(default_factory=list)
    comments: list[str] = field(default_factory=list)
    head_repo: str = FORK_REPO


class FakeGitHub:
    def __init__(self, *, repo: str = FORK_REPO, main_head: str) -> None:
        assert_repo_allowed(repo)
        self.repo = repo
        self.calls: list[tuple[str, str]] = []  # (method, target)
        self.issues: dict[int, _Issue] = {}
        self.prs: dict[int, _PR] = {}
        self.checks: dict[str, list[CheckRun]] = {}
        self.statuses: dict[str, list[CommitStatus]] = {}
        self.files: dict[tuple[str, str], BranchFile] = {}
        self.parents: dict[str, str | None] = {main_head: None}  # commit -> parent
        self.branches: dict[str, str] = {REMEDIATION_BRANCH: main_head}
        self._next_issue = 100
        self._next_pr = 500
        self.fail_next: dict[str, Exception] = {}

    # ------------------------------------------------------------- scripting API (scenarios)

    def add_commit(self, sha: str, parent: str) -> None:
        if parent not in self.parents:
            raise FakeGitHubError(f"unknown parent {parent}")
        self.parents[sha] = parent

    def open_pr(
        self,
        *,
        title: str,
        head_ref: str,
        head_sha: str,
        files: list[str],
        base_ref: str = REMEDIATION_BRANCH,
        author: str = "devin-ai-integration[bot]",
        head_repo: str = FORK_REPO,
        parent: str | None = None,
    ) -> str:
        self.add_commit(head_sha, parent or self.branches[REMEDIATION_BRANCH])
        n = self._next_pr
        self._next_pr += 1
        self.prs[n] = _PR(
            number=n,
            title=title,
            base_ref=base_ref,
            head_ref=head_ref,
            head_sha=head_sha,
            author=author,
            files=[DiffFile(filename=f, status="modified") for f in files],
            head_repo=head_repo,
        )
        return f"https://github.com/{self.repo}/pull/{n}"

    def push(self, number: int, new_sha: str) -> None:
        pr = self.prs[number]
        self.add_commit(new_sha, pr.head_sha)
        pr.head_sha = new_sha

    def set_checks(self, sha: str, results: dict[str, str | None]) -> None:
        """`{"security-scan": "success", "app-runs": None}` (None = still running)."""
        self.checks[sha] = [
            CheckRun(
                name=name,
                status="completed" if conclusion is not None else "in_progress",
                conclusion=conclusion,
                url=f"https://github.com/{self.repo}/actions/runs/{abs(hash((sha, name))) % 10**6}",
            )
            for name, conclusion in results.items()
        ]

    def set_status(self, sha: str, context: str, state: str, description: str = "") -> None:
        others = [s for s in self.statuses.get(sha, []) if s.context != context]
        self.statuses[sha] = [
            *others,
            CommitStatus(context=context, state=state, description=description),
        ]

    def approve(self, number: int, login: str, *, at: datetime | None = None) -> None:
        pr = self.prs[number]
        pr.reviews.append(
            Review(author=login, state="APPROVED", commit_sha=pr.head_sha, submitted_at=at)
        )

    def merge(self, number: int, merge_sha: str, *, at: datetime | None = None) -> str:
        pr = self.prs[number]
        if pr.state != "open":
            raise FakeGitHubError("PR not open")
        self.add_commit(merge_sha, self.branches[REMEDIATION_BRANCH])
        # merge commit descends from both main head and the PR head
        self.parents[f"{merge_sha}~pr"] = pr.head_sha
        self.branches[REMEDIATION_BRANCH] = merge_sha
        pr.state = "closed"
        pr.merged = True
        pr.merge_commit_sha = merge_sha
        pr.merged_at = at
        return merge_sha

    def close_pr(self, number: int) -> None:
        self.prs[number].state = "closed"

    def label(self, number: int, *labels: str) -> None:
        self.issues[number].labels.update(labels)

    def unlabel(self, number: int, label: str) -> None:
        self.issues[number].labels.discard(label)

    def human_close_issue(self, number: int) -> None:
        self.issues[number].state = "closed"

    def put_file(self, path: str, ref: str, content: str) -> None:
        self.files[(path, ref)] = BranchFile(
            path=path, sha=f"blob-{abs(hash(content))}", content=content
        )

    def open_issue_numbers(self) -> list[int]:
        return sorted(n for n, i in self.issues.items() if i.state == "open")

    # ------------------------------------------------------------- protocol

    def _touch(self, method: str, repo: str, target: str = "") -> None:
        assert_repo_allowed(repo)
        if repo != self.repo:
            raise FakeGitHubError(f"fake only serves {self.repo}, got {repo}")
        self.calls.append((method, target))
        exc = self.fail_next.pop(method, None)
        if exc is not None:
            raise exc

    def create_issue(self, repo: str, title: str, body: str, labels: list[str]) -> Issue:
        self._touch("create_issue", repo, title)
        n = self._next_issue
        self._next_issue += 1
        self.issues[n] = _Issue(number=n, title=title, body=body, labels=set(labels))
        return self.get_issue(repo, n)

    def get_issue(self, repo: str, number: int) -> Issue:
        self._touch("get_issue", repo, str(number))
        i = self.issues[number]
        return Issue(
            repo=repo,
            number=number,
            url=f"https://github.com/{repo}/issues/{number}",
            title=i.title,
            state=i.state,
            labels=frozenset(i.labels),
        )

    def comment_issue(self, repo: str, number: int, body: str) -> None:
        self._touch("comment_issue", repo, str(number))
        self.issues[number].comments.append(body)

    def add_labels(self, repo: str, number: int, labels: list[str]) -> None:
        self._touch("add_labels", repo, str(number))
        self.issues[number].labels.update(labels)

    def remove_label(self, repo: str, number: int, label: str) -> None:
        self._touch("remove_label", repo, str(number))
        self.issues[number].labels.discard(label)

    def close_issue(self, repo: str, number: int) -> None:
        self._touch("close_issue", repo, str(number))
        self.issues[number].state = "closed"

    def reopen_issue(self, repo: str, number: int) -> None:
        self._touch("reopen_issue", repo, str(number))
        self.issues[number].state = "open"

    def find_issues(self, repo: str, *, label: str, state: str) -> list[Issue]:
        self._touch("find_issues", repo, label)
        return [
            self.get_issue(repo, n)
            for n, i in sorted(self.issues.items())
            if label in i.labels and (state == "all" or i.state == state)
        ]

    def get_pull_request(self, repo: str, number: int) -> PullRequestInfo:
        self._touch("get_pull_request", repo, str(number))
        pr = self.prs[number]
        return PullRequestInfo(
            repo=repo,
            number=number,
            url=f"https://github.com/{repo}/pull/{number}",
            title=pr.title,
            state=pr.state,
            merged=pr.merged,
            merge_commit_sha=pr.merge_commit_sha,
            base_ref=pr.base_ref,
            head_ref=pr.head_ref,
            head_repo=pr.head_repo,
            head_sha=pr.head_sha,
            author=pr.author,
            merged_at=pr.merged_at,
        )

    def pull_request_from_url(self, url: str) -> PullRequestInfo:
        prefix = f"https://github.com/{self.repo}/pull/"
        if not url.startswith(prefix):
            raise FakeGitHubError(f"foreign PR url {url}")
        return self.get_pull_request(self.repo, int(url[len(prefix) :].rstrip("/")))

    def list_pr_files(self, repo: str, number: int) -> list[DiffFile]:
        self._touch("list_pr_files", repo, str(number))
        return list(self.prs[number].files)

    def list_pr_reviews(self, repo: str, number: int) -> list[Review]:
        self._touch("list_pr_reviews", repo, str(number))
        return list(self.prs[number].reviews)

    def comment_pull_request(self, repo: str, number: int, body: str) -> None:
        self._touch("comment_pull_request", repo, str(number))
        self.prs[number].comments.append(body)

    def list_check_runs(self, repo: str, sha: str) -> list[CheckRun]:
        self._touch("list_check_runs", repo, sha)
        return list(self.checks.get(sha, []))

    def list_commit_statuses(self, repo: str, sha: str) -> list[CommitStatus]:
        self._touch("list_commit_statuses", repo, sha)
        return list(self.statuses.get(sha, []))

    def compare(self, repo: str, base: str, head: str) -> Compare:
        self._touch("compare", repo, f"{base}...{head}")
        if base == head:
            return Compare(status="identical")
        if self._descends(head, base):
            return Compare(status="ahead", ahead_by=1)
        if self._descends(base, head):
            return Compare(status="behind", behind_by=1)
        return Compare(status="diverged", ahead_by=1, behind_by=1)

    def _descends(self, node: str, ancestor: str) -> bool:
        seen: set[str] = set()
        stack = [node]
        while stack:
            cur = stack.pop()
            if cur == ancestor:
                return True
            if cur in seen:
                continue
            seen.add(cur)
            p = self.parents.get(cur)
            if p is not None:
                stack.append(p)
            extra = self.parents.get(f"{cur}~pr")
            if extra is not None:
                stack.append(extra)
        return False

    def get_file(self, repo: str, path: str, ref: str) -> BranchFile | None:
        self._touch("get_file", repo, f"{ref}:{path}")
        return self.files.get((path, ref))

    def branch_head(self, repo: str, branch: str) -> str:
        self._touch("branch_head", repo, branch)
        return self.branches[branch]

    # ------------------------------------------------------------- assertions

    WRITE_METHODS = frozenset(
        {
            "create_issue",
            "comment_issue",
            "add_labels",
            "remove_label",
            "close_issue",
            "reopen_issue",
            "comment_pull_request",
        }
    )

    def write_calls(self) -> list[tuple[str, str]]:
        return [c for c in self.calls if c[0] in self.WRITE_METHODS]

    def never_merged_or_approved(self) -> bool:
        """The controller has no merge/approve method at all; this documents the invariant."""
        return not any(m in ("merge_pull_request", "approve_pull_request") for m, _ in self.calls)
