"""Allowlisted GitHub REST client over httpx: the live `GitHubClient` for orchestration plus the
workflow/artifact helpers the operator-triggered negative suite uses.

Every call refuses repositories outside `REPO_ALLOWLIST`, so nothing can ever reach apache/superset;
`pull_request_from_url` applies the same rule to URLs Devin reports. The token never appears in
logs or error messages.
"""

from __future__ import annotations

import base64
import io
import time
import zipfile
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from pydantic import SecretStr

from hardening_loop.config import REPO_ALLOWLIST
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
from hardening_loop.orchestrator.policy import parse_pr_url

PER_PAGE = 100
MAX_PAGES = 30


class GitHubError(RuntimeError):
    pass


def _assert_allowed(repo: str) -> None:
    if repo not in REPO_ALLOWLIST:
        raise GitHubError(f"refusing to touch {repo!r}: not in {sorted(REPO_ALLOWLIST)}")


class GitHubRest:
    def __init__(
        self,
        token: SecretStr,
        *,
        api_base: str = "https://api.github.com",
        timeout: float = 30.0,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._sleep = sleep
        self._client = httpx.Client(
            base_url=api_base,
            timeout=timeout,
            transport=transport,
            headers={
                "Authorization": f"Bearer {token.get_secret_value()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "superset-hardening-loop",
            },
        )

    def close(self) -> None:
        self._client.close()

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        resp: httpx.Response | None = None
        for attempt in range(4):
            try:
                resp = self._client.request(method, path, **kwargs)
            except httpx.TransportError as exc:
                if attempt == 3:
                    raise GitHubError(f"{method} {path}: {exc.__class__.__name__}") from None
                self._sleep(2**attempt)
                continue
            if attempt < 3 and (
                resp.status_code in (502, 503, 504)
                or (
                    resp.status_code in (403, 429)
                    and resp.headers.get("x-ratelimit-remaining") == "0"
                )
            ):
                self._sleep(2**attempt)
                continue
            if resp.status_code >= 400:
                raise GitHubError(f"{method} {path} -> {resp.status_code}: {resp.text[:500]}")
            return resp
        assert resp is not None
        raise GitHubError(f"{method} {path}: gave up after retries ({resp.status_code})")

    def _paginate(self, path: str, *, key: str | None = None, **params: Any) -> list[Any]:
        items: list[Any] = []
        for page in range(1, MAX_PAGES + 1):
            data = self._request(
                "GET", path, params={**params, "per_page": PER_PAGE, "page": page}
            ).json()
            batch = data.get(key, []) if key else data
            items.extend(batch)
            if len(batch) < PER_PAGE:
                return items
        raise GitHubError(f"GET {path}: more than {MAX_PAGES} pages")

    # ---- issues
    def create_issue(self, repo: str, title: str, body: str, labels: list[str]) -> Issue:
        _assert_allowed(repo)
        data = self._request(
            "POST",
            f"/repos/{repo}/issues",
            json={"title": title, "body": body, "labels": labels},
        ).json()
        return _issue(repo, data)

    def get_issue(self, repo: str, number: int) -> Issue:
        _assert_allowed(repo)
        return _issue(repo, self._request("GET", f"/repos/{repo}/issues/{number}").json())

    def add_labels(self, repo: str, number: int, labels: list[str]) -> None:
        _assert_allowed(repo)
        self._request("POST", f"/repos/{repo}/issues/{number}/labels", json={"labels": labels})

    def remove_label(self, repo: str, number: int, label: str) -> None:
        _assert_allowed(repo)
        resp = self._client.delete(f"/repos/{repo}/issues/{number}/labels/{label}")
        if resp.status_code not in (200, 404):
            raise GitHubError(f"remove label {label!r} -> {resp.status_code}: {resp.text[:300]}")

    def close_issue(self, repo: str, number: int) -> None:
        _assert_allowed(repo)
        self._request(
            "PATCH",
            f"/repos/{repo}/issues/{number}",
            json={"state": "closed", "state_reason": "completed"},
        )

    def reopen_issue(self, repo: str, number: int) -> None:
        _assert_allowed(repo)
        self._request("PATCH", f"/repos/{repo}/issues/{number}", json={"state": "open"})

    def find_issues(self, repo: str, *, label: str, state: str) -> list[Issue]:
        _assert_allowed(repo)
        rows = self._paginate(f"/repos/{repo}/issues", labels=label, state=state)
        return [_issue(repo, row) for row in rows if "pull_request" not in row]

    # ---- refs / branches
    def branch_head(self, repo: str, branch: str) -> str:
        _assert_allowed(repo)
        data = self._request("GET", f"/repos/{repo}/git/ref/heads/{branch}").json()
        return str(data["object"]["sha"])

    def compare(self, repo: str, base: str, head: str) -> Compare:
        _assert_allowed(repo)
        data = self._request(
            "GET", f"/repos/{repo}/compare/{base}...{head}", params={"per_page": 1}
        ).json()
        return Compare(
            status=str(data["status"]),
            ahead_by=int(data.get("ahead_by", 0)),
            behind_by=int(data.get("behind_by", 0)),
        )

    def get_file(self, repo: str, path: str, ref: str) -> BranchFile | None:
        _assert_allowed(repo)
        resp = self._client.get(f"/repos/{repo}/contents/{path}", params={"ref": ref})
        if resp.status_code == 404:
            return None
        if resp.status_code >= 400:
            raise GitHubError(f"GET contents {path}@{ref} -> {resp.status_code}")
        data = resp.json()
        if not isinstance(data, dict) or data.get("type") != "file":
            return None
        if data.get("encoding") == "base64" and data.get("content"):
            content = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        else:
            content = self._request(
                "GET",
                f"/repos/{repo}/contents/{path}",
                params={"ref": ref},
                headers={"Accept": "application/vnd.github.raw+json"},
            ).text
        return BranchFile(path=path, sha=str(data["sha"]), content=content)

    def delete_branch(self, repo: str, branch: str) -> None:
        _assert_allowed(repo)
        resp = self._client.delete(f"/repos/{repo}/git/refs/heads/{branch}")
        if resp.status_code not in (204, 404, 422):
            raise GitHubError(f"delete branch {branch} -> {resp.status_code}: {resp.text[:300]}")

    # ---- pull requests
    def create_pull_request(
        self, repo: str, *, title: str, body: str, head: str, base: str, draft: bool
    ) -> PullRequestInfo:
        _assert_allowed(repo)
        data = self._request(
            "POST",
            f"/repos/{repo}/pulls",
            json={"title": title, "body": body, "head": head, "base": base, "draft": draft},
        ).json()
        return _pr(repo, data)

    def get_pull_request(self, repo: str, number: int) -> PullRequestInfo:
        _assert_allowed(repo)
        return _pr(repo, self._request("GET", f"/repos/{repo}/pulls/{number}").json())

    def pull_request_from_url(self, url: str) -> PullRequestInfo:
        parsed = parse_pr_url(url)
        if parsed is None:
            raise GitHubError(f"not a GitHub pull request url: {url[:200]!r}")
        repo, number = parsed
        _assert_allowed(repo)
        return self.get_pull_request(repo, number)

    def close_pull_request(self, repo: str, number: int) -> None:
        _assert_allowed(repo)
        self._request("PATCH", f"/repos/{repo}/pulls/{number}", json={"state": "closed"})

    def list_pr_files(self, repo: str, number: int) -> list[DiffFile]:
        _assert_allowed(repo)
        return [
            DiffFile(
                filename=str(f["filename"]),
                status=str(f["status"]),
                previous_filename=f.get("previous_filename"),
            )
            for f in self._paginate(f"/repos/{repo}/pulls/{number}/files")
        ]

    def list_pr_reviews(self, repo: str, number: int) -> list[Review]:
        _assert_allowed(repo)
        return [
            Review(
                author=str((r.get("user") or {}).get("login") or ""),
                state=str(r["state"]),
                commit_sha=str(r.get("commit_id") or ""),
                submitted_at=_ts(r.get("submitted_at")),
            )
            for r in self._paginate(f"/repos/{repo}/pulls/{number}/reviews")
        ]

    def comment_issue(self, repo: str, number: int, body: str) -> None:
        _assert_allowed(repo)
        self._request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})

    def comment_pull_request(self, repo: str, number: int, body: str) -> None:
        self.comment_issue(repo, number, body)

    # ---- checks / actions
    def list_check_runs(self, repo: str, sha: str) -> list[CheckRun]:
        _assert_allowed(repo)
        return [
            CheckRun(
                name=str(cr["name"]),
                status=str(cr["status"]),
                conclusion=cr.get("conclusion"),
                url=cr.get("html_url"),
            )
            for cr in self._paginate(f"/repos/{repo}/commits/{sha}/check-runs", key="check_runs")
        ]

    def list_commit_statuses(self, repo: str, sha: str) -> list[CommitStatus]:
        """Latest status per context (what the combined-status endpoint reports)."""
        _assert_allowed(repo)
        out: list[CommitStatus] = []
        for page in range(1, MAX_PAGES + 1):
            data = self._request(
                "GET",
                f"/repos/{repo}/commits/{sha}/status",
                params={"per_page": PER_PAGE, "page": page},
            ).json()
            batch = data.get("statuses", [])
            out.extend(
                CommitStatus(
                    context=str(s["context"]),
                    state=str(s["state"]),
                    description=s.get("description"),
                    target_url=s.get("target_url"),
                )
                for s in batch
            )
            if len(batch) < PER_PAGE:
                return out
        raise GitHubError(f"statuses for {sha}: more than {MAX_PAGES} pages")

    def list_workflow_runs(
        self,
        repo: str,
        workflow_file: str,
        *,
        head_sha: str | None = None,
        branch: str | None = None,
    ) -> list[dict[str, Any]]:
        _assert_allowed(repo)
        params: dict[str, Any] = {"per_page": 20}
        if head_sha:
            params["head_sha"] = head_sha
        if branch:
            params["branch"] = branch
        data = self._request(
            "GET", f"/repos/{repo}/actions/workflows/{workflow_file}/runs", params=params
        ).json()
        return list(data.get("workflow_runs", []))

    def list_run_artifacts(self, repo: str, run_id: int) -> list[dict[str, Any]]:
        _assert_allowed(repo)
        data = self._request(
            "GET", f"/repos/{repo}/actions/runs/{run_id}/artifacts", params={"per_page": 100}
        ).json()
        return list(data.get("artifacts", []))

    def download_artifact(self, repo: str, artifact_id: int, dest: Path) -> Path:
        """Download and unzip one artifact into `dest`; returns `dest`."""
        _assert_allowed(repo)
        resp = self._request(
            "GET", f"/repos/{repo}/actions/artifacts/{artifact_id}/zip", follow_redirects=True
        )
        dest.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if not target.is_relative_to(dest.resolve()):
                    raise GitHubError(f"artifact member escapes destination: {member.filename}")
            zf.extractall(dest)
        return dest


def _ts(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _issue(repo: str, data: dict[str, Any]) -> Issue:
    labels = frozenset(
        str(lb["name"]) if isinstance(lb, dict) else str(lb) for lb in data.get("labels", [])
    )
    return Issue(
        repo=repo,
        number=int(data["number"]),
        url=str(data["html_url"]),
        title=str(data["title"]),
        state=str(data["state"]),
        labels=labels,
    )


def _pr(repo: str, data: dict[str, Any]) -> PullRequestInfo:
    return PullRequestInfo(
        repo=repo,
        number=int(data["number"]),
        url=str(data["html_url"]),
        title=str(data["title"]),
        state=str(data["state"]),
        merged=bool(data.get("merged", False)),
        merge_commit_sha=data.get("merge_commit_sha"),
        base_ref=str(data["base"]["ref"]),
        head_ref=str(data["head"]["ref"]),
        head_repo=str((data["head"].get("repo") or {}).get("full_name") or repo),
        head_sha=str(data["head"]["sha"]),
        author=str((data.get("user") or {}).get("login") or ""),
        merged_at=_ts(data.get("merged_at")),
    )


__all__ = ["GitHubError", "GitHubRest"]
