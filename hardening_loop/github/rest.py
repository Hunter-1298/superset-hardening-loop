"""Thin, allowlisted GitHub REST wrapper over httpx.

Only the endpoints the operator-triggered negative suite needs live here for now; the full
`GitHubClient` protocol implementation for live orchestration builds on the same `_request`.
Every call refuses repositories outside `REPO_ALLOWLIST`, so nothing can ever reach apache/superset.
"""

from __future__ import annotations

import io
import time
import zipfile
from pathlib import Path
from typing import Any

import httpx
from pydantic import SecretStr

from hardening_loop.config import REPO_ALLOWLIST
from hardening_loop.github.protocol import CheckRun, PullRequestInfo


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
    ) -> None:
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
        for attempt in range(4):
            resp = self._client.request(method, path, **kwargs)
            if resp.status_code in (502, 503, 504) or (
                resp.status_code == 403 and resp.headers.get("x-ratelimit-remaining") == "0"
            ):
                time.sleep(2**attempt)
                continue
            if resp.status_code >= 400:
                raise GitHubError(f"{method} {path} -> {resp.status_code}: {resp.text[:500]}")
            return resp
        raise GitHubError(f"{method} {path}: gave up after retries ({resp.status_code})")

    # ---- refs / branches
    def branch_head(self, repo: str, branch: str) -> str:
        _assert_allowed(repo)
        data = self._request("GET", f"/repos/{repo}/git/ref/heads/{branch}").json()
        return str(data["object"]["sha"])

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

    def close_pull_request(self, repo: str, number: int) -> None:
        _assert_allowed(repo)
        self._request("PATCH", f"/repos/{repo}/pulls/{number}", json={"state": "closed"})

    def comment_issue(self, repo: str, number: int, body: str) -> None:
        _assert_allowed(repo)
        self._request("POST", f"/repos/{repo}/issues/{number}/comments", json={"body": body})

    # ---- checks / actions
    def list_check_runs(self, repo: str, sha: str) -> list[CheckRun]:
        _assert_allowed(repo)
        runs: list[CheckRun] = []
        page = 1
        while True:
            data = self._request(
                "GET",
                f"/repos/{repo}/commits/{sha}/check-runs",
                params={"per_page": 100, "page": page},
            ).json()
            for cr in data.get("check_runs", []):
                runs.append(
                    CheckRun(
                        name=str(cr["name"]),
                        status=str(cr["status"]),
                        conclusion=cr.get("conclusion"),
                        url=cr.get("html_url"),
                    )
                )
            if len(data.get("check_runs", [])) < 100:
                return runs
            page += 1

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
    )


__all__ = ["GitHubError", "GitHubRest"]
