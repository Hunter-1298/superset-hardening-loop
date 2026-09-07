"""Settings: environment only. Secrets never appear in source, logs, or the database."""

from __future__ import annotations

from pathlib import Path

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

from hardening_loop.domain.enums import GateMode

FORK_REPO = "Hunter-1298/superset"
CONTROLLER_REPO = "Hunter-1298/superset-hardening-loop"
REPO_ALLOWLIST: frozenset[str] = frozenset({FORK_REPO, CONTROLLER_REPO})
UPSTREAM_REPO = "apache/superset"  # never a target; used only to assert we never touch it
REMEDIATION_BRANCH = "main"
COMPARISON_BRANCH = "upstream-master"
BASELINE_SHA = "c83fb2bb1dcfac41ac51bcebd82471f4a7180d18"

SYFT_VERSION = "1.45.1"
TRIVY_VERSION = "0.71.2"
GRYPE_VERSION = "0.114.0"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HL_", env_file=None, extra="ignore")

    data_dir: Path = Path("./data")
    database_file: str = "hardening_loop.sqlite3"
    evidence_dir_name: str = "evidence"

    devin_api_key: SecretStr | None = None
    devin_org_id: str = "org-ff8ed4605fbc4d098dc203a6c53b3ae9"
    devin_api_base: str = "https://api.devin.ai/v3"

    github_token: SecretStr | None = None
    github_api_base: str = "https://api.github.com"

    fork_repo: str = FORK_REPO
    remediation_branch: str = REMEDIATION_BRANCH

    scan_gate_mode: GateMode = GateMode.report
    max_concurrent_sessions: int = Field(default=2, ge=1)
    global_acu_budget: float = Field(default=60.0, gt=0)
    retries_per_work_item: int = Field(default=2, ge=0)
    session_wall_clock_max_hours: float = Field(default=3.0, gt=0)
    poll_interval_seconds: int = Field(default=60, ge=5)
    review_timeout_minutes: int = Field(default=30, ge=1)
    acu_cost_usd: float | None = None
    approver_logins: list[str] = ["Hunter-1298"]
    devin_review_status_context: str | None = None  # discovered by `doctor`, never assumed

    replay_mode: bool = False

    @property
    def database_path(self) -> Path:
        return self.data_dir / self.database_file

    @property
    def evidence_dir(self) -> Path:
        return self.data_dir / self.evidence_dir_name

    @property
    def secret_values(self) -> list[str]:
        values: list[str] = []
        for secret in (self.devin_api_key, self.github_token):
            if secret is not None and secret.get_secret_value():
                values.append(secret.get_secret_value())
        return values


def assert_repo_allowed(repo: str) -> None:
    if repo not in REPO_ALLOWLIST:
        raise PermissionError(
            f"repository {repo!r} is not in the allowlist {sorted(REPO_ALLOWLIST)}"
        )
