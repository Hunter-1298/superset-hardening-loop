"""Typed domain enums shared by the whole controller."""

from __future__ import annotations

from enum import IntEnum, StrEnum


class Scanner(StrEnum):
    trivy = "trivy"
    grype = "grype"


class ScanMode(StrEnum):
    raw = "raw"
    policy = "policy"


class GateMode(StrEnum):
    report = "report"
    enforce = "enforce"


class ImageTarget(StrEnum):
    lean = "lean"
    ci = "ci"


class Severity(StrEnum):
    critical = "CRITICAL"
    high = "HIGH"
    medium = "MEDIUM"
    low = "LOW"
    unknown = "UNKNOWN"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    @classmethod
    def parse(cls, raw: str | None) -> Severity:
        if raw is None:
            return cls.unknown
        try:
            return cls(raw.upper())
        except ValueError:
            # Grype uses "Negligible"; Trivy uses "UNKNOWN".
            return cls.low if raw.lower() == "negligible" else cls.unknown


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.unknown: 0,
    Severity.low: 1,
    Severity.medium: 2,
    Severity.high: 3,
    Severity.critical: 4,
}

DISPATCH_DEFAULT_SEVERITIES: frozenset[Severity] = frozenset({Severity.high, Severity.critical})


class Layer(StrEnum):
    python = "python"
    os = "os"
    binary = "binary"
    dockerfile = "dockerfile"
    helm = "helm"
    compose = "compose"


class Ecosystem(StrEnum):
    pypi = "pypi"
    deb = "deb"
    npm = "npm"
    golang = "golang"
    binary = "binary"
    config = "config"
    unknown = "unknown"


# Ecosystems each pinned scanner can match vulnerabilities for. A finding is "comparable" (kind 4
# candidate) only when its ecosystem is supported by BOTH scanners. `binary` is Syft/Grype's
# classifier for interpreters such as CPython (pkg:generic/python); Trivy has no equivalent.
SCANNER_ECOSYSTEMS: dict[Scanner, frozenset[Ecosystem]] = {
    Scanner.trivy: frozenset({Ecosystem.pypi, Ecosystem.deb, Ecosystem.npm, Ecosystem.golang}),
    Scanner.grype: frozenset(
        {Ecosystem.pypi, Ecosystem.deb, Ecosystem.npm, Ecosystem.golang, Ecosystem.binary}
    ),
}


class Kind(IntEnum):
    """The five work kinds, numbered as in the brief."""

    dependency_upgrade = 1
    no_fix_reachability = 2
    container_hardening = 3
    scanner_disagreement = 4
    helm_deploy_config = 5

    @property
    def slug(self) -> str:
        return self.name

    @property
    def acu_cap(self) -> int:
        return ACU_CAPS[self]

    @property
    def playbook_slug(self) -> str:
        return PLAYBOOK_SLUGS[self]


ACU_CAPS: dict[Kind, int] = {
    Kind.dependency_upgrade: 5,
    Kind.no_fix_reachability: 8,
    Kind.container_hardening: 20,
    Kind.scanner_disagreement: 3,
    Kind.helm_deploy_config: 6,
}

PLAYBOOK_SLUGS: dict[Kind, str] = {
    Kind.dependency_upgrade: "pb-dependency-upgrade",
    Kind.no_fix_reachability: "pb-no-fix-openvex",
    Kind.container_hardening: "pb-container-hardening",
    Kind.scanner_disagreement: "pb-scanner-disagreement",
    Kind.helm_deploy_config: "pb-helm-security",
}


class Risk(StrEnum):
    normal = "normal"
    high = "high"


class FindingState(StrEnum):
    open = "open"
    unclassified = "unclassified"
    grouped = "grouped"
    in_remediation = "in_remediation"
    awaiting_rescan = "awaiting_rescan"
    fixed = "fixed"
    approved_disposition = "approved_disposition"
    scanner_disagreement_resolved = "scanner_disagreement_resolved"
    regression = "regression"
    human_blocked = "human_blocked"


CLOSING_FINDING_STATES: frozenset[FindingState] = frozenset(
    {
        FindingState.fixed,
        FindingState.approved_disposition,
        FindingState.scanner_disagreement_resolved,
    }
)


class WorkItemState(StrEnum):
    queued = "queued"
    issue_open = "issue_open"
    dispatching = "dispatching"
    session_active = "session_active"
    pr_open = "pr_open"
    checks_running = "checks_running"
    checks_failed = "checks_failed"
    review_pending = "review_pending"
    ready_for_human = "ready_for_human"
    merged = "merged"
    awaiting_rescan = "awaiting_rescan"
    verified = "verified"
    needs_human = "needs_human"
    abandoned = "abandoned"
    failed = "failed"


ACTIVE_WORK_ITEM_STATES: frozenset[WorkItemState] = frozenset(
    {
        WorkItemState.dispatching,
        WorkItemState.session_active,
        WorkItemState.pr_open,
        WorkItemState.checks_running,
        WorkItemState.checks_failed,
        WorkItemState.review_pending,
    }
)

TERMINAL_WORK_ITEM_STATES: frozenset[WorkItemState] = frozenset(
    {WorkItemState.verified, WorkItemState.abandoned}
)


class LifecycleLevel(IntEnum):
    """How far a work item's fix has travelled: PR -> CI -> review -> approval -> merge -> rescan.
    This is workflow progress, not test depth; see `VerificationDepth` for the latter."""

    none = 0
    pr_opened = 1
    ci_green = 2
    review_completed = 3
    human_approved = 4
    merged = 5
    rescan_verified = 6

    @property
    def label(self) -> str:
        return self.name


class VerificationDepth(IntEnum):
    """How deeply a PR head has been exercised. Each rung is earned only by complete, passing
    evidence for that head (GitHub check runs on the fork); Devin's own test claims never raise
    it. Rungs are independent: a head may hold L4 while L3 is `partial` because one of its
    components has no check on this repo."""

    requirements_pip = 0
    import_migrations = 1
    targeted_unit = 2
    immutable_image_runtime = 3
    db_subset = 4
    playwright = 5
    canary = 6

    @property
    def label(self) -> str:
        return f"L{int(self)} {_DEPTH_TITLES[self]}"

    @property
    def title(self) -> str:
        return _DEPTH_TITLES[self]


_DEPTH_TITLES: dict[VerificationDepth, str] = {
    VerificationDepth.requirements_pip: "requirements + pip",
    VerificationDepth.import_migrations: "import + migrations",
    VerificationDepth.targeted_unit: "targeted + unit tests",
    VerificationDepth.immutable_image_runtime: "immutable-image runtime",
    VerificationDepth.db_subset: "database subset",
    VerificationDepth.playwright: "Playwright",
    VerificationDepth.canary: "canary",
}


class CheckStatus(StrEnum):
    """Status of one verification check (or of one whole depth rung) on one PR head."""

    pending = "pending"  # a matching check run exists and has not completed
    passed = "passed"
    failed = "failed"
    partial = "partial"  # rung only: every available component passed, some are unavailable
    unavailable = "unavailable"  # no check produced evidence on this head (missing or skipped)


class CheckSource(StrEnum):
    github_check = "github_check"  # GitHub check run on the fork; the only source that counts
    ladder = "ladder"  # a rung component with no check on this repo, recorded as unavailable
    devin_claim = "devin_claim"  # `tests_run` from Devin's structured output; informational


class ScanRunStatus(StrEnum):
    complete = "complete"
    incomplete = "incomplete"
    failed = "failed"


class Trigger(StrEnum):
    push = "push"
    pull_request = "pull_request"
    schedule = "schedule"
    workflow_dispatch = "workflow_dispatch"
    replay = "replay"
    fixture = "fixture"


CLOSING_TRIGGERS: frozenset[Trigger] = frozenset(
    {Trigger.push, Trigger.schedule, Trigger.workflow_dispatch, Trigger.replay, Trigger.fixture}
)


class HumanLabel(StrEnum):
    needs_human = "needs-human"
    dispatch_approved = "dispatch:approved"
    disposition_approved = "disposition:approved"
    disagreement_resolved = "disagreement:resolved"
    retry = "retry"
    verify_no_change = "verify-no-change"
