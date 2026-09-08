"""PR diff policy: which files a remediation PR of each kind may touch."""

from __future__ import annotations

from hardening_loop.domain.enums import Kind
from hardening_loop.github.protocol import DiffFile
from hardening_loop.orchestrator.policy import diff_policy_violations

PINS = ["requirements/base.txt", "requirements/development.txt"]


def _files(*names: str) -> list[DiffFile]:
    return [DiffFile(filename=n, status="modified") for n in names]


def test_dependency_upgrade_may_regenerate_pins_within_the_declared_range() -> None:
    assert diff_policy_violations(_files(*PINS), Kind.dependency_upgrade) == []
    assert diff_policy_violations(_files("pyproject.toml", *PINS), Kind.dependency_upgrade) == []
    assert (
        diff_policy_violations(_files("requirements/base.in", *PINS), Kind.dependency_upgrade) == []
    )


def test_other_kinds_may_not_change_generated_pins_alone() -> None:
    for kind in (Kind.container_hardening, Kind.helm_deploy_config):
        [violation] = diff_policy_violations(_files(*PINS), kind)
        assert violation.startswith("generated requirements changed without pyproject.toml/*.in")
        assert diff_policy_violations(_files("pyproject.toml", *PINS), kind) == []


def test_suppressions_and_protected_paths_are_refused_for_every_kind() -> None:
    for kind in Kind:
        found = diff_policy_violations(
            _files(".trivyignore", ".github/workflows/security-scan.yml", *PINS), kind
        )
        assert any(v.startswith("scanner ignore file") for v in found)
        assert any(v.startswith("protected CI path modified") for v in found)
