"""Ordered, disjoint classification of normalized findings into the five kinds.

    1. deployment configuration (helm / compose)               -> kind 5
    2. comparable finding reported by exactly one scanner       -> kind 4
    3. Python (PyPI) vulnerability with any fixed version       -> kind 1 (bound-blocked: high risk)
    4. vulnerability with no fixed version from any reporter    -> kind 2
    5. fixable OS / binary / runtime finding, Dockerfile config -> kind 3
    6. anything else                                            -> unclassified (never dispatched)

The first matching rule wins; the trace records the rule that matched and why others did not apply.
"""

from __future__ import annotations

import logging
import tomllib
from dataclasses import dataclass, field

from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from hardening_loop.domain.enums import (
    SCANNER_ECOSYSTEMS,
    Ecosystem,
    Kind,
    Layer,
    Risk,
    Scanner,
)
from hardening_loop.ingest.normalize import NormalizedFinding

NO_FIX_STATES: frozenset[str] = frozenset(
    {"affected", "will_not_fix", "wont-fix", "fix_deferred", "end_of_life", "not-fixed", "unknown"}
)
_UPPER_BOUND_OPS = ("<", "<=", "==", "~=", "===")
log = logging.getLogger(__name__)


@dataclass(frozen=True)
class ClassificationContext:
    """What the classifier needs to know about the run, beyond the finding itself."""

    scanner_job_success: dict[Scanner, bool]
    upper_bounds: dict[str, SpecifierSet] = field(default_factory=dict)  # normalized name -> spec


@dataclass(frozen=True)
class Classification:
    kind: Kind | None
    risk: Risk = Risk.normal
    bound_blocked: bool = False
    trace: str = ""
    unclassified_reason: str | None = None

    @property
    def is_unclassified(self) -> bool:
        return self.kind is None


def parse_upper_bounds(pyproject_text: str) -> dict[str, SpecifierSet]:
    """Direct dependency specifiers from pyproject.toml [project] (deps + all extras)."""
    data = tomllib.loads(pyproject_text)
    project = data.get("project") or {}
    reqs: list[str] = list(project.get("dependencies") or [])
    for extra in (project.get("optional-dependencies") or {}).values():
        reqs.extend(extra)
    bounds: dict[str, SpecifierSet] = {}
    for raw in reqs:
        try:
            req = Requirement(raw)
        except InvalidRequirement:
            log.warning("skipping unparsable requirement %r", raw)
            continue
        name = req.name.replace("_", "-").replace(".", "-").lower()
        if any(s.operator in _UPPER_BOUND_OPS for s in req.specifier):
            existing = bounds.get(name)
            bounds[name] = existing & req.specifier if existing else req.specifier
    return bounds


def _fix_allowed_by_bounds(fix_versions: list[str], spec: SpecifierSet) -> bool:
    for fv in fix_versions:
        try:
            if spec.contains(Version(fv), prereleases=False):
                return True
        except (InvalidVersion, InvalidSpecifier):
            continue
    return False


def _comparable(f: NormalizedFinding) -> bool:
    return not f.is_config and all(
        f.ecosystem in SCANNER_ECOSYSTEMS[s] for s in (Scanner.trivy, Scanner.grype)
    )


def _no_fix_from_every_reporter(f: NormalizedFinding) -> bool:
    if f.has_fix:
        return False
    states = f.fix_state_by_scanner.values()
    return bool(states) and all(s in NO_FIX_STATES or s == "" for s in states)


def classify(f: NormalizedFinding, ctx: ClassificationContext) -> Classification:
    trace: list[str] = []

    # Rule 1: deployment configuration.
    if f.is_config and f.layer in (Layer.helm, Layer.compose):
        return Classification(Kind.helm_deploy_config, trace=f"r1:config layer={f.layer}")
    trace.append("r1:no(not helm/compose config)")

    # Rule 2: scanner disagreement.
    if _comparable(f) and len(f.reported_by) == 1:
        (reporter,) = f.reported_by
        other = Scanner.grype if reporter is Scanner.trivy else Scanner.trivy
        other_ok = ctx.scanner_job_success.get(other, False)
        if other_ok:
            return Classification(
                Kind.scanner_disagreement,
                trace=";".join([*trace, f"r2:only {reporter}, {other} job succeeded"]),
            )
        trace.append(f"r2:no({other} job did not succeed; not a disagreement)")
    else:
        trace.append("r2:no(not comparable or reported by both)")

    # Rule 3: fixable Python dependency.
    if not f.is_config and f.ecosystem is Ecosystem.pypi and f.has_fix:
        spec = ctx.upper_bounds.get(f.pkg_name or "")
        if spec is not None and not _fix_allowed_by_bounds(f.all_fix_versions, spec):
            return Classification(
                Kind.dependency_upgrade,
                risk=Risk.high,
                bound_blocked=True,
                trace=";".join([*trace, f"r3:pypi fix {f.all_fix_versions} blocked by {spec}"]),
            )
        return Classification(
            Kind.dependency_upgrade, trace=";".join([*trace, f"r3:pypi fix {f.all_fix_versions}"])
        )
    trace.append("r3:no(not fixable pypi)")

    # Rule 4: genuinely no fixed version.
    if not f.is_config and _no_fix_from_every_reporter(f):
        return Classification(
            Kind.no_fix_reachability,
            trace=";".join([*trace, f"r4:no fix states={f.fix_state_by_scanner}"]),
        )
    trace.append("r4:no(some reporter has a fix or unknown state)")

    # Rule 5: fixable OS / binary / runtime, or Dockerfile configuration.
    if f.is_config and f.layer is Layer.dockerfile:
        return Classification(
            Kind.container_hardening, trace=";".join([*trace, "r5:dockerfile config"])
        )
    if (
        not f.is_config
        and f.ecosystem in (Ecosystem.deb, Ecosystem.binary, Ecosystem.npm, Ecosystem.golang)
        and f.has_fix
    ):
        return Classification(
            Kind.container_hardening,
            trace=";".join([*trace, f"r5:{f.ecosystem} fix {f.all_fix_versions}"]),
        )
    trace.append("r5:no(not fixable os/binary or dockerfile)")

    reason = _unclassified_reason(f)
    return Classification(None, trace=";".join(trace), unclassified_reason=reason)


def _unclassified_reason(f: NormalizedFinding) -> str:
    if f.ecosystem is Ecosystem.unknown:
        return "unknown_ecosystem"
    if f.is_config:
        return f"config_layer_unsupported:{f.layer}"
    if not f.reported_by:
        return "no_reporter"
    if f.has_fix:
        return f"fixable_but_unsupported_ecosystem:{f.ecosystem}"
    return f"fix_state_inconsistent:{f.fix_state_by_scanner}"
