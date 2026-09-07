"""Group classified findings into WorkItem candidates (one Devin session / PR each)."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from hardening_loop.classify.rules import Classification
from hardening_loop.domain.enums import Ecosystem, Kind, Layer, Risk, Severity
from hardening_loop.ingest.normalize import NormalizedFinding

CONFIG_LAYERS: frozenset[Layer] = frozenset({Layer.dockerfile, Layer.helm, Layer.compose})


def group_key_for(
    kind: Kind | None,
    *,
    pkg_name: str | None,
    ecosystem: Ecosystem,
    layer: Layer,
    dedupe_key: str,
) -> str:
    """Grouping key from plain attributes (shared by normalized findings and DB rows)."""
    is_config = layer in CONFIG_LAYERS
    match kind:
        case Kind.dependency_upgrade:
            return f"pypi:{pkg_name}"
        case Kind.no_fix_reachability:
            return f"nofix:{ecosystem}:{pkg_name}"
        case Kind.container_hardening:
            return "container:dockerfile" if is_config else f"container:{layer}-packages"
        case Kind.scanner_disagreement:
            return f"disagreement:{ecosystem}:{pkg_name}"
        case Kind.helm_deploy_config:
            return f"deploy:{layer}"
        case None:
            return f"unclassified:{dedupe_key}"


def group_key(f: NormalizedFinding, c: Classification) -> str:
    return group_key_for(
        c.kind,
        pkg_name=f.pkg_name,
        ecosystem=f.ecosystem,
        layer=f.layer,
        dedupe_key=f.dedupe_key,
    )


def title_for(
    kind: Kind,
    *,
    vuln_ids: list[str],
    pkg_name: str | None,
    pkg_version: str | None,
    layer: Layer,
) -> str:
    ids = sorted(set(vuln_ids))
    shown = ", ".join(ids[:4]) + (f" (+{len(ids) - 4} more)" if len(ids) > 4 else "")
    is_config = layer in CONFIG_LAYERS
    match kind:
        case Kind.dependency_upgrade:
            return f"Upgrade {pkg_name} {pkg_version}: {shown}"
        case Kind.no_fix_reachability:
            return f"Reachability analysis / OpenVEX for {pkg_name}: {shown}"
        case Kind.container_hardening:
            if is_config:
                return f"Container hardening (Dockerfile): {shown}"
            return f"Container hardening ({layer} packages): {shown}"
        case Kind.scanner_disagreement:
            return f"Scanner disagreement on {pkg_name}: {shown}"
        case Kind.helm_deploy_config:
            return f"Deployment security configuration ({layer}): {shown}"


def group_title(kind: Kind, key: str, members: list[NormalizedFinding]) -> str:
    first = members[0]
    return title_for(
        kind,
        vuln_ids=[m.vuln_id for m in members],
        pkg_name=first.pkg_name,
        pkg_version=first.pkg_version,
        layer=first.layer,
    )


@dataclass
class WorkItemCandidate:
    kind: Kind
    group_key: str
    title: str
    severity: Severity
    risk: Risk
    layer: Layer
    members: list[NormalizedFinding] = field(default_factory=list)

    @property
    def acu_cap(self) -> int:
        return self.kind.acu_cap


def group_findings(
    classified: list[tuple[NormalizedFinding, Classification]],
) -> tuple[list[WorkItemCandidate], list[tuple[NormalizedFinding, Classification]]]:
    """Returns (candidates, unclassified). Unclassified findings are never grouped or dispatched."""
    buckets: dict[tuple[Kind, str], list[tuple[NormalizedFinding, Classification]]] = defaultdict(
        list
    )
    unclassified: list[tuple[NormalizedFinding, Classification]] = []
    for f, c in classified:
        if c.kind is None:
            unclassified.append((f, c))
            continue
        buckets[(c.kind, group_key(f, c))].append((f, c))

    candidates: list[WorkItemCandidate] = []
    for (kind, key), items in sorted(buckets.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        members = [f for f, _ in items]
        severity = max((f.severity for f in members), key=lambda s: s.rank)
        risk = Risk.high if any(c.risk is Risk.high for _, c in items) else Risk.normal
        candidates.append(
            WorkItemCandidate(
                kind=kind,
                group_key=key,
                title=group_title(kind, key, members),
                severity=severity,
                risk=risk,
                layer=members[0].layer,
                members=members,
            )
        )
    return candidates, unclassified
