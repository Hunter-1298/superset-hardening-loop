"""Merge per-scanner records into deduplicated, scanner-neutral findings."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hardening_loop.domain.enums import Ecosystem, Layer, Scanner, Severity
from hardening_loop.ingest.records import RawConfigFinding, RawVuln


class NormalizedFinding(BaseModel):
    model_config = ConfigDict(frozen=False)

    dedupe_key: str
    vuln_id: str
    is_config: bool
    pkg_name: str | None = None
    pkg_version: str | None = None
    purl: str | None = None
    ecosystem: Ecosystem
    layer: Layer
    resource: str | None = None
    title: str | None = None
    severity: Severity = Severity.unknown
    severity_by_scanner: dict[str, str] = Field(default_factory=dict)
    fix_versions_by_scanner: dict[str, list[str]] = Field(default_factory=dict)
    fix_state_by_scanner: dict[str, str] = Field(default_factory=dict)
    reported_by: set[Scanner] = Field(default_factory=set)
    records: dict[str, Any] = Field(default_factory=dict)  # scanner -> raw record (verbatim)

    @property
    def severity_disagreement(self) -> bool:
        return len({v for v in self.severity_by_scanner.values()}) > 1

    @property
    def all_fix_versions(self) -> list[str]:
        seen: list[str] = []
        for versions in self.fix_versions_by_scanner.values():
            for v in versions:
                if v not in seen:
                    seen.append(v)
        return seen

    @property
    def has_fix(self) -> bool:
        return bool(self.all_fix_versions)


def normalize(
    vulns: Iterable[RawVuln], configs: Iterable[RawConfigFinding] = ()
) -> list[NormalizedFinding]:
    merged: dict[str, NormalizedFinding] = {}
    for rv in vulns:
        key = rv.dedupe_key
        nf = merged.get(key)
        if nf is None:
            nf = NormalizedFinding(
                dedupe_key=key,
                vuln_id=rv.canonical_id,
                is_config=False,
                pkg_name=rv.normalized_pkg_name,
                pkg_version=rv.pkg_version,
                purl=rv.purl,
                ecosystem=rv.ecosystem,
                layer=rv.layer,
                title=rv.title,
            )
            merged[key] = nf
        if nf.title is None and rv.title:
            nf.title = rv.title
        if nf.purl is None and rv.purl:
            nf.purl = rv.purl
        nf.reported_by.add(rv.scanner)
        nf.severity_by_scanner[rv.scanner.value] = rv.severity.value
        nf.fix_versions_by_scanner[rv.scanner.value] = list(rv.fixed_versions)
        nf.fix_state_by_scanner[rv.scanner.value] = rv.fix_state
        nf.records[rv.scanner.value] = rv.record
        if rv.severity.rank > nf.severity.rank:
            nf.severity = rv.severity

    for rc in configs:
        key = rc.dedupe_key
        nf = merged.get(key)
        if nf is None:
            nf = NormalizedFinding(
                dedupe_key=key,
                vuln_id=rc.canonical_id,
                is_config=True,
                ecosystem=Ecosystem.config,
                layer=rc.layer,
                resource=rc.resource,
                title=rc.title,
                severity=rc.severity,
            )
            merged[key] = nf
        nf.reported_by.add(rc.scanner)
        nf.severity_by_scanner[rc.scanner.value] = rc.severity.value
        nf.fix_state_by_scanner[rc.scanner.value] = "fixed" if rc.fix_available else "unknown"
        nf.records[rc.scanner.value] = rc.record

    return sorted(merged.values(), key=lambda f: f.dedupe_key)
