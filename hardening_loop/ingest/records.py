"""Scanner-neutral intermediate records produced by the parsers."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from hardening_loop.domain.enums import Ecosystem, Layer, Scanner, Severity

_PEP503 = re.compile(r"[-_.]+")


def normalize_pkg_name(name: str, ecosystem: Ecosystem) -> str:
    if ecosystem is Ecosystem.pypi:
        return _PEP503.sub("-", name).lower()
    return name


def canonical_vuln_id(primary: str, aliases: list[str]) -> str:
    """Prefer a CVE id; else GHSA; else the primary id. Scanners disagree on which is primary."""
    candidates = [primary, *aliases]
    for prefix in ("CVE-", "GHSA-"):
        matches = sorted(c for c in candidates if c.upper().startswith(prefix))
        if matches:
            return matches[0]
    return primary


class RawVuln(BaseModel):
    model_config = ConfigDict(frozen=True)

    scanner: Scanner
    primary_id: str
    aliases: list[str] = Field(default_factory=list)
    pkg_name: str
    pkg_version: str
    purl: str | None = None
    ecosystem: Ecosystem
    layer: Layer
    severity: Severity
    fixed_versions: list[str] = Field(default_factory=list)
    fix_state: str  # scanner-native: fixed / affected / not-fixed / wont-fix / ...
    title: str | None = None
    location: str | None = None
    record: dict[str, Any]

    @property
    def canonical_id(self) -> str:
        return canonical_vuln_id(self.primary_id, self.aliases)

    @property
    def normalized_pkg_name(self) -> str:
        return normalize_pkg_name(self.pkg_name, self.ecosystem)

    @property
    def dedupe_key(self) -> str:
        return "|".join(
            (
                "vuln",
                self.canonical_id,
                self.ecosystem.value,
                self.normalized_pkg_name,
                self.pkg_version,
                self.layer.value,
            )
        )

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed_versions)


class RawConfigFinding(BaseModel):
    model_config = ConfigDict(frozen=True)

    scanner: Scanner
    rule_id: str  # AVD-DS-0002 etc.
    resource: str  # file path / helm template / image ref
    layer: Layer  # dockerfile | helm | compose
    severity: Severity
    title: str | None = None
    message: str | None = None
    fix_available: bool = True
    record: dict[str, Any]

    @property
    def canonical_id(self) -> str:
        return self.rule_id

    @property
    def dedupe_key(self) -> str:
        return "|".join(("config", self.rule_id, self.layer.value, self.resource))


class SbomComponent(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str
    purl: str | None
    component_type: str
    ecosystem: Ecosystem


def ecosystem_from_purl(purl: str | None) -> Ecosystem:
    if not purl or not purl.startswith("pkg:"):
        return Ecosystem.unknown
    ptype = purl[4:].split("/", 1)[0].lower()
    return _PURL_TYPE_TO_ECOSYSTEM.get(ptype, Ecosystem.unknown)


_PURL_TYPE_TO_ECOSYSTEM: dict[str, Ecosystem] = {
    "pypi": Ecosystem.pypi,
    "deb": Ecosystem.deb,
    "npm": Ecosystem.npm,
    "golang": Ecosystem.golang,
    "generic": Ecosystem.binary,
}


def layer_for(ecosystem: Ecosystem) -> Layer:
    if ecosystem is Ecosystem.pypi:
        return Layer.python
    if ecosystem is Ecosystem.deb:
        return Layer.os
    return Layer.binary
