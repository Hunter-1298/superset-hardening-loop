"""Trivy JSON (schema v2) parsers: vulnerabilities (image/sbom) and misconfigurations (config)."""

from __future__ import annotations

from typing import Any

from hardening_loop.domain.enums import Ecosystem, Layer, Scanner, Severity
from hardening_loop.ingest.records import RawConfigFinding, RawVuln, ecosystem_from_purl, layer_for

# Trivy `Result.Type` -> ecosystem. Anything else falls back to the PURL, then `unknown`.
_TYPE_TO_ECOSYSTEM: dict[str, Ecosystem] = {
    "pip": Ecosystem.pypi,
    "python-pkg": Ecosystem.pypi,
    "pipenv": Ecosystem.pypi,
    "poetry": Ecosystem.pypi,
    "uv": Ecosystem.pypi,
    "debian": Ecosystem.deb,
    "ubuntu": Ecosystem.deb,
    "npm": Ecosystem.npm,
    "node-pkg": Ecosystem.npm,
    "yarn": Ecosystem.npm,
    "pnpm": Ecosystem.npm,
    "gomod": Ecosystem.golang,
    "gobinary": Ecosystem.golang,
}

# Trivy `Result.Type` for misconfig results -> layer.
_CONFIG_TYPE_TO_LAYER: dict[str, Layer] = {
    "dockerfile": Layer.dockerfile,
    "helm": Layer.helm,
    "kubernetes": Layer.helm,
    "dockercompose": Layer.compose,
    "docker-compose": Layer.compose,
    "yaml": Layer.compose,
}


class TrivyParseError(ValueError):
    pass


def _require_schema(report: dict[str, Any]) -> None:
    if report.get("SchemaVersion") != 2:
        raise TrivyParseError(f"unsupported Trivy SchemaVersion {report.get('SchemaVersion')!r}")


def parse_trivy_vulns(report: dict[str, Any]) -> list[RawVuln]:
    _require_schema(report)
    out: list[RawVuln] = []
    for result in report.get("Results") or []:
        if result.get("Class") not in ("lang-pkgs", "os-pkgs"):
            continue
        rtype = str(result.get("Type", ""))
        target = str(result.get("Target", ""))
        for v in result.get("Vulnerabilities") or []:
            purl = (v.get("PkgIdentifier") or {}).get("PURL")
            ecosystem = _TYPE_TO_ECOSYSTEM.get(rtype) or ecosystem_from_purl(purl)
            if ecosystem is Ecosystem.unknown and result.get("Class") == "os-pkgs":
                ecosystem = Ecosystem.deb if rtype in ("debian", "ubuntu") else Ecosystem.unknown
            fixed = _split_versions(v.get("FixedVersion"))
            out.append(
                RawVuln(
                    scanner=Scanner.trivy,
                    primary_id=str(v["VulnerabilityID"]),
                    aliases=[str(a) for a in (v.get("VendorIDs") or [])],
                    pkg_name=str(v["PkgName"]),
                    pkg_version=str(v.get("InstalledVersion", "")),
                    purl=purl,
                    ecosystem=ecosystem,
                    layer=layer_for(ecosystem),
                    severity=Severity.parse(v.get("Severity")),
                    fixed_versions=fixed,
                    fix_state=str(v.get("Status") or ("fixed" if fixed else "unknown")),
                    title=v.get("Title"),
                    location=target,
                    record=v,
                )
            )
    return out


def _split_versions(raw: str | None) -> list[str]:
    if not raw:
        return []
    return [p.strip() for p in raw.split(",") if p.strip()]


def parse_trivy_misconfigs(
    report: dict[str, Any], *, image_ref: str | None = None
) -> list[RawConfigFinding]:
    """Both `trivy config` and `trivy image --image-config-scanners misconfig` output."""
    _require_schema(report)
    out: list[RawConfigFinding] = []
    for result in report.get("Results") or []:
        if result.get("Class") != "config":
            continue
        rtype = str(result.get("Type", "")).lower()
        target = str(result.get("Target", ""))
        layer = _CONFIG_TYPE_TO_LAYER.get(rtype)
        if layer is None:
            layer = _layer_from_target(target)
        if layer is Layer.compose and "helm" in target.lower():
            layer = Layer.helm
        resource = image_ref if image_ref and target == image_ref else target
        for m in result.get("Misconfigurations") or []:
            if m.get("Status") != "FAIL":
                continue
            out.append(
                RawConfigFinding(
                    scanner=Scanner.trivy,
                    rule_id=str(m.get("AVDID") or m["ID"]),
                    resource=_resource(resource, m),
                    message=m.get("Message"),
                    layer=layer,
                    severity=Severity.parse(m.get("Severity")),
                    title=m.get("Title"),
                    fix_available=bool(m.get("Resolution")),
                    record=m,
                )
            )
    return out


def _resource(target: str, m: dict[str, Any]) -> str:
    """One rule can fail for several containers in one file; the start line tells them apart."""
    cause = m.get("CauseMetadata") or {}
    start = cause.get("StartLine")
    return f"{target}:{start}" if start else target


def _layer_from_target(target: str) -> Layer:
    t = target.lower()
    if "dockerfile" in t:
        return Layer.dockerfile
    if "helm" in t or t.endswith((".tpl",)) or "/templates/" in t:
        return Layer.helm
    return Layer.compose
