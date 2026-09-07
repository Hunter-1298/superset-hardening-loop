"""Grype JSON parser."""

from __future__ import annotations

from typing import Any

from hardening_loop.domain.enums import Ecosystem, Scanner, Severity
from hardening_loop.ingest.records import RawVuln, ecosystem_from_purl, layer_for

_ARTIFACT_TYPE_TO_ECOSYSTEM: dict[str, Ecosystem] = {
    "python": Ecosystem.pypi,
    "deb": Ecosystem.deb,
    "npm": Ecosystem.npm,
    "go-module": Ecosystem.golang,
    "binary": Ecosystem.binary,
}


class GrypeParseError(ValueError):
    pass


def parse_grype_vulns(report: dict[str, Any]) -> list[RawVuln]:
    if "matches" not in report or "descriptor" not in report:
        raise GrypeParseError("not a grype JSON report (missing matches/descriptor)")
    out: list[RawVuln] = []
    for m in report["matches"]:
        vuln = m["vulnerability"]
        art = m["artifact"]
        purl = art.get("purl")
        ecosystem = _ARTIFACT_TYPE_TO_ECOSYSTEM.get(
            str(art.get("type", ""))
        ) or ecosystem_from_purl(purl)
        fix = vuln.get("fix") or {}
        fixed = [str(v) for v in (fix.get("versions") or []) if v]
        aliases = [str(r["id"]) for r in (m.get("relatedVulnerabilities") or []) if r.get("id")]
        locations = [loc.get("path", "") for loc in (art.get("locations") or [])]
        out.append(
            RawVuln(
                scanner=Scanner.grype,
                primary_id=str(vuln["id"]),
                aliases=aliases,
                pkg_name=str(art["name"]),
                pkg_version=str(art.get("version", "")),
                purl=purl,
                ecosystem=ecosystem,
                layer=layer_for(ecosystem),
                severity=Severity.parse(vuln.get("severity")),
                fixed_versions=fixed,
                fix_state=str(fix.get("state") or ("fixed" if fixed else "unknown")),
                title=None,
                location=";".join(p for p in locations if p) or None,
                record=m,
            )
        )
    return out


def grype_db_built_at(report: dict[str, Any]) -> str | None:
    db = (report.get("descriptor") or {}).get("db") or {}
    status = db.get("status") or db
    built = status.get("built")
    return str(built) if built else None
