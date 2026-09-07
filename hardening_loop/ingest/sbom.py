"""Syft CycloneDX (JSON) SBOM parser: component inventory only."""

from __future__ import annotations

from typing import Any

from hardening_loop.ingest.records import SbomComponent, ecosystem_from_purl


class SbomParseError(ValueError):
    pass


def parse_cyclonedx(doc: dict[str, Any]) -> list[SbomComponent]:
    if doc.get("bomFormat") != "CycloneDX":
        raise SbomParseError(f"unsupported bomFormat {doc.get('bomFormat')!r}")
    out: list[SbomComponent] = []
    for c in doc.get("components") or []:
        purl = c.get("purl")
        out.append(
            SbomComponent(
                name=str(c.get("name", "")),
                version=str(c.get("version", "")),
                purl=purl,
                component_type=str(c.get("type", "")),
                ecosystem=ecosystem_from_purl(purl),
            )
        )
    return out


def sbom_tool_version(doc: dict[str, Any]) -> str | None:
    tools = (doc.get("metadata") or {}).get("tools") or {}
    components = tools.get("components") if isinstance(tools, dict) else tools
    for t in components or []:
        if t.get("name") == "syft":
            return str(t.get("version"))
    return None
