"""Vulnerability detail assembled from the raw scanner records the controller already persists.

The dashboard never consults an external vulnerability database: everything on the CVE page comes
from the Trivy and Grype records stored on each raw sighting (`Sighting.record`). Trivy stores the
`Vulnerabilities[]` (or `Misconfigurations[]`) entry; Grype stores the whole `matches[]` entry."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any


@dataclass(frozen=True)
class CvssEntry:
    scanner: str
    source: str
    version: str
    vector: str | None
    base_score: float | None
    exploitability_score: float | None = None
    impact_score: float | None = None


@dataclass(frozen=True)
class EpssEntry:
    score: float
    percentile: float | None
    date: str | None


@dataclass(frozen=True)
class Reference:
    url: str
    scanners: tuple[str, ...]


@dataclass(frozen=True)
class ScannerView:
    """What one scanner said about the finding, kept side by side for disagreement review."""

    scanner: str
    severity: str | None
    fixed_versions: tuple[str, ...]
    fix_state: str | None
    data_source: str | None
    namespace: str | None
    fingerprint: str | None
    matched_by: str | None
    version_constraint: str | None
    layer_id: str | None
    locations: tuple[str, ...]
    risk: float | None
    purl: str | None


@dataclass(frozen=True)
class VulnDetail:
    description: str | None = None
    title: str | None = None
    cwes: tuple[str, ...] = ()
    cvss: tuple[CvssEntry, ...] = ()
    epss: EpssEntry | None = None
    published: str | None = None
    modified: str | None = None
    primary_url: str | None = None
    references: tuple[Reference, ...] = ()
    scanners: tuple[ScannerView, ...] = ()
    message: str | None = None
    resolution: str | None = None
    cause: dict[str, Any] = field(default_factory=dict)
    synthetic: bool = False  # replay double output; carries no advisory text by design

    @property
    def best_cvss(self) -> CvssEntry | None:
        """Highest-version primary CVSS with a base score; what the page leads with."""
        scored = [c for c in self.cvss if c.base_score is not None]
        if not scored:
            return None
        return max(scored, key=lambda c: (_version_key(c.version), c.base_score or 0.0))


def _version_key(version: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in version.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _str(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _float(value: object) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _list(value: object) -> list[Any]:
    return value if isinstance(value, list) else []


def vuln_detail(records: dict[str, dict[str, Any] | None]) -> VulnDetail:
    """Merge the raw records keyed by scanner name (`trivy`, `grype`) into one detail view.
    Missing or `None` records simply contribute nothing."""
    trivy = records.get("trivy")
    grype = records.get("grype")
    detail = VulnDetail()
    if trivy:
        detail = _merge(detail, _from_trivy(trivy))
    if grype:
        detail = _merge(detail, _from_grype(grype))
    if any(_dict(r).get("synthetic") is True for r in (trivy, grype)):
        detail = replace(detail, synthetic=True)
    return detail


def _merge(base: VulnDetail, extra: VulnDetail) -> VulnDetail:
    refs: dict[str, set[str]] = {}
    for ref in (*base.references, *extra.references):
        refs.setdefault(ref.url, set()).update(ref.scanners)
    cwes = tuple(dict.fromkeys((*base.cwes, *extra.cwes)))
    return VulnDetail(
        description=_longest(base.description, extra.description),
        title=base.title or extra.title,
        cwes=cwes,
        cvss=(*base.cvss, *extra.cvss),
        epss=base.epss or extra.epss,
        published=base.published or extra.published,
        modified=base.modified or extra.modified,
        primary_url=base.primary_url or extra.primary_url,
        references=tuple(
            Reference(url=u, scanners=tuple(sorted(s))) for u, s in sorted(refs.items())
        ),
        scanners=(*base.scanners, *extra.scanners),
        message=base.message or extra.message,
        resolution=base.resolution or extra.resolution,
        cause={**base.cause, **extra.cause},
        synthetic=base.synthetic or extra.synthetic,
    )


def _longest(a: str | None, b: str | None) -> str | None:
    if a is None:
        return b
    if b is None:
        return a
    return a if len(a) >= len(b) else b


# ---------------------------------------------------------------------------- trivy


def _from_trivy(rec: dict[str, Any]) -> VulnDetail:
    cvss: list[CvssEntry] = []
    for source, block in sorted(_dict(rec.get("CVSS")).items()):
        b = _dict(block)
        for ver, vec_key, score_key in (
            ("4.0", "V40Vector", "V40Score"),
            ("3.x", "V3Vector", "V3Score"),
            ("2.0", "V2Vector", "V2Score"),
        ):
            vector = _str(b.get(vec_key))
            score = _float(b.get(score_key))
            if vector is None and score is None:
                continue
            version = ver
            if vector and vector.startswith("CVSS:"):
                version = vector.split("/", 1)[0].removeprefix("CVSS:")
            cvss.append(
                CvssEntry(
                    scanner="trivy",
                    source=str(source),
                    version=version,
                    vector=vector,
                    base_score=score,
                )
            )
    data_source = _dict(rec.get("DataSource"))
    layer = _dict(rec.get("Layer"))
    references = tuple(
        Reference(url=str(u), scanners=("trivy",)) for u in _list(rec.get("References")) if u
    )
    fixed = _str(rec.get("FixedVersion"))
    fixed_versions = tuple(v.strip() for v in fixed.split(",") if v.strip()) if fixed else ()
    cause = _dict(rec.get("CauseMetadata"))
    view = ScannerView(
        scanner="trivy",
        severity=_str(rec.get("Severity")),
        fixed_versions=fixed_versions,
        fix_state=_str(rec.get("Status")),
        data_source=_str(data_source.get("Name") or data_source.get("ID")),
        namespace=_str(rec.get("SeveritySource")),
        fingerprint=_str(rec.get("Fingerprint")),
        matched_by=None,
        version_constraint=None,
        layer_id=_str(layer.get("DiffID") or layer.get("Digest")),
        locations=(),
        risk=None,
        purl=_str(_dict(rec.get("PkgIdentifier")).get("PURL")),
    )
    return VulnDetail(
        description=_str(rec.get("Description")),
        title=_str(rec.get("Title")),
        cwes=tuple(str(c) for c in _list(rec.get("CweIDs")) if c),
        cvss=tuple(cvss),
        published=_str(rec.get("PublishedDate")),
        modified=_str(rec.get("LastModifiedDate")),
        primary_url=_str(rec.get("PrimaryURL")),
        references=references,
        scanners=(view,),
        message=_str(rec.get("Message")),
        resolution=_str(rec.get("Resolution")),
        cause={
            k: cause[k]
            for k in ("Provider", "Service", "Resource", "StartLine", "EndLine")
            if k in cause and cause[k] not in (None, "", 0)
        },
    )


# ---------------------------------------------------------------------------- grype


def _from_grype(rec: dict[str, Any]) -> VulnDetail:
    vuln = _dict(rec.get("vulnerability"))
    artifact = _dict(rec.get("artifact"))
    details = [_dict(d) for d in _list(rec.get("matchDetails"))]
    cvss: list[CvssEntry] = []
    for entry in _list(vuln.get("cvss")):
        e = _dict(entry)
        metrics = _dict(e.get("metrics"))
        version = _str(e.get("version")) or "?"
        vector = _str(e.get("vector"))
        if vector and vector.startswith("CVSS:"):
            version = vector.split("/", 1)[0].removeprefix("CVSS:")
        cvss.append(
            CvssEntry(
                scanner="grype",
                source=_str(e.get("source")) or _str(e.get("type")) or "grype",
                version=version,
                vector=vector,
                base_score=_float(metrics.get("baseScore")),
                exploitability_score=_float(metrics.get("exploitabilityScore")),
                impact_score=_float(metrics.get("impactScore")),
            )
        )
    epss: EpssEntry | None = None
    for entry in _list(vuln.get("epss")):
        e = _dict(entry)
        score = _float(e.get("epss"))
        if score is None:
            continue
        candidate = EpssEntry(
            score=score, percentile=_float(e.get("percentile")), date=_str(e.get("date"))
        )
        if epss is None or (candidate.date or "") > (epss.date or ""):
            epss = candidate
    cwes = tuple(
        dict.fromkeys(
            str(_dict(c).get("cwe")) for c in _list(vuln.get("cwes")) if _dict(c).get("cwe")
        )
    )
    references = tuple(
        Reference(url=str(u), scanners=("grype",)) for u in _list(vuln.get("urls")) if u
    )
    fix = _dict(vuln.get("fix"))
    locations = tuple(
        str(_dict(loc).get("path"))
        for loc in _list(artifact.get("locations"))
        if _dict(loc).get("path")
    )
    layer_ids = [
        _str(_dict(loc).get("layerID")) for loc in _list(artifact.get("locations")) if _dict(loc)
    ]
    matched_by = ", ".join(
        dict.fromkeys(
            f"{d.get('type')}/{d.get('matcher')}" if d.get("matcher") else str(d.get("type"))
            for d in details
            if d.get("type")
        )
    )
    constraint = next(
        (
            _str(_dict(d.get("found")).get("versionConstraint"))
            for d in details
            if _dict(d.get("found")).get("versionConstraint")
        ),
        None,
    )
    view = ScannerView(
        scanner="grype",
        severity=_str(vuln.get("severity")),
        fixed_versions=tuple(str(v) for v in _list(fix.get("versions")) if v),
        fix_state=_str(fix.get("state")),
        data_source=_str(vuln.get("dataSource")),
        namespace=_str(vuln.get("namespace")),
        fingerprint=None,
        matched_by=matched_by or None,
        version_constraint=constraint,
        layer_id=next((lid for lid in layer_ids if lid), None),
        locations=locations,
        risk=_float(vuln.get("risk")),
        purl=_str(artifact.get("purl")),
    )
    return VulnDetail(
        description=_str(vuln.get("description")),
        cwes=cwes,
        cvss=tuple(cvss),
        epss=epss,
        primary_url=_str(vuln.get("dataSource")),
        references=references,
        scanners=(view,),
    )


__all__ = ["CvssEntry", "EpssEntry", "Reference", "ScannerView", "VulnDetail", "vuln_detail"]
