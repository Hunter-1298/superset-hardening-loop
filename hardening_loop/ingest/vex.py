"""Approved OpenVEX documents as scan evidence.

A policy scan may suppress a finding only through a document a human approved and merged under
`security/vex/approved/`. To let closure trust that suppression later, the scan job keeps a
checksummed copy of every document it fed to the scanners, and `job.json` records where each copy
came from. Loading re-validates all of it: source path, checksum, OpenVEX shape and the
`x-approval` block that ties the document to the GitHub issue it dispositions.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, ValidationError

APPROVED_DIR = "security/vex/approved"
VEX_EVIDENCE_DIR = "vex"
_SUPPRESSING_STATUSES = frozenset({"not_affected", "fixed"})
_ISSUE_URL = re.compile(r"^https://github\.com/[\w.-]+/[\w.-]+/issues/\d+$")


class VexEvidenceError(ValueError):
    pass


class VexApproval(BaseModel):
    """The `x-approval` extension: which issue the disposition closes and who approved it."""

    model_config = ConfigDict(frozen=True, extra="allow")

    issue_url: str
    approved_by: str


class VexStatementSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    vulnerability: str
    products: tuple[str, ...]
    status: str


class ApprovedVexDocument(BaseModel):
    """One approved OpenVEX document as recorded in scan evidence, validated."""

    model_config = ConfigDict(frozen=True)

    source_path: str  # relative to the Superset checkout, always under APPROVED_DIR
    evidence_file: str  # relative to the job directory, checksummed in job.json `files`
    sha256: str
    approval: VexApproval
    statements: tuple[VexStatementSummary, ...]
    document: dict[str, Any]

    @property
    def vuln_ids(self) -> frozenset[str]:
        return frozenset(s.vulnerability for s in self.statements)


def approval_of(doc: dict[str, Any]) -> VexApproval | None:
    """Validated `x-approval` of an OpenVEX document dict, or None if absent/malformed."""
    raw = doc.get("x-approval")
    if not isinstance(raw, dict):
        return None
    try:
        approval = VexApproval.model_validate(raw)
    except ValidationError:
        return None
    if not _ISSUE_URL.match(approval.issue_url) or not approval.approved_by.strip():
        return None
    return approval


def validate_openvex(doc: dict[str, Any], *, where: str) -> tuple[VexStatementSummary, ...]:
    """Structural check of an OpenVEX document meant to suppress findings."""
    context = doc.get("@context")
    if not isinstance(context, str) or not context.startswith("https://openvex.dev/ns/"):
        raise VexEvidenceError(f"{where}: not an OpenVEX document (@context={context!r})")
    statements = doc.get("statements")
    if not isinstance(statements, list) or not statements:
        raise VexEvidenceError(f"{where}: OpenVEX document has no statements")
    out: list[VexStatementSummary] = []
    for i, st in enumerate(statements):
        if not isinstance(st, dict):
            raise VexEvidenceError(f"{where}: statement {i} is not an object")
        vuln = st.get("vulnerability")
        name = vuln.get("name") if isinstance(vuln, dict) else None
        if not isinstance(name, str) or not name:
            raise VexEvidenceError(f"{where}: statement {i} has no vulnerability.name")
        status = st.get("status")
        if status not in _SUPPRESSING_STATUSES:
            raise VexEvidenceError(
                f"{where}: statement {i} status {status!r} cannot suppress a finding"
            )
        products = st.get("products")
        ids: list[str] = []
        for p in products if isinstance(products, list) else []:
            pid = p.get("@id") if isinstance(p, dict) else None
            if not isinstance(pid, str) or not pid:
                raise VexEvidenceError(f"{where}: statement {i} has a product without @id")
            ids.append(pid)
        if not ids:
            raise VexEvidenceError(f"{where}: statement {i} has no products")
        out.append(VexStatementSummary(vulnerability=name, products=tuple(ids), status=status))
    return tuple(out)


def load_vex_documents(
    job_dir: Path, entries: list[dict[str, Any]], files: dict[str, str]
) -> list[ApprovedVexDocument]:
    """Re-validate the `vex_documents` entries of a job.json against the copies in `job_dir`.
    `files` is the job's checksum map, already verified against disk by the caller."""
    docs: list[ApprovedVexDocument] = []
    for i, entry in enumerate(entries):
        where = f"{job_dir}/job.json vex_documents[{i}]"
        source_path = entry.get("path")
        evidence_file = entry.get("evidence_file")
        sha = entry.get("sha256")
        if not isinstance(source_path, str) or not isinstance(evidence_file, str):
            raise VexEvidenceError(f"{where}: missing path/evidence_file")
        if not isinstance(sha, str) or files.get(evidence_file) != sha:
            raise VexEvidenceError(
                f"{where}: sha256 {sha!r} is not the checksummed evidence file {evidence_file!r}"
            )
        norm = Path(source_path).as_posix()
        if (
            Path(norm).parent.as_posix() != APPROVED_DIR
            or Path(norm).suffix != ".json"
            or ".." in Path(norm).parts
        ):
            raise VexEvidenceError(
                f"{where}: {source_path!r} is not directly under {APPROVED_DIR}/"
            )
        if Path(evidence_file).parent.as_posix() != VEX_EVIDENCE_DIR:
            raise VexEvidenceError(f"{where}: evidence copy {evidence_file!r} not under vex/")
        with (job_dir / evidence_file).open("rb") as fh:
            document = json.load(fh)
        if not isinstance(document, dict):
            raise VexEvidenceError(f"{where}: {evidence_file} is not a JSON object")
        statements = validate_openvex(document, where=where)
        approval = approval_of(document)
        if approval is None:
            raise VexEvidenceError(
                f"{where}: approved document lacks a valid x-approval "
                "{issue_url: https://github.com/<owner>/<repo>/issues/<n>, approved_by}"
            )
        docs.append(
            ApprovedVexDocument(
                source_path=norm,
                evidence_file=evidence_file,
                sha256=sha,
                approval=approval,
                statements=statements,
                document=document,
            )
        )
    return docs


__all__ = [
    "APPROVED_DIR",
    "VEX_EVIDENCE_DIR",
    "ApprovedVexDocument",
    "VexApproval",
    "VexEvidenceError",
    "VexStatementSummary",
    "approval_of",
    "load_vex_documents",
    "validate_openvex",
]
