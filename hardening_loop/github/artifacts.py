"""Unpacking of GitHub Actions artifact zips, shared by the live client and the in-memory double."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path


class ArtifactError(RuntimeError):
    pass


def extract_artifact_zip(payload: bytes, dest: Path) -> Path:
    """Unzip an artifact into `dest`, refusing members that escape it. The zip itself is kept
    beside the tree as `<dest>.zip` so its checksum can be recorded with the intake."""
    dest.mkdir(parents=True, exist_ok=True)
    dest.with_suffix(".zip").write_bytes(payload)
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            for member in zf.infolist():
                target = (dest / member.filename).resolve()
                if not target.is_relative_to(dest.resolve()):
                    raise ArtifactError(f"artifact member escapes destination: {member.filename}")
            zf.extractall(dest)
    except zipfile.BadZipFile as exc:
        raise ArtifactError(f"artifact is not a zip archive: {exc}") from None
    return dest
