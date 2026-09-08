"""`scripts/scan_image.sh` end-to-end against stubbed `syft`/`trivy`/`grype`/`docker` binaries.

The stubs honour the exact flag shapes the script uses and write minimal-but-parseable reports, so
the test proves the script's own logic: path handling, identity checks, SARIF alongside raw JSON,
job.json/SHA256SUMS bookkeeping, and that the resulting directory loads through the real evidence
loader. No real scanner, network or Docker daemon is involved."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

from hardening_loop.ingest.evidence import load_scan_job

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "scan_image.sh"
STUB = Path(__file__).resolve().parent / "support" / "scanner_stub.py"
IMAGE_ID = "sha256:" + "c" * 64
IMAGE_REF = f"docker:{IMAGE_ID}"
IMAGE_NAME = "superset:scan-test"


@pytest.fixture
def stub_env(tmp_path: Path) -> dict[str, str]:
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for tool in ("syft", "trivy", "grype", "docker"):
        p = bindir / tool
        p.write_text(STUB.read_text())
        p.chmod(p.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "calls.jsonl"
    env = {
        **os.environ,
        "PATH": f"{bindir}:{os.environ['PATH']}",
        "STUB_LOG": str(log),
        "STUB_IMAGE_ID": IMAGE_ID,
        "STUB_SYFT_VERSION": "1.45.1",
        "STUB_TRIVY_VERSION": "0.71.2",
        "STUB_GRYPE_VERSION": "0.114.0",
        "IMAGE_NAME": IMAGE_NAME,
    }
    env.pop("SYFT_VERSION", None)
    env.pop("TRIVY_VERSION", None)
    env.pop("GRYPE_VERSION", None)
    return env


def _source_tree(root: Path) -> Path:
    src = root / "superset-src"
    (src / "docker").mkdir(parents=True)
    (src / "Dockerfile").write_text("FROM scratch\n")
    (src / "docker" / "entrypoint.sh").write_text("#!/bin/sh\n")
    return src


def _run(args: list[str], *, cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", str(SCRIPT), *args], cwd=cwd, env=env, capture_output=True, text=True
    )


EXPECTED_FILES = {
    "sbom.cdx.json",
    "trivy-vuln.json",
    "grype-vuln.json",
    "trivy-image-config.json",
    "trivy-config.json",
    "trivy-vuln.sarif",
    "grype-vuln.sarif",
    "tools.json",
    "job.json",
    "SHA256SUMS",
}


def test_relative_out_and_src_land_in_callers_directory(
    tmp_path: Path, stub_env: dict[str, str]
) -> None:
    """Regression for run 34138972368: `trivy config` runs inside a staging dir, so a relative
    <out-dir> used to resolve there and the job died with `open evidence/...: no such file`."""
    src = _source_tree(tmp_path)
    workdir = tmp_path / "workspace"
    workdir.mkdir()
    shutil.copytree(src, workdir / "src")

    res = _run([IMAGE_REF, "src", "evidence/lean/raw", "raw", "lean"], cwd=workdir, env=stub_env)
    assert res.returncode == 0, res.stderr

    out = workdir / "evidence" / "lean" / "raw"
    assert {p.name for p in out.iterdir()} == EXPECTED_FILES
    calls = [json.loads(line) for line in Path(stub_env["STUB_LOG"]).read_text().splitlines()]
    config_call = next(c for c in calls if c["tool"] == "trivy" and c["args"][0] == "config")
    assert config_call["cwd"] != str(workdir), "trivy config must run inside the staging dir"
    assert config_call["args"][config_call["args"].index("--output") + 1] == str(
        out / "trivy-config.json"
    )
    # Nothing leaked next to the staging dir or into the source tree.
    assert not list((workdir / "src").glob("**/trivy-config.json"))

    job = load_scan_job(out)
    assert job.image_ref == IMAGE_REF
    assert job.mode.value == "raw" and job.image_target.value == "lean"
    assert set(job.files) == EXPECTED_FILES - {"job.json", "SHA256SUMS"}
    assert job.tools.syft == "1.45.1"
    assert job.tools.trivy == "0.71.2"
    assert job.tools.grype == "0.114.0"


def test_sarif_is_additional_to_raw_json(tmp_path: Path, stub_env: dict[str, str]) -> None:
    src = _source_tree(tmp_path)
    out = tmp_path / "out"
    res = _run([IMAGE_REF, str(src), str(out), "raw"], cwd=tmp_path, env=stub_env)
    assert res.returncode == 0, res.stderr
    sums = dict(line.split("  ", 1)[::-1] for line in (out / "SHA256SUMS").read_text().splitlines())
    for name in ("trivy-vuln.json", "grype-vuln.json", "trivy-vuln.sarif", "grype-vuln.sarif"):
        assert name in sums and (out / name).is_file()
    calls = [json.loads(line) for line in Path(stub_env["STUB_LOG"]).read_text().splitlines()]
    convert = next(c for c in calls if c["tool"] == "trivy" and c["args"][0] == "convert")
    assert convert["args"][-1] == str(out / "trivy-vuln.json")
    assert "--ignorefile" in convert["args"]
    assert convert["args"][convert["args"].index("--ignorefile") + 1] == "/dev/null"


def test_refuses_mutable_reference_before_running_any_tool(
    tmp_path: Path, stub_env: dict[str, str]
) -> None:
    src = _source_tree(tmp_path)
    res = _run(
        ["superset:latest", str(src), str(tmp_path / "out"), "raw"], cwd=tmp_path, env=stub_env
    )
    assert res.returncode == 5
    assert "refusing mutable image reference" in res.stderr
    assert not Path(stub_env["STUB_LOG"]).exists()


def test_refuses_when_tag_resolves_to_a_different_image(
    tmp_path: Path, stub_env: dict[str, str]
) -> None:
    src = _source_tree(tmp_path)
    other = "docker:sha256:" + "d" * 64
    res = _run([other, str(src), str(tmp_path / "out"), "raw"], cwd=tmp_path, env=stub_env)
    assert res.returncode == 5
    assert "resolves to" in res.stderr


def test_refuses_source_tree_with_scanner_ignore_file(
    tmp_path: Path, stub_env: dict[str, str]
) -> None:
    src = _source_tree(tmp_path)
    (src / ".trivyignore").write_text("CVE-2024-0001\n")
    res = _run([IMAGE_REF, str(src), str(tmp_path / "out"), "raw"], cwd=tmp_path, env=stub_env)
    assert res.returncode == 3
    assert "scanner ignore files are forbidden" in res.stderr


def test_refuses_unpinned_tool_version(tmp_path: Path, stub_env: dict[str, str]) -> None:
    src = _source_tree(tmp_path)
    env = {**stub_env, "STUB_TRIVY_VERSION": "0.70.0"}
    res = _run([IMAGE_REF, str(src), str(tmp_path / "out"), "raw"], cwd=tmp_path, env=env)
    assert res.returncode == 4
    assert "trivy is not 0.71.2" in res.stderr
