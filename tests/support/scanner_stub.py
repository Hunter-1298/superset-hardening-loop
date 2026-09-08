#!/usr/bin/env python3
"""Stub scanner used by the scan_image.sh regression test. Reads the argv shapes the script
emits and writes minimal reports; records every invocation in $STUB_LOG."""

import json
import os
import sys
from typing import Any

TOOL = os.path.basename(sys.argv[0])
ARGS = sys.argv[1:]
IMAGE_ID = os.environ["STUB_IMAGE_ID"]
with open(os.environ["STUB_LOG"], "a") as fh:
    fh.write(json.dumps({"tool": TOOL, "cwd": os.getcwd(), "args": ARGS}) + "\n")


def opt(name: str) -> str | None:
    return ARGS[ARGS.index(name) + 1] if name in ARGS else None


def write(path: str | None, doc: dict[str, Any]) -> None:
    if path is None:
        sys.exit(f"{TOOL}: no output path in {ARGS}")
    with open(path, "w") as fh:
        json.dump(doc, fh)


def trivy_report(results: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "SchemaVersion": 2,
        "ArtifactType": "container_image",
        "Metadata": {"ImageID": IMAGE_ID, "RepoDigests": []},
        "Results": results,
    }


if TOOL == "syft":
    if ARGS[:2] == ["version", "-o"]:
        print(json.dumps({"version": os.environ["STUB_SYFT_VERSION"]}))
    elif ARGS[0] == "scan":
        target = next(a for a in ARGS if a.startswith("cyclonedx-json=")).split("=", 1)[1]
        write(
            target,
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "metadata": {
                    "component": {
                        "name": "sha256",
                        "version": IMAGE_ID[7:],
                        "properties": [{"name": "syft:image:id", "value": IMAGE_ID}],
                    }
                },
                "components": [
                    {
                        "name": "urllib3",
                        "version": "1.26.0",
                        "type": "library",
                        "purl": "pkg:pypi/urllib3@1.26.0",
                    }
                ],
            },
        )
    else:
        sys.exit(f"syft: unexpected args {ARGS}")
elif TOOL == "trivy":
    if ARGS == ["--version"]:
        print(f"Version: {os.environ['STUB_TRIVY_VERSION']}")
    elif ARGS[:3] == ["version", "--format", "json"]:
        print(
            json.dumps(
                {
                    "Version": os.environ["STUB_TRIVY_VERSION"],
                    "VulnerabilityDB": {"UpdatedAt": "2026-09-01T00:00:00Z"},
                }
            )
        )
    elif ARGS[0] == "image" and ("--download-db-only" in ARGS or "--download-java-db-only" in ARGS):
        pass
    elif ARGS[0] == "image":
        out = opt("--output")
        if "vuln" in (opt("--scanners") or ""):
            write(
                out,
                trivy_report(
                    [
                        {
                            "Target": "python",
                            "Class": "lang-pkgs",
                            "Type": "python-pkg",
                            "Vulnerabilities": [],
                        }
                    ]
                ),
            )
        else:
            write(
                out,
                trivy_report(
                    [
                        {
                            "Target": ARGS[-1],
                            "Class": "config",
                            "Type": "dockerfile",
                            "Misconfigurations": [],
                        }
                    ]
                ),
            )
    elif ARGS[0] == "config":
        # The bug this test guards against: the script runs this inside a staging dir, so a
        # relative --output would land there. Refuse to write outside an absolute path.
        out = opt("--output") or ""
        if not os.path.isabs(out):
            sys.exit(
                f"trivy config: relative --output {out!r} would be written under {os.getcwd()}"
            )
        if not os.path.isdir(ARGS[-1]) or not os.path.exists(os.path.join(ARGS[-1], "Dockerfile")):
            sys.exit(f"trivy config: staged tree {ARGS[-1]} lacks Dockerfile")
        write(
            out,
            trivy_report(
                [
                    {
                        "Target": "Dockerfile",
                        "Class": "config",
                        "Type": "dockerfile",
                        "Misconfigurations": [],
                    }
                ]
            ),
        )
    elif ARGS[0] == "convert":
        src, out = ARGS[-1], opt("--output")
        if opt("--format") != "sarif" or not os.path.isfile(src):
            sys.exit(f"trivy convert: unexpected {ARGS}")
        write(
            out,
            {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Trivy"}}, "results": []}]},
        )
    else:
        sys.exit(f"trivy: unexpected args {ARGS}")
elif TOOL == "grype":
    if ARGS[:3] == ["version", "-o", "json"]:
        print(json.dumps({"version": os.environ["STUB_GRYPE_VERSION"]}))
    elif ARGS[:2] == ["db", "update"]:
        pass
    elif ARGS[:3] == ["db", "status", "-o"]:
        print(json.dumps({"built": "2026-09-01T00:00:00Z", "schemaVersion": "v6.0.2"}))
    elif ARGS[0].startswith("sbom:"):
        if not os.path.isfile(ARGS[0][5:]):
            sys.exit(f"grype: sbom {ARGS[0]} missing")
        outs: dict[str, str | None] = {}
        for i, a in enumerate(ARGS):
            if a == "-o" and "=" in ARGS[i + 1]:
                fmt, path = ARGS[i + 1].split("=", 1)
                outs[fmt] = path
        if "--file" in ARGS:
            outs["json"] = opt("--file")
        write(
            outs["json"],
            {
                "matches": [],
                "descriptor": {
                    "name": "grype",
                    "db": {"status": {"built": "2026-09-01T00:00:00Z"}},
                },
            },
        )
        if "sarif" in outs:
            write(
                outs["sarif"],
                {
                    "version": "2.1.0",
                    "runs": [{"tool": {"driver": {"name": "Grype"}}, "results": []}],
                },
            )
    else:
        sys.exit(f"grype: unexpected args {ARGS}")
elif TOOL == "docker":
    if ARGS[:3] == ["image", "inspect", "--format"] and ARGS[3] == "{{.Id}}":
        print(IMAGE_ID)
    else:
        sys.exit(f"docker: unexpected args {ARGS}")
else:
    sys.exit(f"unknown stub {TOOL}")
