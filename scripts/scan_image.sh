#!/usr/bin/env bash
# Scan ONE immutable image reference with the pinned tools and write a self-describing evidence dir.
#
#   scripts/scan_image.sh <image-ref> <superset-src-dir> <out-dir> <mode: raw|policy> [image-target]
#
# raw    : no suppression of any kind.
# policy : identical, plus every approved OpenVEX document from <src>/security/vex/approved/*.json.
#          No .trivyignore / .grype.yaml / ignore rules are ever used; the script refuses to run if
#          any such file exists in the source tree (see check_no_ignore_files).
#
# Outputs (all JSON, plus SHA256SUMS and job.json):
#   sbom.cdx.json            Syft CycloneDX SBOM of the image
#   trivy-vuln.json          trivy image --scanners vuln --list-all-pkgs (native image analysis)
#   grype-vuln.json          grype sbom: (vulnerabilities from the Syft SBOM of the SAME image)
#   trivy-image-config.json  trivy image --scanners misconfig --image-config-scanners misconfig
#   trivy-config.json        trivy config on Dockerfile, docker-compose*.yml, docker/, helm/superset
#   trivy-vuln.sarif         SARIF rendering of trivy-vuln.json (for code scanning; never replaces JSON)
#   grype-vuln.sarif         SARIF rendering of the same grype run
#   tools.json               tool versions + vulnerability DB timestamps
set -euo pipefail

IMAGE_REF="${1:?image ref}"
SRC="${2:?superset source dir}"
OUT="${3:?output dir}"
MODE="${4:?raw|policy}"
IMAGE_TARGET="${5:-lean}"
PLATFORM="${PLATFORM:-linux/amd64}"

case "$MODE" in raw|policy) ;; *) echo "mode must be raw|policy" >&2; exit 2;; esac
mkdir -p "$OUT"
# Several steps below run inside other directories (the source tree, a staging dir). Resolve both
# user-supplied paths to absolute ones first so a relative <out-dir> or <src-dir> keeps meaning
# the caller's directory everywhere.
OUT="$(cd "$OUT" && pwd -P)"
SRC="$(cd "$SRC" && pwd -P)"

# Only immutable references are accepted: a local image ID ("docker:sha256:...") or a registry
# digest ("repo@sha256:..."). A tag alone could change between SBOM, scan and smoke test.
#
# Trivy's image scanner cannot parse a bare local image ID. For local IDs a tag must be supplied via
# IMAGE_NAME and is verified to resolve to exactly that ID before use. Registry digests are accepted
# by every tool unchanged; the digest must already be pulled into the local daemon so that all tools
# read the same bytes without re-resolving anything remotely.
TRIVY_IMAGE_REF="$IMAGE_REF"
if [[ "$IMAGE_REF" == docker:sha256:* ]]; then
  : "${IMAGE_NAME:?IMAGE_NAME (a local tag) is required when scanning a bare image ID}"
  RESOLVED_ID="$(docker image inspect --format '{{.Id}}' "$IMAGE_NAME")"
  if [[ "docker:$RESOLVED_ID" != "$IMAGE_REF" ]]; then
    echo "IMAGE_NAME=$IMAGE_NAME resolves to $RESOLVED_ID, not ${IMAGE_REF#docker:}" >&2
    exit 5
  fi
  TRIVY_IMAGE_REF="$IMAGE_NAME"
  EXPECTED_DIGEST="${IMAGE_REF#docker:}"
elif [[ "$IMAGE_REF" == *@sha256:* ]]; then
  EXPECTED_DIGEST="${IMAGE_REF##*@}"
  if ! docker image inspect --format '{{join .RepoDigests "\n"}}' "$IMAGE_REF" 2>/dev/null | grep -qx -- "$IMAGE_REF"; then
    echo "$IMAGE_REF is not present in the local docker daemon under that digest (docker pull it first)" >&2
    exit 5
  fi
else
  echo "refusing mutable image reference $IMAGE_REF: use docker:sha256:<id> or repo@sha256:<digest>" >&2
  exit 5
fi
START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

check_no_ignore_files() {
  local found
  found="$(cd "$SRC" && find . -path ./node_modules -prune -o \( -name '.trivyignore' -o -name '.trivyignore.yaml' -o -name '.trivyignore.yml' -o -name '.grype.yaml' -o -name '.grype.yml' -o -name '.grype' \) -print | head -n 20)"
  if [[ -n "$found" ]]; then
    echo "::error::scanner ignore files are forbidden; found:" >&2
    echo "$found" >&2
    exit 3
  fi
}
check_no_ignore_files

# VEX handling: only files under security/vex/approved/ and only in policy mode. Each document fed
# to the scanners is copied verbatim into $OUT/vex/ and checksummed with the rest of the evidence,
# so closure can later re-validate exactly which approval suppressed a finding.
VEX_ARGS_TRIVY=()
VEX_ARGS_GRYPE=()
VEX_LIST=()
if [[ "$MODE" == "policy" && -d "$SRC/security/vex/approved" ]]; then
  while IFS= read -r -d '' f; do
    VEX_LIST+=("$f")
    VEX_ARGS_TRIVY+=(--vex "$f")
    VEX_ARGS_GRYPE+=(--vex "$f")
    mkdir -p "$OUT/vex"
    cp "$f" "$OUT/vex/$(basename "$f")"
  done < <(find "$SRC/security/vex/approved" -maxdepth 1 -name '*.json' -print0 | sort -z)
fi
if [[ "$MODE" == "policy" && ${#VEX_LIST[@]} -eq 0 ]]; then
  echo "policy mode with no approved VEX documents: results will equal raw"
fi

# Tool identity (fail if not the pinned versions).
: "${SYFT_VERSION:=1.45.1}" "${TRIVY_VERSION:=0.71.2}" "${GRYPE_VERSION:=0.114.0}"
syft version -o json > "$OUT/.syft-version.json"
grep -q "\"version\": *\"$SYFT_VERSION\"" "$OUT/.syft-version.json" || { echo "syft is not $SYFT_VERSION" >&2; exit 4; }
trivy --version | grep -q "Version: $TRIVY_VERSION" || { echo "trivy is not $TRIVY_VERSION" >&2; exit 4; }
grype version -o json > "$OUT/.grype-version.json"
grep -q "\"version\": *\"$GRYPE_VERSION\"" "$OUT/.grype-version.json" || { echo "grype is not $GRYPE_VERSION" >&2; exit 4; }

# Warm DBs up-front so timestamps in tools.json describe exactly what scanned.
trivy image --download-db-only --quiet
trivy image --download-java-db-only --quiet || true
grype db update -q

# 1. SBOM
syft scan "$IMAGE_REF" --platform "$PLATFORM" -o "cyclonedx-json=$OUT/sbom.cdx.json" -q

# 2. Vulnerabilities, both scanners, same immutable image. Exit code always 0: gating is separate.
#    Grype consumes the Syft SBOM (same tool family; identical to scanning the image). Trivy scans
#    the image natively: fed a third-party SBOM it loses Debian source-package data and under-reports
#    OS vulnerabilities by an order of magnitude, which would fabricate "scanner disagreements".
trivy image --skip-version-check --scanners vuln --list-all-pkgs --format json --exit-code 0 \
  --platform "$PLATFORM" "${VEX_ARGS_TRIVY[@]+"${VEX_ARGS_TRIVY[@]}"}" \
  --output "$OUT/trivy-vuln.json" "$TRIVY_IMAGE_REF"
grype "sbom:$OUT/sbom.cdx.json" -o "json=$OUT/grype-vuln.json" -o "sarif=$OUT/grype-vuln.sarif" -q \
  "${VEX_ARGS_GRYPE[@]+"${VEX_ARGS_GRYPE[@]}"}"
# SARIF is derived from the JSON report already written, so both describe one scan.
trivy convert --format sarif --ignorefile /dev/null --output "$OUT/trivy-vuln.sarif" "$OUT/trivy-vuln.json"

# 3. Image configuration (runtime hardening: USER, HEALTHCHECK, exposed ports, ...)
trivy image --skip-version-check --scanners misconfig --image-config-scanners misconfig --format json --exit-code 0 \
  --platform "$PLATFORM" --output "$OUT/trivy-image-config.json" "$TRIVY_IMAGE_REF"

# Every Trivy image report must describe the same image bytes Syft SBOM'd.
check_image_identity() {
  python3 - "$1" "$EXPECTED_DIGEST" <<'PY'
import json, sys
report, expected = json.load(open(sys.argv[1])), sys.argv[2]
meta = report.get("Metadata") or {}
seen = {meta.get("ImageID"), *(meta.get("RepoDigests") or [])}
if meta.get("ImageID") != expected and not any(
    d.endswith("@" + expected) for d in (meta.get("RepoDigests") or [])
):
    sys.exit(f"{sys.argv[1]} scanned {seen}, expected {expected}")
PY
}
check_image_identity "$OUT/trivy-vuln.json"
check_image_identity "$OUT/trivy-image-config.json"
python3 - "$OUT/sbom.cdx.json" "$EXPECTED_DIGEST" <<'PY'
import json, sys
doc, expected = json.load(open(sys.argv[1])), sys.argv[2]
comp = (doc.get("metadata") or {}).get("component") or {}
props = {p.get("name"): p.get("value") for p in comp.get("properties") or []}
# Syft names the root component after the image ID when scanning a bare ID: name=sha256 version=<hex>;
# for a registry digest ref the root component is name=<repo> version=sha256:<digest>.
candidates = {props.get("syft:image:id"), props.get("syft:image:manifestDigest"), f"{comp.get('name')}:{comp.get('version')}", comp.get("version")}
candidates |= {v.rsplit("@", 1)[-1] for k, v in props.items() if k and k.startswith("syft:image:repoDigests:") and v}
if expected not in candidates:
    sys.exit(f"sbom describes {candidates - {None}}, expected {expected}")
PY

# 4. IaC / deployment configuration from the source tree
CONFIG_TARGETS=()
for p in Dockerfile docker docker-compose.yml docker-compose-non-dev.yml docker-compose-image-tag.yml helm/superset; do
  [[ -e "$SRC/$p" ]] && CONFIG_TARGETS+=("$p")
done
# trivy config accepts a single target, so stage the in-scope paths (keeping their repo-relative
# names) into a temp dir and scan that once.
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
(cd "$SRC" && cp -a --parents "${CONFIG_TARGETS[@]}" "$STAGE/")
# Trivy's helm scanner refuses charts whose subchart dependencies are not vendored under charts/.
# The bitnami postgresql/redis subcharts are third-party and out of scope: strip the `dependencies:`
# block from the STAGED copy only, so Superset's own templates are rendered and scanned.
if [[ -f "$STAGE/helm/superset/Chart.yaml" ]]; then
  python3 - "$STAGE/helm/superset/Chart.yaml" <<'PY'
import re, sys
p = sys.argv[1]
text = open(p).read()
open(p, "w").write(re.sub(r"(?ms)^dependencies:\n(?:[ \t].*\n?|\n)*", "", text))
PY
fi
(cd "$STAGE" && trivy config --skip-version-check --format json --exit-code 0 --output "$OUT/trivy-config.json" .)

# 5. Tool + DB metadata
TRIVY_DB_JSON="$(trivy version --format json)"
GRYPE_DB_JSON="$(grype db status -o json)"
python3 - "$OUT" "$MODE" "$IMAGE_REF" "$IMAGE_TARGET" "$PLATFORM" "$START" "$TRIVY_DB_JSON" "$GRYPE_DB_JSON" "$SRC" "${VEX_LIST[@]+"${VEX_LIST[@]}"}" <<'PY'
import hashlib, json, os, sys, datetime
out, mode, image_ref, image_target, platform, start, trivy_json, grype_json, src, *vex = sys.argv[1:]
syft = json.load(open(os.path.join(out, ".syft-version.json")))
grype = json.load(open(os.path.join(out, ".grype-version.json")))
trivy = json.loads(trivy_json)
grype_db = json.loads(grype_json)
tools = {
    "syft": {"version": syft["version"]},
    "trivy": {
        "version": trivy["Version"],
        "vuln_db": trivy.get("VulnerabilityDB"),
        "java_db": trivy.get("JavaDB"),
        "checks_bundle": trivy.get("CheckBundle"),
    },
    "grype": {"version": grype["version"], "db": grype_db},
}
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()
files = ["sbom.cdx.json", "trivy-vuln.json", "grype-vuln.json", "trivy-image-config.json", "trivy-config.json",
         "trivy-vuln.sarif", "grype-vuln.sarif"]
json.dump(tools, open(os.path.join(out, "tools.json"), "w"), indent=2, sort_keys=True)
files.append("tools.json")
vex_docs = []
for v in vex:
    doc = json.load(open(v))
    approval = doc.get("x-approval") if isinstance(doc, dict) else None
    if not isinstance(approval, dict) or not approval.get("issue_url") or not approval.get("approved_by"):
        sys.exit(f"{v}: approved OpenVEX must carry x-approval.issue_url and x-approval.approved_by")
    evidence_file = "vex/" + os.path.basename(v)
    if sha(v) != sha(os.path.join(out, evidence_file)):
        sys.exit(f"{v}: evidence copy differs from source")
    files.append(evidence_file)
    vex_docs.append({
        "path": os.path.relpath(v, start=src),
        "evidence_file": evidence_file,
        "sha256": sha(v),
        "x-approval": {"issue_url": approval["issue_url"], "approved_by": approval["approved_by"]},
        "vulnerabilities": sorted(
            {
                (s.get("vulnerability") or {}).get("name")
                for s in doc.get("statements") or []
                if isinstance(s, dict) and (s.get("vulnerability") or {}).get("name")
            }
        ),
    })
sums = {f: sha(os.path.join(out, f)) for f in files}
with open(os.path.join(out, "SHA256SUMS"), "w") as fh:
    for f in files:
        fh.write(f"{sums[f]}  {f}\n")
job = {
    "schema": "hardening-loop/scan-job/v1",
    "mode": mode,
    "image_ref": image_ref,
    "image_target": image_target,
    "platform": platform,
    "layer_scope": "image",
    "inputs": {"syft": "image", "trivy": "image", "grype": "sbom.cdx.json", "trivy-config": "source-tree"},
    "started_at": start,
    "finished_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "files": sums,
    "vex_documents": vex_docs,
    "tools": tools,
}
json.dump(job, open(os.path.join(out, "job.json"), "w"), indent=2, sort_keys=True)
for f in (".syft-version.json", ".grype-version.json"):
    os.remove(os.path.join(out, f))
print(json.dumps({k: job[k] for k in ("mode", "image_ref", "image_target", "platform")}))
PY
