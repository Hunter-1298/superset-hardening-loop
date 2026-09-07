#!/usr/bin/env bash
# Reproducibly capture the 6.1.0 baseline fixture set for Hunter-1298/superset.
#
#   scripts/capture_baseline.sh <superset-checkout> <out-dir> [sha]
#
# Builds the production `lean` image and the `ci` integration image (linux/amd64) from the exact
# baseline commit, records both image IDs and the ci-over-lean layer delta, then scans the `lean`
# image in raw and policy mode with scripts/scan_image.sh. Writes <out-dir>/manifest.json.
set -euo pipefail

SRC="$(cd "${1:?superset checkout}" && pwd)"
OUT="${2:?output dir}"
EXPECTED_SHA="${3:-c83fb2bb1dcfac41ac51bcebd82471f4a7180d18}"
PLATFORM="${PLATFORM:-linux/amd64}"
TAG_BASE="${TAG_BASE:-hardening-baseline}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ACTUAL_SHA="$(git -C "$SRC" rev-parse HEAD)"
if [[ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
  echo "::error::checkout is at $ACTUAL_SHA, expected $EXPECTED_SHA" >&2
  exit 1
fi
if [[ -n "$(git -C "$SRC" status --porcelain)" ]]; then
  echo "::error::checkout is dirty; refusing to capture a non-reproducible baseline" >&2
  exit 1
fi

mkdir -p "$OUT"
export DOCKER_BUILDKIT=1
BUILD_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

build_target() {
  local target="$1" tag="${TAG_BASE}:${1}-${EXPECTED_SHA:0:12}"
  docker buildx build --platform "$PLATFORM" --target "$target" --load \
    --build-arg "BUILD_TRANSLATIONS=false" \
    --label "org.opencontainers.image.revision=$EXPECTED_SHA" \
    --label "org.opencontainers.image.source=https://github.com/Hunter-1298/superset" \
    --label "io.hardening-loop.image-target=$target" \
    --label "io.hardening-loop.platform=$PLATFORM" \
    -t "$tag" "$SRC" > "$OUT/build-${target}.log" 2>&1
  echo "$tag"
}

echo "building lean ..."
LEAN_TAG="$(build_target lean)"
echo "building ci ..."
CI_TAG="$(build_target ci)"

LEAN_ID="$(docker image inspect --format '{{.Id}}' "$LEAN_TAG")"
CI_ID="$(docker image inspect --format '{{.Id}}' "$CI_TAG")"
echo "lean image id: $LEAN_ID"
echo "ci   image id: $CI_ID"

# Scan the lean image by its immutable ID, not by tag.
IMAGE_NAME="$LEAN_TAG" "$HERE/scan_image.sh" "docker:$LEAN_ID" "$SRC" "$OUT/lean/raw" raw lean
IMAGE_NAME="$LEAN_TAG" "$HERE/scan_image.sh" "docker:$LEAN_ID" "$SRC" "$OUT/lean/policy" policy lean

python3 - "$OUT" "$SRC" "$EXPECTED_SHA" "$PLATFORM" "$LEAN_TAG" "$LEAN_ID" "$CI_TAG" "$CI_ID" "$BUILD_DATE" <<'PY'
import hashlib, json, os, subprocess, sys, datetime
out, src, sha, platform, lean_tag, lean_id, ci_tag, ci_id, build_date = sys.argv[1:]

def inspect(ref):
    return json.loads(subprocess.check_output(["docker", "image", "inspect", ref]))[0]

lean, ci = inspect(lean_id), inspect(ci_id)
lean_layers, ci_layers = lean["RootFS"]["Layers"], ci["RootFS"]["Layers"]
common = os.path.commonprefix([lean_layers, ci_layers])
delta = {
    "shared_layer_count": len(common),
    "lean_only_layers": lean_layers[len(common):],
    "ci_only_layers": ci_layers[len(common):],
    "lean_size_bytes": lean["Size"],
    "ci_size_bytes": ci["Size"],
    "ci_extra_bytes": ci["Size"] - lean["Size"],
    "note": "ci = lean + Postgres/DuckDB extras; used only for app-runs integration coverage",
}
def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()
jobs = {}
for mode in ("raw", "policy"):
    job = json.load(open(os.path.join(out, "lean", mode, "job.json")))
    jobs[f"lean-{mode}"] = job
manifest = {
    "schema": "hardening-loop/baseline-manifest/v1",
    "source_repo": "Hunter-1298/superset",
    "source_branch": "main",
    "source_sha": sha,
    "trigger": "fixture",
    "platform": platform,
    "built_at": build_date,
    "captured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "images": {
        "lean": {"tag": lean_tag, "image_id": lean_id, "digest_kind": "image_id",
                 "created": lean["Created"], "size_bytes": lean["Size"],
                 "config_user": lean["Config"].get("User"), "labels": lean["Config"].get("Labels")},
        "ci": {"tag": ci_tag, "image_id": ci_id, "digest_kind": "image_id",
               "created": ci["Created"], "size_bytes": ci["Size"],
               "config_user": ci["Config"].get("User")},
    },
    "ci_layer_delta": delta,
    "jobs": jobs,
    "files": {
        f"lean/{m}/{f}": s for m in ("raw", "policy") for f, s in jobs[f"lean-{m}"]["files"].items()
    },
}
for m in ("raw", "policy"):
    for f in ("job.json", "SHA256SUMS"):
        manifest["files"][f"lean/{m}/{f}"] = sha256(os.path.join(out, "lean", m, f))
for f in ("build-lean.log", "build-ci.log"):
    manifest["files"][f] = sha256(os.path.join(out, f))
json.dump(manifest, open(os.path.join(out, "manifest.json"), "w"), indent=2, sort_keys=True)
# Top-level SHA256SUMS covers every file in the evidence directory except itself.
with open(os.path.join(out, "SHA256SUMS"), "w") as fh:
    for rel, digest in sorted(manifest["files"].items()):
        fh.write(f"{digest}  {rel}\n")
    fh.write(f"{sha256(os.path.join(out, 'manifest.json'))}  manifest.json\n")
print(json.dumps({"lean_image_id": lean_id, "ci_image_id": ci_id, "ci_extra_bytes": delta["ci_extra_bytes"]}))
PY
echo "baseline captured in $OUT"
