#!/usr/bin/env bash
# Install pinned Syft / Trivy / Grype for linux/amd64 with hard-pinned SHA-256 verification.
#
# The SHA-256 values below were taken from each project's published *_checksums.txt for the
# pinned release. Any mismatch aborts. When VERIFY_SIGNATURES=1 and cosign is present, the
# published checksums file is additionally verified against the project's keyless Sigstore
# signature (Syft/Grype: .pem+.sig; Trivy: .sigstore.json bundle) and cross-checked against the
# pinned digests, so a tampered checksums file cannot go unnoticed either.
#
# Usage: scripts/install_scanners.sh [DEST_DIR]      (default: /usr/local/bin if writable, else ~/.local/bin)
set -euo pipefail

SYFT_VERSION="${SYFT_VERSION:-1.45.1}"
TRIVY_VERSION="${TRIVY_VERSION:-0.71.2}"
GRYPE_VERSION="${GRYPE_VERSION:-0.114.0}"

SYFT_SHA256="20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716"
TRIVY_SHA256="0510e71e2fd39bf863856d499c8dc19feb4e7336546394c502a8f5cc7ab27460"
GRYPE_SHA256="edda0968d8827daab01d32b3cd7de192ae0915005e7bbfcfef9e68e79bc43343"

SYFT_ASSET="syft_${SYFT_VERSION}_linux_amd64.tar.gz"
TRIVY_ASSET="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
GRYPE_ASSET="grype_${GRYPE_VERSION}_linux_amd64.tar.gz"

SYFT_BASE="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}"
TRIVY_BASE="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"
GRYPE_BASE="https://github.com/anchore/grype/releases/download/v${GRYPE_VERSION}"

if [[ -n "${1:-}" ]]; then
  DEST="$1"
elif [[ -w /usr/local/bin ]]; then
  DEST=/usr/local/bin
else
  DEST="${HOME}/.local/bin"
fi
mkdir -p "$DEST"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

fetch() { curl -fsSL --retry 3 --retry-delay 2 -o "$2" "$1"; }

verify_sha256() {
  local file="$1" expected="$2" actual
  actual="$(sha256sum "$file" | awk '{print $1}')"
  if [[ "$actual" != "$expected" ]]; then
    echo "::error::checksum mismatch for $(basename "$file"): expected $expected got $actual" >&2
    exit 1
  fi
  echo "verified sha256 $(basename "$file") = $actual"
}

# $1 checksums file, $2 asset name, $3 pinned digest
cross_check_checksums_file() {
  local listed
  listed="$(awk -v a="$2" '$2==a {print $1}' "$1")"
  if [[ "$listed" != "$3" ]]; then
    echo "::error::published checksums file lists $listed for $2 but pinned digest is $3" >&2
    exit 1
  fi
}

verify_signatures="${VERIFY_SIGNATURES:-0}"
if [[ "$verify_signatures" == "1" ]] && ! command -v cosign >/dev/null 2>&1; then
  echo "::error::VERIFY_SIGNATURES=1 but cosign is not installed" >&2
  exit 1
fi

install_tool() {
  # $1 name  $2 base url  $3 asset  $4 sha256  $5 checksums file name  $6 sig style (anchore|trivy)  $7 identity regexp
  local name="$1" base="$2" asset="$3" sha="$4" sums="$5" style="$6" ident="$7"
  fetch "${base}/${asset}" "${WORK}/${asset}"
  verify_sha256 "${WORK}/${asset}" "$sha"

  fetch "${base}/${sums}" "${WORK}/${sums}"
  cross_check_checksums_file "${WORK}/${sums}" "$asset" "$sha"

  if [[ "$verify_signatures" == "1" ]]; then
    if [[ "$style" == "anchore" ]]; then
      fetch "${base}/${sums}.pem" "${WORK}/${sums}.pem"
      fetch "${base}/${sums}.sig" "${WORK}/${sums}.sig"
      cosign verify-blob \
        --certificate "${WORK}/${sums}.pem" --signature "${WORK}/${sums}.sig" \
        --certificate-identity-regexp "$ident" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "${WORK}/${sums}"
    else
      fetch "${base}/${sums}.sigstore.json" "${WORK}/${sums}.sigstore.json"
      cosign verify-blob --new-bundle-format \
        --bundle "${WORK}/${sums}.sigstore.json" \
        --certificate-identity-regexp "$ident" \
        --certificate-oidc-issuer https://token.actions.githubusercontent.com \
        "${WORK}/${sums}"
    fi
    echo "verified sigstore signature on ${sums}"
  fi

  tar -xzf "${WORK}/${asset}" -C "$WORK" "$name"
  install -m 0755 "${WORK}/${name}" "${DEST}/${name}"
}

install_tool syft "$SYFT_BASE" "$SYFT_ASSET" "$SYFT_SHA256" "syft_${SYFT_VERSION}_checksums.txt" anchore \
  '^https://github.com/anchore/syft/\.github/workflows/release\.yaml@refs/(heads/main|tags/v'"${SYFT_VERSION}"')$'
install_tool trivy "$TRIVY_BASE" "$TRIVY_ASSET" "$TRIVY_SHA256" "trivy_${TRIVY_VERSION}_checksums.txt" trivy \
  '^https://github.com/aquasecurity/trivy/\.github/workflows/'
install_tool grype "$GRYPE_BASE" "$GRYPE_ASSET" "$GRYPE_SHA256" "grype_${GRYPE_VERSION}_checksums.txt" anchore \
  '^https://github.com/anchore/grype/\.github/workflows/release\.yaml@refs/(heads/main|tags/v'"${GRYPE_VERSION}"')$'

"${DEST}/syft" version | grep -q "${SYFT_VERSION}"
"${DEST}/trivy" --version | grep -q "${TRIVY_VERSION}"
"${DEST}/grype" version | grep -q "${GRYPE_VERSION}"
echo "installed syft ${SYFT_VERSION}, trivy ${TRIVY_VERSION}, grype ${GRYPE_VERSION} into ${DEST}"
