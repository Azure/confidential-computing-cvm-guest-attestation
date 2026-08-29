#!/usr/bin/env bash
#
# generate-source-tarball.sh
#
# Produces the Fedora Source0 tarball for azure-protected-vm-secrets: a
# `git archive` of ONLY the azure-protected-vm-secrets/ component subtree at an
# upstream release tag. This is intentionally NOT GitHub's auto-generated
# whole-repo tag archive, because that archive:
#   1. is not byte-reproducible (breaks fedora-review's "sources match upstream"
#      checksum check), and
#   2. bundles ~27 MB of unrelated monorepo content (e.g. a demo .mp4) that is
#      impermissible in the Fedora SRPM.
#
# The resulting tarball has a single top-level directory,
# azure-protected-vm-secrets-<version>/, matching the spec's
# `%autosetup -n %{name}-%{version}`.
#
# Fedora workflow: run this to (re)generate the tarball, then upload it to the
# lookaside cache with `fedpkg new-sources azure-protected-vm-secrets-<ver>.tar.gz`.
# The Source0 in the spec is a bare filename (no URL) on purpose.
#
# Usage:
#   generate-source-tarball.sh <version> [git-ref] [upstream-repo-url]
#
#   <version>          e.g. 1.0.9 (the tarball/version to produce)
#   [git-ref]          tag/commit to archive from.
#                      Default: azure-protected-vm-secrets-v<version>
#   [upstream-repo-url] Default:
#                      https://github.com/Azure/confidential-computing-cvm-guest-attestation
#
# Requires: git.

set -euo pipefail

NAME="azure-protected-vm-secrets"
SUBDIR="azure-protected-vm-secrets"

VERSION="${1:-}"
if [[ -z "${VERSION}" ]]; then
    echo "ERROR: version argument required (e.g. ${0##*/} 1.0.9)" >&2
    exit 2
fi
REF="${2:-${NAME}-v${VERSION}}"
UPSTREAM="${3:-https://github.com/Azure/confidential-computing-cvm-guest-attestation}"

PREFIX="${NAME}-${VERSION}"
OUT="${NAME}-${VERSION}.tar.gz"

echo "Generating ${OUT}"
echo "  upstream : ${UPSTREAM}"
echo "  ref      : ${REF}"
echo "  subtree  : ${SUBDIR}/"
echo "  prefix   : ${PREFIX}/"

# Archive directly from the remote by ref, extracting only the component
# subtree. This does not require a full local clone.
#
# Note: `git archive --remote` support varies by host; GitHub does not enable
# the git upload-archive service, so we fetch the ref into a throwaway shallow
# clone and archive locally (deterministic output).
WORKDIR="$(mktemp -d)"
trap 'rm -rf "${WORKDIR}"' EXIT

OUT_ABS="$(pwd)/${OUT}"
git -C "${WORKDIR}" init -q
git -C "${WORKDIR}" remote add origin "${UPSTREAM}"
git -C "${WORKDIR}" fetch -q --depth 1 origin "${REF}"
git -C "${WORKDIR}" archive --format=tar.gz \
    --prefix="${PREFIX}/" \
    FETCH_HEAD:"${SUBDIR}" \
    -o "${OUT_ABS}"

echo "Wrote ${OUT}"
sha256sum "${OUT}" 2>/dev/null || shasum -a 256 "${OUT}"
echo
echo "Next: fedpkg new-sources ${OUT}"
