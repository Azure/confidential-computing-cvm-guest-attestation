#!/bin/bash
set -euo pipefail

# Configure the production PMC feed by default; -i opts into insiders-fast.
FEED=prod

usage() {
    echo "Usage: $0 [-h] [-i]"
    echo "  -i  Use insiders-fast instead of the production PMC feed."
}

while getopts ":hi" opt; do
    case "$opt" in
        h) usage; exit 0 ;;
        i) FEED=insiders-fast ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))
if [ "$#" -ne 0 ]; then
    usage >&2
    exit 1
fi

# Verify the SHA256 checksum of a downloaded file.
# Usage: verify_sha256 <file> <expected_hash>
verify_sha256() {
    local file="$1"
    local expected_hash="$2"
    local actual_hash
    actual_hash=$(sha256sum "$file" | awk '{print $1}')
    if [ "$actual_hash" != "$expected_hash" ]; then
        echo "SHA256 mismatch for $file!" >&2
        return 1
    fi
}

# Add the selected packages.microsoft.com feed only if it is not configured.
SOURCE_LIST="/etc/apt/sources.list.d/microsoft-${FEED}.list"
if [ -e "$SOURCE_LIST" ]; then
    echo "${FEED} repo already configured."
    exit 0
fi

# Detect Ubuntu version to pick the matching PMC config.
. /etc/os-release
case "${ID:-}:${VERSION_ID:-}" in
    ubuntu:22.04)
        PROD_LIST_SHA256="54d0a050a21eee01a6ef32bc5e39c74d30888c28ca2381f1673d5d87fbd1c35e"
        INSIDERS_FAST_LIST_SHA256="2d7bf753c6036b8e894c93a65b0ce669906ebe54ba2db7107900e7e99ae47712"
        ;;
    ubuntu:24.04)
        PROD_LIST_SHA256="b1603241c9619c02611a77a663f55e726608bde079c4f559bcccdf73847a45c8"
        INSIDERS_FAST_LIST_SHA256="6106538850c7fbb89616393aa7a9ed1094e653603a1b76dd4d7512417cfb6cf8"
        ;;
    *)
        echo "Unsupported distribution: ${ID:-unknown} ${VERSION_ID:-unknown}. Expected Ubuntu 22.04 or 24.04." >&2
        exit 1
        ;;
esac

LIST_SHA256="$PROD_LIST_SHA256"
if [ "$FEED" = insiders-fast ]; then
    LIST_SHA256="$INSIDERS_FAST_LIST_SHA256"
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# SHA256 computed from: https://packages.microsoft.com/config/ubuntu/<version>/<feed>.list
# No published manifest for config files — to update, wget the URL and run `sha256sum`.
# Validate the downloaded feed before installing it.
wget -q "https://packages.microsoft.com/config/ubuntu/${VERSION_ID}/${FEED}.list" \
    -O "$TMPDIR/${FEED}.list"
verify_sha256 "$TMPDIR/${FEED}.list" "$LIST_SHA256"

# Setup PMC GPG keys.
# SHA256 hashes published by Microsoft at: https://packages.microsoft.com/keys/FILE_MANIFEST
# To update: check FILE_MANIFEST for current hashes, or wget the keys and run `sha256sum`.

# Legacy key (pre-Spring 2025 repos)
wget -q https://packages.microsoft.com/keys/microsoft.asc -O "$TMPDIR/microsoft.asc"
verify_sha256 "$TMPDIR/microsoft.asc" \
    "2fa9c05d591a1582a9aba276272478c262e95ad00acf60eaee1644d93941e3c6"
gpg --dearmor "$TMPDIR/microsoft.asc"
cp "$TMPDIR/microsoft.asc.gpg" /etc/apt/trusted.gpg.d/
cp "$TMPDIR/microsoft.asc.gpg" /usr/share/keyrings/microsoft-prod.gpg

# Current key (Spring 2025+ repos)
wget -q https://packages.microsoft.com/keys/microsoft-2025.asc -O "$TMPDIR/microsoft-2025.asc"
verify_sha256 "$TMPDIR/microsoft-2025.asc" \
    "d45224d594d969f084232deaaf97c58ca502a9d964c362d7aaef5a76e16b3dd1"
gpg --dearmor "$TMPDIR/microsoft-2025.asc"
cp "$TMPDIR/microsoft-2025.asc.gpg" /etc/apt/trusted.gpg.d/
cp "$TMPDIR/microsoft-2025.asc.gpg" /usr/share/keyrings/microsoft-prod-2025.gpg

cp "$TMPDIR/${FEED}.list" "$SOURCE_LIST"
echo "=== Configured PMC ${FEED} feed for Ubuntu ${VERSION_ID} ==="