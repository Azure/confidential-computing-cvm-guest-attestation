#!/bin/bash
set -euo pipefail

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

# Add packages.microsoft.com insiders-fast to apt sources
if [ -e /etc/apt/sources.list.d/microsoft-insiders-fast.list ]; then
    echo "insiders-fast repo already configured."
    exit 0
fi

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# Setup PMC GPG keys
# SHA256 hashes published by Microsoft at: https://packages.microsoft.com/keys/FILE_MANIFEST
# To update: check FILE_MANIFEST for current hashes, or wget the keys and run `sha256sum`.

# Legacy key (pre-Spring 2025 repos)
wget -q https://packages.microsoft.com/keys/microsoft.asc -O "$TMPDIR/microsoft.asc"
verify_sha256 "$TMPDIR/microsoft.asc" \
    "2fa9c05d591a1582a9aba276272478c262e95ad00acf60eaee1644d93941e3c6"
gpg --dearmor "$TMPDIR/microsoft.asc"
mv "$TMPDIR/microsoft.asc.gpg" /etc/apt/trusted.gpg.d/

# Current key (Spring 2025+ repos)
wget -q https://packages.microsoft.com/keys/microsoft-2025.asc -O "$TMPDIR/microsoft-2025.asc"
verify_sha256 "$TMPDIR/microsoft-2025.asc" \
    "d45224d594d969f084232deaaf97c58ca502a9d964c362d7aaef5a76e16b3dd1"
gpg --dearmor "$TMPDIR/microsoft-2025.asc"
mv "$TMPDIR/microsoft-2025.asc.gpg" /etc/apt/trusted.gpg.d/

# Add insiders-fast apt source
# SHA256 computed from: https://packages.microsoft.com/config/ubuntu/22.04/insiders-fast.list
# No published manifest for config files — to update, wget the URL and run `sha256sum`.
wget -q https://packages.microsoft.com/config/ubuntu/22.04/insiders-fast.list -O "$TMPDIR/insiders-fast.list"
verify_sha256 "$TMPDIR/insiders-fast.list" \
    "2d7bf753c6036b8e894c93a65b0ce669906ebe54ba2db7107900e7e99ae47712"
cp "$TMPDIR/insiders-fast.list" /etc/apt/sources.list.d/microsoft-insiders-fast.list