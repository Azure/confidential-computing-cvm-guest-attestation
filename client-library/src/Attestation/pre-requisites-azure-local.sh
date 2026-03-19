#!/bin/bash
# Pre-requisites for Azure Local builds.
# This script installs everything from the standard pre-requisites.sh
# and additionally installs the edge-cc-base-attestation-sdk from the
# insiders-fast repo and the tpm2-tools (libtss2-dev) package.

set -e

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Run the standard pre-requisites
echo "=== Running standard pre-requisites ==="
"${CURRENT_DIR}/pre-requisites.sh"


# Install tpm2 tss development libraries and tools
echo "=== Installing libtss2-dev ==="
sudo apt-get install -y libtss2-dev

# Enable insiders-fast repo and install edge-cc-base-attestation-sdk
if ! [ -e /etc/apt/sources.list.d/microsoft-insiders-fast.list ]; then
    read -r -p "The insiders-fast repo is not configured. Enable it now? [y/N] " response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        echo "=== Enabling insiders-fast repo ==="
        sudo "${CURRENT_DIR}/enable-insider-fast-repo.sh"
        sudo apt-get update
    else
        echo "[ERROR] insiders-fast repo is required to install edge-cc-base-attestation-sdk."
        exit 1
    fi
fi
echo "=== Installing edge-cc-base-attestation-sdk ==="
sudo apt-get install -y edge-cc-base-attestation-sdk

echo "=== Azure Local pre-requisites complete ==="
