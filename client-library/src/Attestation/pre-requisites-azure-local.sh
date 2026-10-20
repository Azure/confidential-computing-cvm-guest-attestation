#!/bin/bash
# Pre-requisites for Azure Local builds.
# This script installs everything from the standard pre-requisites.sh
# and additionally installs the edge-cc-base-attestation-sdk from the
# production PMC feed (or insiders-fast with -i) and libtss2-dev.

set -e

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
USE_INSIDERS_FAST=false

usage() {
    echo "Usage: $0 [-h] [-i]"
    echo "  -i  Install the evidence SDK from insiders-fast instead of production PMC."
}

while getopts ":hi" opt; do
    case "$opt" in
        h) usage; exit 0 ;;
        i) USE_INSIDERS_FAST=true ;;
        *) usage >&2; exit 1 ;;
    esac
done
shift $((OPTIND - 1))
if [ "$#" -ne 0 ]; then
    usage >&2
    exit 1
fi

# Run the standard pre-requisites
echo "=== Running standard pre-requisites ==="
"${CURRENT_DIR}/pre-requisites.sh"


# Install tpm2 tss development libraries and tools
echo "=== Installing libtss2-dev ==="
sudo apt-get install -y libtss2-dev

# Configure the selected PMC feed if it is not already present.
if [ "$USE_INSIDERS_FAST" = true ]; then
    sudo bash "${CURRENT_DIR}/enable-pmc-repo.sh" -i
else
    sudo bash "${CURRENT_DIR}/enable-pmc-repo.sh"
fi
sudo apt-get update

# Select the suite explicitly so an existing insiders-fast source cannot override
# production. Allow switching back to production even if a newer preview is installed.
. /etc/os-release
SDK_SUITE="$VERSION_CODENAME"
if [ "$USE_INSIDERS_FAST" = true ]; then
    SDK_SUITE=insiders-fast
fi
echo "=== Installing edge-cc-base-attestation-sdk from ${SDK_SUITE} ==="
sudo apt-get install -y --allow-downgrades "edge-cc-base-attestation-sdk/${SDK_SUITE}"

echo "=== Azure Local pre-requisites complete ==="
