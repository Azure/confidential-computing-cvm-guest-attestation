#!/bin/bash
set -e

# repostiory marks scripts as non-executable, here are commands to find and apply executable permissions to all .sh files in the repository, you can run these commands in the root of the repository
#find . -type f -name "*.sh"
# apply
#find . -type f -name "*.sh" -exec chmod +x {} +

INSTALL_PREREQS=false
USE_INSIDERS_FAST=false

function Usage()
{
    echo "Usage: $0 [-h] [-p] [-i]"
    echo "  -p  Install pre-requisites."
    echo "  -i  Use insiders-fast for the evidence SDK (requires -p)."
    exit "${1:-1}"
}

while getopts ":hpi" opt; do
  case ${opt} in
    h )
        Usage 0
      ;;
    p )
        INSTALL_PREREQS=true
      ;;
    i )
        USE_INSIDERS_FAST=true
      ;;
    \? )
        Usage
      ;;
  esac
done
shift $((OPTIND - 1))
if [ "$#" -ne 0 ]; then
    Usage
fi
if [ "$USE_INSIDERS_FAST" = true ] && [ "$INSTALL_PREREQS" != true ]; then
    echo "[ERROR] -i requires -p to install pre-requisites." >&2
    exit 1
fi

sudo rm -rf ../client-library/src/Attestation/_build
sudo dpkg -r azguestattestation1 2>/dev/null || true

if [ "$INSTALL_PREREQS" = true ]; then
  if [ "$USE_INSIDERS_FAST" = true ]; then
    sudo ../client-library/src/Attestation/pre-requisites-azure-local.sh -i
  else
    sudo ../client-library/src/Attestation/pre-requisites-azure-local.sh
  fi
fi

sudo ../client-library/src/Attestation/build.sh -l
sudo dpkg -i ../client-library/src/Attestation/_build/x86_64/packages/attestationlibrary/deb/azguestattestation1_1.0.5_amd64.deb