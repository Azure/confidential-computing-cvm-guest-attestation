#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR="${SCRIPT_DIR}/output"
CLEAN_BUILD=false
INSTALL_PREREQS=false

# Make all .sh scripts in the repo executable
find "${SCRIPT_DIR}" -type f -name "*.sh" -exec chmod +x {} +

function Usage()
{
    echo "Usage: $0 [-h] [-c] [-p] --> where -c cleans and rebuilds everything before gathering, -p installs pre-requisites.";
    exit 1;
}

while getopts ":hcp" opt; do
  case ${opt} in
    h )
        Usage
      ;;
    c )
        CLEAN_BUILD=true
      ;;
    p )
        INSTALL_PREREQS=true
      ;;
    \? )
        Usage
      ;;
  esac
done

# Build pre-requisite flags to forward
CLIENT_LIB_FLAGS=""
if [ "$INSTALL_PREREQS" = true ]; then
    CLIENT_LIB_FLAGS="-p"
fi

if [ "$CLEAN_BUILD" = true ]; then
    echo "=== Clean rebuild ==="

    # Rebuild attestation library for Azure Local
    echo "Rebuilding attestation library (Azure Local)..."
    pushd "${SCRIPT_DIR}/cvm-attestation-sample-app" > /dev/null
    sudo ./ClientLibBuildAndInstallAzureLocal.sh ${CLIENT_LIB_FLAGS}
    popd > /dev/null

    # Clean and rebuild AttestationClient
    echo "Cleaning AttestationClient..."
    rm -rf "${SCRIPT_DIR}/cvm-attestation-sample-app/build"
    mkdir -p "${SCRIPT_DIR}/cvm-attestation-sample-app/build"
    pushd "${SCRIPT_DIR}/cvm-attestation-sample-app/build" > /dev/null
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make
    popd > /dev/null

    # Clean and rebuild AzureAttestSKR
    echo "Cleaning AzureAttestSKR..."
    rm -rf "${SCRIPT_DIR}/cvm-securekey-release-app/build"
    mkdir -p "${SCRIPT_DIR}/cvm-securekey-release-app/build"
    pushd "${SCRIPT_DIR}/cvm-securekey-release-app/build" > /dev/null
    cmake .. -DCMAKE_BUILD_TYPE=Release -DAZURE_LOCAL=ON
    make
    popd > /dev/null

    # Clean artifacts
    rm -rf "${OUTPUT_DIR}"
fi

echo "=== Gathering artifacts into ${OUTPUT_DIR} ==="
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

# Attestation library deb package
ATTEST_DEB="${SCRIPT_DIR}/client-library/src/Attestation/_build/x86_64/packages/attestationlibrary/deb/azguestattestation1_1.0.5_amd64.deb"
if [ ! -f "${ATTEST_DEB}" ]; then
    echo "Building attestation library (Azure Local)..."
    pushd "${SCRIPT_DIR}/cvm-attestation-sample-app" > /dev/null
    sudo ./ClientLibBuildAndInstallAzureLocal.sh ${CLIENT_LIB_FLAGS}
    popd > /dev/null
fi
if [ -f "${ATTEST_DEB}" ]; then
    cp "${ATTEST_DEB}" "${OUTPUT_DIR}/"
    echo "[OK] azguestattestation1_1.0.5_amd64.deb"
else
    echo "[MISSING] ${ATTEST_DEB}"
fi

# AttestationClient sample app
ATTEST_APP="${SCRIPT_DIR}/cvm-attestation-sample-app/build/AttestationClient"
if [ ! -f "${ATTEST_APP}" ]; then
    echo "Building AttestationClient..."
    mkdir -p "${SCRIPT_DIR}/cvm-attestation-sample-app/build"
    pushd "${SCRIPT_DIR}/cvm-attestation-sample-app/build" > /dev/null
    cmake .. -DCMAKE_BUILD_TYPE=Release
    make
    popd > /dev/null
fi
if [ -f "${ATTEST_APP}" ]; then
    cp "${ATTEST_APP}" "${OUTPUT_DIR}/"
    echo "[OK] AttestationClient"
else
    echo "[MISSING] ${ATTEST_APP}"
fi

# AzureAttestSKR (Secure Key Release app)
SKR_APP="${SCRIPT_DIR}/cvm-securekey-release-app/build/AzureAttestSKR"
if [ ! -f "${SKR_APP}" ]; then
    echo "Building AzureAttestSKR..."
    mkdir -p "${SCRIPT_DIR}/cvm-securekey-release-app/build"
    pushd "${SCRIPT_DIR}/cvm-securekey-release-app/build" > /dev/null
    cmake .. -DCMAKE_BUILD_TYPE=Release -DAZURE_LOCAL=ON
    make
    popd > /dev/null
fi
if [ -f "${SKR_APP}" ]; then
    cp "${SKR_APP}" "${OUTPUT_DIR}/"
    echo "[OK] AzureAttestSKR"
else
    echo "[MISSING] ${SKR_APP}"
fi

# Certs bundle
CERTS_BUNDLE="${SCRIPT_DIR}/cvm-attestation-sample-app/certs/curl-ca-bundle.crt"
if [ -f "${CERTS_BUNDLE}" ]; then
    cp "${CERTS_BUNDLE}" "${OUTPUT_DIR}/"
    echo "[OK] curl-ca-bundle.crt"
else
    echo "[MISSING] ${CERTS_BUNDLE}"
fi

# Deploy script (bundle into artifacts folder)
DEPLOY_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Deploy-Artifacts.ps1"
if [ -f "${DEPLOY_SCRIPT}" ]; then
    cp "${DEPLOY_SCRIPT}" "${OUTPUT_DIR}/"
    echo "[OK] Deploy-Artifacts.ps1"
else
    echo "[MISSING] ${DEPLOY_SCRIPT}"
fi

# Install script (bundle into artifacts folder)
INSTALL_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/Install-Artifacts.sh"
if [ -f "${INSTALL_SCRIPT}" ]; then
    cp "${INSTALL_SCRIPT}" "${OUTPUT_DIR}/"
    chmod +x "${OUTPUT_DIR}/Install-Artifacts.sh"
    echo "[OK] Install-Artifacts.sh"
else
    echo "[MISSING] ${INSTALL_SCRIPT}"
fi

echo ""
echo "=== Artifacts ==="
ls -lh "${OUTPUT_DIR}/"
