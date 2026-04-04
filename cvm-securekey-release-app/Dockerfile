# Build AzureAttestSKR for Ubuntu 22.04 CVM
#
# Uses the pre-built azguestattestation1 .deb from packages.microsoft.com
# instead of building the attestation client library from source.
# Build time: ~2 min (vs ~45 min for the source-build approach).
#
# Usage:
#   docker build -t azureattest-skr -f cvm-securekey-release-app/Dockerfile .
#     (run from repo root)
#   docker create --name skr-build azureattest-skr /bin/false
#   docker cp skr-build:/out/ .
#   docker rm skr-build

FROM ubuntu:22.04 AS build

ENV DEBIAN_FRONTEND=noninteractive

# -------------------------------------------------------------------
# 1. Build tools + development libraries for our app only.
#    No autoconf/libtool/libgtest needed — we are NOT building the
#    attestation client library from source.
# -------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ca-certificates wget patchelf \
        libcurl4-openssl-dev \
        nlohmann-json3-dev \
        libssl-dev \
        zlib1g-dev \
        libjsoncpp-dev \
        libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# -------------------------------------------------------------------
# 2. Install the pre-built attestation library from Microsoft.
#    The .deb provides:
#      /usr/lib/libazguestattestation.so*   (the shared library)
#      /usr/local/attestationssl/           (bundled private OpenSSL)
#      /usr/local/attestationcurl/          (bundled private curl ≥7.84)
#      /usr/local/attestationtpm2-tss/      (bundled private tpm2-tss)
#    dpkg may report unmet deps (tpm2-tss runtime etc.) — resolve with
#    apt-get install -f which pulls them in automatically.
# -------------------------------------------------------------------
ARG ATTESTATION_DEB_URL=https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.1.2_amd64.deb
RUN wget -q "${ATTESTATION_DEB_URL}" -O /tmp/azguestattestation1.deb \
    && dpkg -i /tmp/azguestattestation1.deb || true \
    && apt-get update && apt-get install -f -y --no-install-recommends \
    && rm -f /tmp/azguestattestation1.deb \
    && rm -rf /var/lib/apt/lists/* \
    && ldconfig

# -------------------------------------------------------------------
# 3. Build AzureAttestSKR against system OpenSSL/curl (from apt).
#    The attestation library uses its own bundled OpenSSL/curl
#    internally (via RUNPATH), which is transparent to our app.
# -------------------------------------------------------------------
WORKDIR /repo/cvm-securekey-release-app
COPY cvm-securekey-release-app/ .
RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DSKR_PORTABLE_DEPLOY=ON \
    && cmake --build build

# -------------------------------------------------------------------
# 4. Strip the private RUNPATH from the attestation .so.
#    The .deb hardcodes /usr/local/attestation{ssl,curl,tpm2-tss}/lib*
#    in RUNPATH. With it removed, the library resolves OpenSSL, curl,
#    and tpm2-tss from standard system paths at runtime instead.
#    This also fixes the curl-ca-bundle.crt issue: system curl has
#    the correct CA cert path compiled in, so no fallback file needed.
#
#    Stage the .so to a known path for the output COPY.
# -------------------------------------------------------------------
RUN ATTEST_SO=$(find /usr/lib -name 'libazguestattestation.so.*.*.*' | head -1) \
    && echo "Patching: $ATTEST_SO" \
    && patchelf --remove-rpath "$ATTEST_SO" \
    && SONAME=$(patchelf --print-soname "$ATTEST_SO") \
    && mkdir -p /staging \
    && cp "$ATTEST_SO" "/staging/${SONAME}"

# -------------------------------------------------------------------
# Output stage — binary + attestation shared library only.
# All other dependencies (OpenSSL 3.x, curl, tpm2-tss, etc.) come
# from system packages on the target machine.
#
# Target requirements:
#   Ubuntu 22.04+:  apt install libcurl4 libssl3 libtss2-esys-3.0.2-0
#   RHEL 9+:        dnf install openssl-libs libcurl tpm2-tss
#
# Deploy layout (flat — .so next to binary):
#   ./AzureAttestSKR                   (executable, RPATH=$ORIGIN)
#   ./libazguestattestation.so.1       (attestation library, no RUNPATH)
# -------------------------------------------------------------------
FROM scratch AS output
COPY --from=build /repo/cvm-securekey-release-app/build/AzureAttestSKR /out/AzureAttestSKR
COPY --from=build /staging/libazguestattestation.so.1                  /out/libazguestattestation.so.1
