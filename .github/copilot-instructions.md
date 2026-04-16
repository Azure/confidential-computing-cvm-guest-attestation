# Copilot Instructions

## Project Overview

This repository provides open-source client libraries and tools for **Azure Confidential VM (CVM) guest attestation** and **protected VM secrets provisioning**. It enables guests running on AMD SEV-SNP hardware to cryptographically verify their runtime environment via Microsoft Azure Attestation (MAA) and to decrypt secrets protected from the host by Azure.

## Architecture

The repo contains two independent C++ library projects plus sample apps:

### Attestation Client Library (`client-library/src/Attestation/`)

- **LinuxTpm/** — Low-level TPM 2.0 operations (read NV indices, unseal, get quotes). Wraps tpm2-tss. Has its own unit tests (`unittests/`).
- **AttestationClient/** — High-level attestation logic. `AttestationClientImpl` implements the `AttestationClient` abstract interface (defined in `AttestationClient/lib/include/AttestationClient.h`). Key operations: `Attest()` (get JWT from MAA), `Encrypt()`, `Decrypt()`.
  - `lib/DynamicLibrary/` — Builds `libazguestattestation.so`, the shared library consumers link against. Packaged as a `.deb`.
  - `tests/lib/` — Unit tests (`AttestationClientLibTests`).
- **External dependencies** are vendored in `client-library/src/external/` (SnpVmReport headers, jsoncpp).
- Uses C++14 (`CMAKE_CXX_STANDARD 14`). Uses a custom OpenSSL build installed to `/usr/local/attestationssl` and custom curl to `/usr/local/attestationcurl`.

### Azure Protected VM Secrets Library (`azure-protected-vm-secrets/`)

- Decrypts secrets from JWTs signed/encrypted with TPM-bound keys. Core API: `unprotect_secret()` / `unprotect_secret_wide()`.
- Platform-specific crypto: `Linux/` uses OpenSSL; `Windows/` uses BCrypt.
- Builds static lib, dynamic lib (`DynamicSecretsProvisioningLibrary`), CLI tool (`azure-protected-secrets-tool`), and sample app.
- Uses C++17 (`CMAKE_CXX_STANDARD 17`). Depends on Boost, nlohmann/json (fetched via CMake FetchContent), tpm2-tss, OpenSSL, systemd (optional).

### Sample / Utility Apps

- **`cvm-attestation-sample-app/`** — Standalone Linux app that links `libazguestattestation` and demonstrates attestation flow.
- **`cvm-securekey-release-app/`** — Demonstrates secure key release using attestation.
- **`aks-linux-sample/`** — Dockerfile and Kubernetes YAML for running attestation in AKS containers.
- **`cvm-platform-checker-exe/`** — Platform checker tool (Windows and Linux).

## Build Commands

All builds are Linux-primary and require running on an Ubuntu-based system (tested on Ubuntu 20, 22, 24).

### Attestation Client Library

```bash
# Install all prerequisites (builds custom OpenSSL, curl, tpm2-tss from source)
sudo ./client-library/src/Attestation/pre-requisites.sh

# Build (release)
sudo ./client-library/src/Attestation/build.sh

# Build (debug)
sudo ./client-library/src/Attestation/build.sh -d
```

Output goes to `client-library/src/Attestation/_build/x86_64/`.

### Azure Protected VM Secrets Library

```bash
cd azure-protected-vm-secrets
mkdir build && cd build
cmake ..
make
```

On Windows, open `SecretsProvisioningLibrary.sln` in Visual Studio.

## Test Commands

### Attestation Client Library

```bash
# Run all tests
./client-library/src/Attestation/run_tests.sh

# Run LinuxTpm unit tests only
./client-library/src/Attestation/_build/x86_64/LinuxTpm/unittests/LinuxTpmTests

# Run AttestationClient unit tests only
./client-library/src/Attestation/_build/x86_64/AttestationClient/tests/lib/AttestationClientLibTests
```

### Azure Protected VM Secrets Library

```bash
# Unit tests (no TPM required)
./azure-protected-vm-secrets/build/SecretsProvsioningUT/SecretsProvsioningUT

# CLI tool unit tests (no TPM required)
./azure-protected-vm-secrets/build/azure-protected-secrets-tool/tests/<test_binary>

# Functionality tests (requires real vTPM on a CVM)
./azure-protected-vm-secrets/build/SecretsProvisioningFunctionalityTest/SecretsProvisioningFunctionalityTest
```

All tests use **Google Test** (gtest/gmock). Run a single test with `--gtest_filter=TestSuiteName.TestName`.

## Key Conventions

- **Platform abstraction via `#ifdef PLATFORM_UNIX`** — Both libraries define `-DPLATFORM_UNIX` in CMake for Linux builds. Platform-specific implementations live in `Linux/` and `Windows/` subdirectories.
- **Namespace `attest::`** — The attestation library uses the `attest` namespace for its types (`AttestationResult`, `ClientParameters`, `ErrorCode`, etc.).
- **Singleton pattern** — `AttestationClient` is initialized via `Initialize()` / `Uninitialize()` C functions that manage a global singleton. Callers must pass an `AttestationLogger` implementation.
- **Manual memory management** — Public C APIs allocate memory that callers must free via provided `Free()` / `free_secret()` functions. Do not use `delete` on library-allocated buffers.
- **Error codes** — The secrets library uses structured negative return codes where octets encode error class (General/TPM/Crypto/JWT). The attestation library returns `AttestationResult` objects with `ErrorCode` enums.
- **Note the typo**: The unit test directory is `SecretsProvsioningUT` (missing 'i' in Provisioning). This is intentional/historical — do not rename it.
- **CI** — CodeQL analysis runs on push/PR to `main` (`.github/workflows/codeql.yml`). The workflow builds `azure-protected-vm-secrets` via its `build.sh`.
