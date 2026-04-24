# AKV (or mHSM) Secure Key Release sample application

The code in this directory demonstrates how to get an asymetric encryption key stored in Azure Keyvault or managed HSM released to a Linux Confidential or Trusted Launch VM. The attesting of the VM state cryptographically verifies it meets the requirements of a baseline attestation policy. The securely released asymmetric key can be used to wrap and unwrap a symmetric key.

## Build Instructions for Linux

Create a Linux Confidential or Trusted Launch virtual machine in Azure, tested on Ubuntu 22.04 and 24.04 with openssl 3.0.x package.

Use the below command to install the `build-essential` package. This package will install everything required for compiling our sample application written in C++.

```sh
$ sudo apt-get install -y build-essential
```

Install the below packages

```sh
$ sudo apt-get install -y libssl-dev libcurl4-openssl-dev libjsoncpp-dev libboost-all-dev nlohmann-json3-dev cmake
```

Download the latest attestation package from the following location - https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/

Use the below command to install the attestation package

```sh
$ wget https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.1.2_amd64.deb
$ sudo dpkg -i azguestattestation1_1.1.2_amd64.deb
```
Note for Azure Local the attestation package must be built from source with Azure Local support enabled.
Use the following script from the repo root to build and install:

```sh
$ cd cvm-attestation-sample-app/
$ sudo ./ClientLibBuildAndInstallAzureLocal.sh -p  # -p to install pre-requisites (first time only)
```

See client-library/src/Readme.md for more details.

Once the above packages have been installed, use below steps to build and run the app

```sh
$ git clone --recursive https://github.com/Azure/confidential-computing-cvm-guest-attestation
$ cd confidential-computing-cvm-guest-attestation
$ cd cvm-securekey-release-app/
$ mkdir build && cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Release  # Debug for more tracing output and define TRACE constant in CMakeLists.txt
$ make
```

# Execution instructions.

1- Create or use an existing Azure KeyVault in your subscription.
2- Create an RSA key with below sample confidentiality policy for Azure.

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://sharedweu.weu.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-isolation-tee.x-ms-attestation-type",
          "equals": "sevsnpvm"
        },
        {
          "claim": "x-ms-isolation-tee.x-ms-compliance-status",
          "equals": "azure-compliant-cvm"
        }
      ]
    }
  ]
}
```

For Azure Local, use the following SKR sample policy:

```json
{
  "version": "1.0.0",
  "anyOf": [
    {
      "authority": "https://sharedweu.weu.attest.azure.net",
      "allOf": [
        {
          "claim": "x-ms-isolation-tee.x-ms-sevsnpvm-is-debuggable",
          "equals": "false"
        },
        {
          "claim": "x-ms-isolation-tee.x-ms-attestation-type",
          "equals": "sevsnpvm"
        },
        {
          "claim": "x-ms-policy.edge-compliant-cvm",
          "equals": "true"
        }
      ]
    }
  ]
}
```

3- Create or use an existing Managed Identity (user-assigned).

> **⚠️ Azure Local Note:** Managed Identities are not supported on Azure Local CVMs. Use a Service Principal (`-c sp`) instead. See the `-c` option below for details.
4- Assign the managed identity to the confidential VM.
4- Grant 'Get' and 'Release' permissions to the managed identity in the Azure Keyvault access policies.
5- Copy the built sample application to your target confidential VM.

```sh
scp -P 22 -i ssh.key AzureAttestSKR user@<VM_ip>:~
```

6- Execute wrap and unwrap key operations as shown below:

```sh
# to wrap a secret key
sudo ./AzureAttestSKR -a "https://sharedweu.weu.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s mysecretkey123 -w

# to unwrap an encrypted key
sudo ./AzureAttestSKR -a "https://sharedweu.weu.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s <copy_base64_from_previous_run> -u

```

Optional Arguments

- `-n`: If a nonce needs to be passed as client_payload json, use `-n` argument as below. This demo app only supports `nonce` key, however clients can send in any arbitary json as the `client_payload` in the MAA request.

```sh
sudo ./AzureAttestSKR -a "https://sharedweu.weu.attest.azure.net" -n "<some-identifier-per-maa-request>" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s <copy_base64_from_previous_run> -u
```

- `-c (imds|sp)`: Override the credentials source provider for accessing AKV

  - `imds`: If multiple managed identities are associated with the Confidential VM, `IMDS_CLIENT_ID` environment variable can be used to get the IMDS token for a selected identity

  - `sp`: If a custom service principal credentials needs to be used, `AKV_SKR_CLIENT_ID`, `AKV_SKR_CLIENT_SECRET` and `AKV_SKR_TENANT_ID` environment variables can be provided

---

## Enhancements

### Cross-Platform Support (Windows + Linux)

The application now builds on both **Linux** and **Windows**.

#### Windows Build

Requires Visual Studio 2022 with C++ workload, CMake ≥ 3.15, and [vcpkg](https://github.com/microsoft/vcpkg).

```powershell
# One-time: install the GuestAttestation NuGet package
nuget install Microsoft.Azure.Security.GuestAttestation -Version 1.1.0 -OutputDirectory packages

# Configure and build
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:/vcpkg/scripts/buildsystems/vcpkg.cmake ^
      -DVCPKG_TARGET_TRIPLET=x64-windows-release ^
      -DVCPKG_OVERLAY_TRIPLETS=triplets
cmake --build build --config Release
```

The build output in `build/Release/` includes the executable, all required vcpkg DLLs, the AttestationClientLib DLL, and MSVC runtime DLLs — ready for xcopy deployment.

#### Linux Build — Classic vs Portable

The CMake file supports a **`SKR_PORTABLE_DEPLOY`** option (default `OFF`):

| Mode | CMake flag | Behavior |
|------|-----------|----------|
| **Classic** (default) | none | Hardcoded system paths, links jsoncpp. Matches the original main-branch build. |
| **Portable** | `-DSKR_PORTABLE_DEPLOY=ON` | Uses `find_path`/`find_library`, sets `RPATH=$ORIGIN`, drops jsoncpp from the link line. Used by Dockerfiles and `build-linux.sh`. |

### Docker Build (Ubuntu 22.04)

Builds the application inside a Docker container using the pre-built `azguestattestation1` .deb package. Build time is ~2 minutes.

```sh
# From repo root:
docker build -t azureattest-skr -f cvm-securekey-release-app/Dockerfile .

# Extract the binaries:
docker create --name skr-build azureattest-skr /bin/false
docker cp skr-build:/out/ .
docker rm skr-build
```

Output is a flat deploy directory:
```
out/AzureAttestSKR                  # executable (RPATH=$ORIGIN)
out/libazguestattestation.so.1      # attestation library (RUNPATH stripped)
```

### Docker Build (Azure Linux 3.0)

Builds the attestation library from source (Azure Linux has no pre-built .deb). System OpenSSL/curl/tpm2-tss packages are symlinked into the paths the attestation library's CMake expects.

```sh
docker build -t azureattest-skr-azl \
    -f cvm-securekey-release-app/Dockerfile.azurelinux .
```

### Runtime Dependencies (target machine)

| Distro | Packages |
|--------|----------|
| Ubuntu 22.04+ | `libcurl4 libssl3 libtss2-esys-3.0.2-0` |
| RHEL 9+ | `openssl-libs libcurl tpm2-tss` |
| Azure Linux 3.0+ | `curl-libs openssl-libs tpm2-tss libgcrypt` |

### Batch Key Unwrap (`-B` flag)

Performs **one SKR call** followed by multiple unwrap operations. Accepts input from a file, stdin (`-`), or inline JSON.

```sh
# From a JSON file
sudo ./AzureAttestSKR -a <attestation-url> -k <kek-url> -c imds -B keys.json

# From stdin
cat keys.json | sudo ./AzureAttestSKR -a <attestation-url> -k <kek-url> -c imds -B -

# Inline JSON
sudo ./AzureAttestSKR -a <attestation-url> -k <kek-url> -c imds \
    -B '{"keys":[{"id":"label1","wrapped":"base64..."}]}'
```

**Input format** (`id` is a caller-chosen label for correlating results — it is not a key vault reference):
```json
{
  "keys": [
    { "id": "label1", "wrapped": "base64-encoded-ciphertext" },
    { "id": "label2", "wrapped": "base64-encoded-ciphertext" }
  ]
}
```

**Output format** (stdout):
```json
{
  "results": [
    { "id": "label1", "unwrapped": "plaintext-key" },
    { "id": "label2", "unwrapped": "plaintext-key" }
  ]
}
```

### OAEP / MGF1 Hash Algorithm Options

For unwrap operations (`-u` and `-B`), the OAEP and MGF1 hash algorithms can be specified:

- `-H <hash>` — OAEP hash algorithm: `sha1`, `sha256`, `sha384`, `sha512` (default: `sha256`, i.e. RSA-OAEP-256)
- `-G <hash>` — MGF1 hash algorithm (default: same as `-H`)

```sh
# Unwrap with SHA-256 for both OAEP and MGF1 (default — AKV standard)
sudo ./AzureAttestSKR -a <url> -k <kek> -c imds -s <wrapped> -u

# Legacy RSA-OAEP (SHA-1)
sudo ./AzureAttestSKR -a <url> -k <kek> -c imds -s <wrapped> -u -H sha1
```

### Structured Exit Codes

The application returns structured exit codes for programmatic callers:

| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `EXIT_OK` | Success |
| 1 | `EXIT_USAGE` | Bad CLI arguments |
| 2 | `EXIT_ATTEST_FAIL` | MAA attestation failed |
| 3 | `EXIT_AUTH_FAIL` | IMDS / AAD token acquisition failed |
| 4 | `EXIT_SKR_FAIL` | AKV/MHSM SKR HTTP error (policy, 403, key not found) |
| 5 | `EXIT_CRYPTO_FAIL` | OpenSSL error (decrypt, parse, unwrap) |
| 6 | `EXIT_NETWORK_FAIL` | curl/WinHTTP transport failure |

### Cross-Distro SSL CA Bundle Fix

On non-Ubuntu distros (RHEL, Fedora, SUSE, Alpine), the attestation library's hardcoded CA path (`/etc/ssl/certs/ca-certificates.crt`) does not exist, causing HTTPS failures. The application now auto-creates a `curl-ca-bundle.crt` symlink in the current working directory pointing to the distro's actual CA bundle at startup.

### Stdout / Stderr Separation

All diagnostic and trace output is written to **stderr**. Only the final result (plaintext key, JSON) is written to **stdout**, enabling clean piping:

```sh
# Pipe unwrapped key directly to another tool
sudo ./AzureAttestSKR -a <url> -k <kek> -c imds -s <wrapped> -u 2>/dev/null | my-consumer
```

  Example:

  ```sh
  sudo ./AzureAttestSKR -a "https://sharedweu.weu.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -c "sp" -s "<copy_base64_from_previous_run>" -u
  ```

## Debugging

To enable debug trace output, set the `SKR_TRACE_ON` environment variable at runtime. Use `-E` with `sudo` to preserve the environment variable (if using Service Principle environment vars).

```sh
# Level 1: full trace output
sudo SKR_TRACE_ON=1 ./AzureAttestSKR -a "https://sharedweu.weu.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s mysecretkey123 -w

# Level 2: trace with redacted sensitive values
sudo  SKR_TRACE_ON=2 ./AzureAttestSKR -a "https://sharedweu.weu.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -s mysecretkey123 -w
```
