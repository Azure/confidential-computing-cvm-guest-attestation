# Azure Protected VM Secrets

Welcome to the Azure Protected VM Secrets Library project! This documentation is intended to help developers understand the structure and functionality of the project, as well as provide guidance on how to build, test, and extend the library. The library provides in-guest components the ability to decrypt secrets that are protected from the host by the Azure. This gives control plane services the ability to protect a secret from the host, and for the guest component to decrypt the secret for provisioning.

## Table of Contents

1. [Usage](#usage)
2. [Project Structure](#project-structure)
3. [Building the Project](#building-the-project)
4. [Running Tests](#running-tests)
5. [Using the Library](#using-the-library)
6. [Extending the Library](#extending-the-library)

## Usage

The ProtectSecret method is invoked by the Azure to protect the secret and return a JWT token. The UnProtectSecret method is executed by the guest's executable, utilizing the TPM to securely unprotect the secret from the JWT token.

### JWT data contract

Header:

```yaml
{ 
  "type": "string" // JWT type, default "JWT"
  "alg": "string" // JWS algorithm descriptor per JWA1. I.e. "RS256"
  "x5c": "array" // Leaf certificate 
  "x5t": "string" // Thumbprint of leaf 
  "x-az-cvm-purpose": "string" // Required: "secrets-provisioning"
  "x-az-rsa-padding": "string" // Optional: RSA padding for transport key. "rsaes" (default) or "rsaes-oaep"
}
```

Payload

```yaml
{ 
  "encryptedSecret": "string", // Encrypted Secret 
  "wrappedAesTransportKey": "string", // Symmetric key to wrap ECDH Private 
  "encryptedGuestEcdhPrivateKey": "string", // Encrypted ECDH private key DER and base64 encoded 
  "ephemeralEcdhPublicKey": "string", // base64 encoded DER encoding of ECDH public key 
  "iat": "integer", // Timestamp when token was issued per RFC 
  "secretIv": "string", // IV for encrypted secret data 
  "dataNonce": "string", 
  "keyNonce": "string",
  "salt": "string" // Salt used in HKDF 
}
```

The JWT will be signed with the signature in the JWS signature field. The Leaf certificate in X509 form is present in the “x5c” field of the header, and the Root Certificate and Intermediate Certificate will be embedded in the client.

TODO:

- Add protocol version like `"version": "1" // Protocol version`

### Guest side API

```C
/*
    @description: This function unprotects the secret from a jwt signed 
        with the provisioned Guest Secret Key. 
    @param jwt: the jwt token to unprotect 
    @param jwtlen: the length of the jwt token 
    @param policy: Flags to designate configuration settings. 0 – allow unsigned & unencrypted, 1 allow unencrypted & require signed, 2 require encrypted & allow unsigned, 3 require signed & require encrypted.
    @param output_secret: the pointer to the secret extracted from the jwt    token. Allocated by the function, must be freed by the caller. 
    @param eval_policy: a pointer to an unsigned integer (size_t) provided by reference by the caller to return the type of protected payload. This is a bitfield where 1 designates the protection is enabled and 0 designates that it lacks that protection. The current fields are encrypted (bit 0) and signed (bit 1).
    @return: non-negative length of the secret on success. On failure 
        returns a negative value indicating the error code. The error 
        codes are grouped as follows: 
        - The fourth least significant octet Defines the class of error: 
            - 0 - General Library error (e.g. time, base64, io, memory) 
            - 1 - TPM error 
            - 2 - Cryptography Error 
            - 3 - Json/JWT error 
        - The 0-3 least significant octets points to specific Errors. 
*/
long unprotect_secret(char* jwt, unsigned int jwtlen, unsigned int policy, char** output_secret, unsigned int* eval_policy);
/*
   @description: This function unprotects the secret from a jwt signed 
      with the provisioned Guest Secret Key and returns it as wide characters (UTF-16).
   @param jwt: the wide character jwt token to unprotect 
   @param jwtlen: the length of the jwt token in wide characters
   @param policy: Bitmask of PolicyOption flags - same values as unprotect_secret above.
   @param output_secret: the pointer to the wide character secret extracted from the jwt token. Allocated by the function, must be freed by the caller using delete[]. 
   @param eval_policy: a pointer to an unsigned integer (size_t) provided by reference by the caller to return the type of protected payload. This is a bitfield where 1 designates the protection is enabled and 0 designates that it lacks that protection. The current fields are encrypted (bit 0), signed (bit 1) and legacy (bit 2).
   @return: 0 on success. On failure returns a negative value indicating the error code. The error codes are grouped as follows: 
      - The fourth least significant octet Defines the class of error: 
         - 0 - General Library error (e.g. time, base64, io, memory) 
         - 1 - TPM error 
         - 2 - Cryptography Error 
         - 3 - Json/JWT error 
*/
long unprotect_secret_wide(wchar_t* jwt, unsigned int jwtlen, unsigned int policy, wchar_t** output_secret, unsigned int* eval_policy);
/* 
   @description: This function frees the memory used by the protected secret.
   @param secret: the unprotected secret. 
*/ 
void free_secret(char* secret); 
/* 
   @description: This function determines if the library is being used in a CVM.
   @return: Boolean indicating whether the library is running in a CVM.
*/ 
bool is_cvm();
```

## Delivery

This drop contains:

- Windows Static Library (`SecretsProvisioningLibrary.lib`)
- Linux Static Library (`libSecretsProvisioningLibrary.a`)
- Windows Dynamic Library (`DynamicSecretsProvisioningLibrary.dll`)
- Linux Dynamic Library (`libDynamicSecretsProvisioningLibrary.so`)
- CLI tool (`azure-protected-secrets-tool`) for Windows and Linux
- Sample App for both Windows and Linux

Other dependencies:

- Visual C++ Redistributable
- tpm2-tss (Linux)

## Project Structure

The Azure Protected VM Secrets project is organized into several directories and files. Here is an overview of the key components:

- **SecretsProvisioningLibrary**: Root directory containing the main library source code.
  - **CMakeLists.txt**: CMake configuration file for building all targets.
  - **SecretsProvisioningLibrary.vcxproj**: Visual Studio project file for building the static library on Windows.
  - **Linux**: Contains Linux-specific implementations.
    - **OsslAesWrapper.cpp/h**: AES encryption/decryption using OpenSSL.
    - **OsslHKDF.cpp/h**: HKDF using OpenSSL.
    - **OsslECDiffieHellman.cpp/h**: ECDH using OpenSSL.
  - **Windows**: Contains Windows-specific implementations.
    - **BcryptAesWrapper.cpp/h**: AES encryption/decryption using BCrypt.
    - **BcryptHKDF.cpp/h**: HKDF using BCrypt.
    - **BcryptECDiffieHellman.cpp/h**: ECDH using BCrypt.

- **SecretsProvisioningLibrary/SecretsProvisioningSample**: Static sample app and CLI source files.
  - **main.cpp**: Entry point — static sample mode or CLI mode (`DYNAMIC_SAMPLE`).
  - **cli_common.h/.cpp**: `CliArgs` struct and `parse_args()` — shared by all CLI commands.
  - **cmd_is_cvm.h/.cpp**: `is-cvm` command — detects SNP/TDX/VBS isolation via CvmHelper.
  - **cmd_is_secrets_enabled.h/.cpp**: `is-secrets-provisioning-enabled` command — checks TPM key presence.
  - **cmd_unprotect_secret.h/.cpp**: `unprotect-secret` command — accepts JWT as inline argument or from stdin, writes decrypted secret to stdout.
  - **cmd_validate_imds.h/.cpp**: `validate-imds-metadata` command — two-level IMDS blob verification.

- **SecretsProvisioningLibrary/azure-protected-secrets-tool**: Build configs for the CLI binary.
  - **azure-protected-secrets-tool.vcxproj**: Windows project — builds CLI exe linking `DynamicSecretsProvisioningLibrary.dll`.
  - **CMakeLists.txt**: Linux CMake — builds CLI exe linking `libDynamicSecretsProvisioningLibrary.so`.
  - **tests/**: Unit tests for CLI commands (GTest, no TPM required).

- **SecretsProvisioningLibrary/SecretsProvsioningUT**: Unit tests for the library.
  - **CMakeLists.txt**: CMake configuration for building unit tests.
  - **SecretsProvsioningUT.vcxproj**: Visual Studio project file.

- **SecretsProvisioningLibrary/SecretsProvisioningFunctionalityTest**: Functionality tests requiring a real TPM.
  - **SecretsProvisioningFunctionalityTest.vcxproj**: Visual Studio project file.
  - **test.cpp**: End-to-end encrypt/decrypt tests against a real vTPM.

## Building the Project

### Prerequisites

- **CMake**: Ensure CMake is installed on your system.
- **OpenSSL**: Ensure OpenSSL is installed on your system.
- **tpm2-tss**: Ensure [tpm2-tss](https://github.com/tpm2-software/tpm2-tss) is installed on your system.
- **Visual Studio**: For building on Windows, ensure Visual Studio is installed.
- **Googletest**: For building unit tests, ensure [Googletest](https://google.github.io/googletest/) is installed.

### Building on Linux

1. **Clone the Repository**:

   ```sh
   git clone https://github.com/Azure/confidential-computing-cvm-guest-attestation.git
   cd azure-protected-vm-secrets
   ```

2. **Configure the Project**:

   ```sh
   mkdir build
   cd build
   cmake ..
   ```

3. **Build the Project**:

   ```sh
   make
   ```

### Building on Windows

1. **Clone the Repository**:

   ```sh
   git clone https://github.com/Azure/confidential-computing-cvm-guest-attestation.git
   cd azure-protected-vm-secrets
   ```

2. **Open the Solution**:
   Open `SecretsProvisioningLibrary.sln` in Visual Studio.

3. **Build the Solution**:
   Select the desired configuration (e.g., Debug or Release) and build the solution.

## Running Tests

### Running Unit Tests on Linux

1. **Navigate to the Build Directory**:

   ```sh
   cd azure-protected-vm-secrets/build
   ```

2. **Run the Tests**:

   ```sh
   ./SecretsProvsioningUT/SecretsProvsioningUT
   ```

### Running Unit Tests on Windows

1. **Open the Solution**:
   Open `SecretsProvisioningLibrary.sln` in Visual Studio.

2. **Build the Test Project**:
   Build the `SecretsProvsioningUT` project.

3. **Run the Tests**:
    Use the Test Explorer in Visual Studio to run the tests.

### Running Functionality Tests on Windows

1. **Open the Solution**:
   Open `SecretsProvisioningLibrary.sln` in Visual Studio.

2. **Build the Functionality Test Project**:
   Build the `SecretsProvisioningFunctionalityTest` project.

3. **Deploy Test VM**:
   Deploy a CVM/TVM for running the test.

4. **Run test**:
   Copy the output test from step 2 to the VM and run the test binary.

## Using the Library

### Example: Secret Decryption

```cpp
#include "SecretsProvisioningLibrary.h"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
  int jwtlen = strlen(argv[2]); // Note Better to use strnlen() or receive as input
  
  unsigned int policy = 2; // Policy Allow unsigned payload
  unsigned int evaluated_policy = 0;
  long result = unprotect_secret((char*)(jwt), jwtlen, policy, &output_secret, &evaluated_policy);
  if (result <= 0) {
    std::cout << "Failed to unprotect secret" << std::hex << result << std::endl;
    return 1;
  }
  if (output_secret != nullptr) {
    secret = std::string(output_secret, result);
    std::cout << "\n\nSecret: " << secret.c_str() << std::endl;
    free_secret(output_secret);
  }
  return 0;
}
```

## Sample App

The static `SecretsProvisioningSample` binary can be used to test the library on a CVM/TVM. It exposes the following commands:

- **GenerateKey**: Generates and persists a key to TPM handle `0x81000004`.
- **IsKeyPresent**: Checks if a key is present at handle `0x81000004`.
- **RemoveKey**: Removes the key at handle `0x81000004`.
- **GetVmid**: Fetches the VM UUID from SMBIOS.
- **IsCvm**: Checks if running inside a CVM (Windows only).
- **Encrypt `<string>`**: Simulates the CPS protect API — produces a real JWT with TPM-wrapped keys. For integration testing only.
- **Decrypt `<jwt>`**: Decrypts a JWT and prints the secret.

A test flow for a new application using the library:

1. Deploy CVM/TVM.
2. Copy `SecretsProvisioningSample` to the VM.
3. Run `GenerateKey` to create a key in the vTPM.
4. Run `Encrypt testData` to produce a JWT.
5. Pass the JWT to the application under test.

## CLI Tool

`azure-protected-secrets-tool` is a standalone CLI that links `DynamicSecretsProvisioningLibrary` and exposes the guest-side API as shell commands. It supports `--json` output for machine-readable results.

| Command | Description | `--json` |
|---|---|---|
| `is-cvm` | Detect CVM isolation type (SNP/TDX/VBS) | `{"isolation_type":"SNP","hypervisor":"Microsoft Hv"}` |
| `is-secrets-provisioning-enabled` | Check if TPM guest key is present | `{"enabled":true,"version":"1.0.4"}` |
| `unprotect-secret [TOKEN]` | Decrypt a protected secret. TOKEN may be passed as an inline argument or piped via stdin. | `{"secret":"..."}` with `--json`, raw bytes otherwise |
| `validate-imds-metadata` | Validate IMDS blob SignatureInfo | `{"validated":true,"fields":{...}}` |

Options: `--policy N`, `--json`, `--help`, `--version`

```sh
# Example: decrypt a protected secret (inline argument)
azure-protected-secrets-tool unprotect-secret "$JWT" --policy 2

# Example: decrypt via pipe
printf '%s' "$JWT" | azure-protected-secrets-tool unprotect-secret --policy 2

# Example: JSON output
azure-protected-secrets-tool unprotect-secret "$JWT" --policy 2 --json

# Example: check CVM status as JSON
azure-protected-secrets-tool is-cvm --json
```

## Extending the Library

To extend the library, follow these steps:

1. **Add New Source Files**: Add new `.cpp` and `.h` files to the SecretsProvisioningLibrary directory.
2. **Update CMakeLists.txt**: Add the new source files to the `CMakeLists.txt` file.
3. **Update Visual Studio Project**: Add the new source files to the Visual Studio project file (`SecretsProvisioningLibrary.vcxproj`).

---

This documentation provides an overview of the `SecretsProvisioningLibrary` project, including how to build, test, and use the library, as well as how to extend it. If you have any questions or need further assistance, please feel free to reach out to the project maintainers.
