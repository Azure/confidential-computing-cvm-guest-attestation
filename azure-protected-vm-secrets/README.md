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

- JWT will be appended with a magic string to indicate just looking at the blob that it is a secret provisioned by Azure. This will help quickly return plain text passwords back. This will be unpeeled before making unprotect secret call.

- Add protocol version like `"version": "1" // Protocol version`

### Guest side API

```C
/*
    @description: This function unprotects the secret from a jwt signed 
        with the provisioned Guest Secret Key. 
    @param jwt: the jwt token to unprotect 
    @param jwtlen: the length of the jwt token 
    @param output_secret: the pointer to the secret extracted from the jwt    token. Allocated by the function, must be freed by the caller. 
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
long unprotect_secret(char *jwt, uint jwtlen, char **output_secret) 
```

TODO:

- Add policy field as an enum to indicate allowed payload is encrypted, signed, or legacy.

## Delivery

This drop contains:

- Windows Static Library
- Linux Static Library
- Sample App for both Windows and Linux
- libcrypto-3-x64.dll for Windows(TODO: fix this to static link)

Other dependencies:

- Visual C++ Redistributable

_Note_: Signature verification is not implemented in Linux in this drop.

## Project Structure

The Azure Protected VM Secrets project is organized into several directories and files. Here is an overview of the key components:

- **azure-protected-vm-secrets**: Contains the main library source code.
  - **CMakeLists.txt**: CMake configuration file for building the library.
  - **SecretsProvisioningLibrary.vcxproj**: Visual Studio project file for building the library on Windows.
  - **Linux**: Contains Linux-specific implementations.
    - **OsslAesWrapper.cpp/h**: Implementation of AES encryption/decryption using OpenSSL.
    - **OsslHKDF.cpp/h**: Implementation of HKDF (HMAC-based Extract-and-Expand Key Derivation Function) using OpenSSL.
    - **OsslECDiffieHellman.cpp/h**: Implementation of ECDH (Elliptic Curve Diffie-Hellman) using OpenSSL.
  - **Windows**: Contains Windows-specific implementations.
    - **BcryptAesWrapper.cpp/h**: Implementation of AES encryption/decryption using BCrypt.
    - **BcryptHKDF.cpp/h**: Implementation of HKDF using BCrypt.
    - **BcryptECDiffieHellman.cpp/h**: Implementation of ECDH using BCrypt.
  - **SecretsProvisioningLibrary.nuspec**: NuGet package specification for the library.

- **azure-protected-vm-secrets/SecretsProvisioningSample**: Contains sample code demonstrating how to use the library.
  - **CMakeLists.txt**: CMake configuration file for building the sample.
  - **SecretsProvisioningSample.vcxproj**: Visual Studio project file for building the sample on Windows.
  - **main.cpp**: Entry point for the sample application.

- **azure-protected-vm-secrets/SecretsProvsioningUT**: Contains unit tests for the library.
  - **CMakeLists.txt**: CMake configuration file for building the unit tests.
  - **SecretsProvsioningUT.vcxproj**: Visual Studio project file for building the unit tests on Windows.
  - **BcryptTests.cpp**: Unit tests for the library.

- **azure-protected-vm-secrets/SecretsProvisioningFunctionalityTest**: Contains functionality tests for the library.
  - **SecretsProvisioningFunctionalityTest.vcxproj**: Visual Studio project file for building the functionality tests on Windows.
  - **test.cpp**: Functionality tests for the library.

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
  
  long result = unprotect_secret((char*)(jwt), jwtlen, &output_secret);
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

The sample App can be used to test the usage of the library on TVM/CVM that has or has not be provisioned with the third blob. It has 6 commands:

- GenerateKey: Generates and evicts a key to the handle for Secure Secrets Provisioning Platform.
- IsKeyPresent: Checks if a key is present at the mandated index (0x81000004)
- RemoveKey: Removes the key present on the mandated index.
- GetVmid: Fetches the vmid from the SMBIOS
- Encrypt: Takes in a string and performs the equivalent of one invocation of the protect API. This is only intended for small integration testing. Please use the service otherwise.
- Decrypt: Takes in a jwt and decrypts the secret.

A test flow for a new application that uses the library could use the sample app to set up a test using the following steps:

1. Deploy CVM/TVM.
2. Copy Sample app to VM.
3. Run `GenerateKey` to generate a key in the vTPM.
4. Run `Encrypt testData` to create the JWT (currently this will not sign).
5. Take the JWT from step 5, and pass to the new application that is being tested.

## Extending the Library

To extend the library, follow these steps:

1. **Add New Source Files**: Add new `.cpp` and `.h` files to the SecretsProvisioningLibrary directory.
2. **Update CMakeLists.txt**: Add the new source files to the `CMakeLists.txt` file.
3. **Update Visual Studio Project**: Add the new source files to the Visual Studio project file (`SecretsProvisioningLibrary.vcxproj`).

---

This documentation provides an overview of the `SecretsProvisioningLibrary` project, including how to build, test, and use the library, as well as how to extend it. If you have any questions or need further assistance, please feel free to reach out to the project maintainers.
