# AKV (or mHSM) Secure Key Release sample application

The code in this directory demonstrates how to get an asymetric encryption key stored in Azure Keyvault or managed HSM released to a Linux Confidential or Trusted Launch VM. The attesting of the VM state cryptographically verifies it meets the requirements of a baseline attestation policy. The securely released asymmetric key can be used to wrap and unwrap a symmetric key.

## Build Instructions for Linux

Create a Linux Confidential or Trusted Launch virtual machine in Azure and clone the application.

Use the below command to install the `build-essential` package. This package will install everything required for compiling our sample application written in C++.

```sh
$ sudo apt-get install build-essential
```

Install the below packages

```sh
$ sudo apt-get install libssl-dev
$ sudo apt-get install libcurl4-openssl-dev
$ sudo apt-get install libjsoncpp-dev
$ sudo apt-get install libboost-all-dev
$ sudo apt install nlohmann-json3-dev
```

Download the attestation package from the following location - https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/

Use the below command to install the attestation package

```sh
$ sudo dpkg -i azguestattestation1_1.0.5_amd64.deb
```

Once the above packages have been installed, use below steps to build and run the app

```sh
$ cd cvm-securekey-release-app/
$ mkdir build && cd build
$ cmake .. -DCMAKE_BUILD_TYPE=Release  # Debug for more tracing output.
$ make
```

# Execution instructions.

1- Create or use an existing Azure KeyVault in your subscription.
2- Create an RSA key with below sample confidentiality policy.

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

3- Create or use an existing Managed Identity (user-assigned).
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

  Example:

  ```sh
  sudo ./AzureAttestSKR -a "https://sharedweu.weu.attest.azure.net" -k "https://mykv.vault.azure.net/keys/mykey/version_GUID" -c "sp" -s "<copy_base64_from_previous_run>" -u
  ```
