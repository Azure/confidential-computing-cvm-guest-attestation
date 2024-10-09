**Building AttestationLibrary**

This document describes how to compile and build Attestation Library from sources.

**Note**

The build instructions have been created using Debian based distribution (Ubuntu).

***Build Attestation Library***

1. Open terminal.
2. Clone this repo.
```
git clone https://github.com/Azure/confidential-computing-cvm-guest-attestation.git
cd confidential-computing-cvm-guest-attestation
```
3. Run pre-requisites.sh
```
sudo ./client-library/src/Attestation/pre-requisites.sh
```
4. Build the library.
```
sudo ./client-library/src/Attestation/build.sh
```

AttestationLibrary would be built at path client-library/src/Attestation/_build/x86_64/packages/attestationlibrary
