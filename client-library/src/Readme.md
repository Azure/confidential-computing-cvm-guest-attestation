**Building AttestationLibrary**

This document describes how to compile and build Attestation Library from sources.

**Note**

The build instructions have been created using Debian based distribution (Ubuntu) and verified on Ubuntu 20, 22 and 24 based Confidential VM images.

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
The prerequisite script skips the curl build if libcurl 8.5.0 is already installed in `/usr/local/attestationcurl`, and skips the OpenSSL build if OpenSSL 3.3.2 is already installed in `/usr/local/attestationssl`. System installations alone do not replace these custom builds. When a build is needed, its source archive is downloaded; the OpenSSL archive is checksum-verified.

4. Build the library.
```
sudo ./client-library/src/Attestation/build.sh
```

AttestationLibrary would be built at path client-library/src/Attestation/_build/x86_64/packages/attestationlibrary

**Note Azure Local Builds**
1. On Ubuntu 22.04 or 24.04, install the Azure Local pre-requisites instead of the standard pre-requisites above. This includes libtss2-dev and edge-cc-base-attestation-sdk from the production PMC feed by default. Add `-i` to explicitly opt into insiders-fast.
```
sudo ./client-library/src/Attestation/pre-requisites-azure-local.sh
# Optional: use the insiders-fast evidence SDK instead
sudo ./client-library/src/Attestation/pre-requisites-azure-local.sh -i
```
If `edge-cc-base-attestation-sdk` is already installed, its feed setup and installation are skipped unless you use `-f` to force SDK installation.
When you use both `-i` and `-f`, the SDK is installed from the insiders-fast feed rather than the production PMC feed, even if the SDK is already installed.

```
sudo ./client-library/src/Attestation/pre-requisites-azure-local.sh -f
# Force installation from insiders-fast instead of production PMC
sudo ./client-library/src/Attestation/pre-requisites-azure-local.sh -i -f
```

2. Build the Library specifiying its for Azure local.
```
sudo ./client-library/src/Attestation/build.sh -l
```
