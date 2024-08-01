**Building AttestationLibrary**

This document describes how to compile and build Attestation Library from sources.

**Prerequisites**

Docker must be installed for setting up the build environment for compiling Attestation library.

***Build docker image***

```
cd docker
./build.sh
```

***Build Attestation Library***

```
cd docker
./compile.sh
```

AttestationLibrary would be built at path client-library/src/Attestation/_build/Attestation/packages
