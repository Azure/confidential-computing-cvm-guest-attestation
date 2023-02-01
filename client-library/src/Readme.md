**Building AttestationLibrary**

This document describes how to compile and build Attestation Library from sources.

**Prerequisites**

Docker must be installed for setting up the build environment for compiling Attestation library.

***Build docker image***

1. Open terminal or command promt.
2. Move to path client-library/src/docker.
3. Build the docker image and it will build and install all the libraries required at run time like boost, tpm2-tss, libcurl, openssl etc.
```
docker build . -t attestationlib.azurecr.io/linux:latest
```

***Build Attestation Library***
1. Start docker container built in last step.
```
docker run --rm --privileged --detach -v "C:\confidential-computing-cvm-guest-attestation:/mnt" --net=host --hostname "AttestationLibBuild" --name=attestation_lib_container attestationlib.azurecr.io/linux:latest "bin/sleep" infinity
```

```
docker exec -it -w /mnt attestation_lib_container bash
```

2. Move to path client-library/src/Attestation

3. run build.sh

```
./build.sh
```

AttestationLibrary would be built at path client-library/src/Attestation/_build/Attestation/packages
