# Azure Local Build Scripts

Scripts for building the attestation SDK (Clientlib), SKR sample app, and attestation client sample app for Azure Local.

## Projects

- [Attestation Client Sample App](../cvm-attestation-sample-app/README.md)
- [Secure Key Release Sample App](../cvm-securekey-release-app/README.md)
- Attestation Client Library (`../client-library/`)

## Build

```bash
./build-azure-local.sh        # Build and gather artifacts
./build-azure-local.sh -c     # Clean rebuild
./build-azure-local.sh -p     # Install pre-requisites first
./build-azure-local.sh -cp    # Clean rebuild with pre-requisites
```

Artifacts are collected into the `output/` directory at the repo root.
