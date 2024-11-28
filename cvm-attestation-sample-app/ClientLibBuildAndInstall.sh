#!/bin/bash

sudo ../client-library/src/Attestation/pre-requisites.sh
sudo ../client-library/src/Attestation/build.sh
sudo dpkg -i ../client-library/src/Attestation/_build/x86_64/packages/attestationlibrary/deb/azguestattestation1_1.0.5_amd64.deb