#!/bin/bash
sudo apt-get install build-essential -y
sudo apt-get install libcurl4-openssl-dev -y
sudo apt-get install libjsoncpp-dev -y
sudo apt-get install cmake -y
wget https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.0.2_amd64.deb
sudo dpkg -i azguestattestation1_1.0.2_amd64.deb
git clone https://github.com/skondla/confidential-computing-cvm-guest-attestation.git
cd confidential-computing-cvm-guest-attestation/cvm-guest-attestation-linux-app
cmake .
make
sudo ./AttestationClient
bash generateAttestationReport.sh
cat maa_report.json | jq

