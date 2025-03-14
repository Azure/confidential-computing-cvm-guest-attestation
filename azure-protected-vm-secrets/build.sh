#!/bin/bash
set +e

sudo apt-get update --fix-missing && sudo apt-get install -y build-essential
DEBIAN_FRONTEND=noninteractive sudo apt-get install cmake libssl-dev \
    libtasn1-6-dev pkg-config \
    googletest google-mock \
    libini-config-dev \
    libcurl4-openssl-dev \
    uuid-dev \
    libltdl-dev \
    libboost-all-dev \
    libtool \
    autoconf-archive \
    libcmocka0 \
    libcmocka-dev \
    procps \
    iproute2 \
    git \
    gcc \
    libtool \
    automake \
    libssl-dev \
    uthash-dev \
    autoconf \
    doxygen \
    libjson-c-dev \
    libusb-1.0-0-dev \
    libftdi-dev -y

dir=./repos
[ -d ${dir} ] || mkdir ${dir}

TARGETDIR=/tmp/localbuild
rm -rf ${TARGETDIR}
mkdir ${TARGETDIR}

repodir=$(git rev-parse --show-toplevel)
echo ${repodir}

echo ----------- Tpm2-tss -------------------------------
git clone https://github.com/tpm2-software/tpm2-tss ${dir}/tpm2-tss
pushd ${dir}/tpm2-tss
git checkout 3d3c9a81db1354fe75dd27f5a87551c101034b0d
./bootstrap
./configure --prefix=$TARGETDIR
sudo make install

#install locally as well since tpm2-tss needs it
./bootstrap
./configure --prefix=/usr
sudo make install
popd

echo ----------- SSPP library  -------------------------------
cd ${repodir}/azure-protected-vm-secrets
mkdir build
cd build
cmake ..
make -j$(nproc) VERBOSE=1
