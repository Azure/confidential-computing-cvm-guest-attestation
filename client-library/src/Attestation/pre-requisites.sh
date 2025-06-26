#!/bin/bash

sudo apt-get update

sudo apt-get install -y --fix-missing \
    build-essential \
    python3 \
    wget \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    doxygen \
    libtool \
    libgcrypt-dev \
    gnulib \
    g++-12 \
    pkg-config \
    libjsoncpp-dev \
    gcc-12 \
    attr \
    squashfs-tools \
    cryptsetup-bin \
    libcap-dev \
    python3-pip \
    libtspi-dev \
    rpm \
    debhelper \
    libgtest-dev \
    libgmock-dev \
    cmake \
    git \
    zip \
    uuid-dev \
    libjson-c-dev \
    libarchive-dev \
    libboost-dev \
    libcurl4-openssl-dev \
    nlohmann-json3-dev

# Needed to sudo the Attestation extension tests.
sudo pip3 install mock

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"

sudo wget https://www.openssl.org/source/openssl-3.3.2.tar.gz && \
    echo 2e8a40b01979afe8be0bbfb3de5dc1c6709fedb46d6c89c10da114ab5fc3d281 openssl-3.3.2.tar.gz | sha256sum -c - && \
    sudo tar -C /tmp -xzf openssl-3.3.2.tar.gz && \
    sudo rm -rf openssl-3.3.2.tar.gz && \
    cd /tmp/openssl-3.3.2 && \
    sudo LDFLAGS='-Wl,-R/usr/local/attestationssl/lib64' ./config --prefix=/usr/local/attestationssl --openssldir=/usr/local/attestationssl && \
    sudo make -j$(nproc) && \
    sudo make install_sw

cd ${CURRENT_DIR}

sudo wget https://curl.se/download/curl-8.5.0.tar.gz --no-check-certificate && \
    sudo tar -C /tmp -xzf curl-8.5.0.tar.gz && \
    sudo rm -rf curl-8.5.0.tar.gz && cd /tmp/curl-8.5.0 && \
    env PKG_CONFIG_PATH=/usr/local/attestationssl/lib64/pkgconfig LDFLAGS='-Wl,-R/usr/local/attestationssl/lib64' ./configure \
    --without-zstd --with-openssl \
    --prefix=/usr/local/attestationcurl && \
    sudo make -j$(nproc) && \
    sudo make install

cd ${CURRENT_DIR}

sudo mkdir -p /usr/src

export CC=gcc-12 && export CXX=g++-12 && \
    sudo mkdir -p /usr/src/tpm2-tss && \
    sudo git config --global --add safe.directory /usr/src/tpm2-tss && \
    sudo git clone https://github.com/tpm2-software/tpm2-tss.git /usr/src/tpm2-tss && \
    cd /usr/src/tpm2-tss && \
    # Build tpm2-tss
    sudo ./bootstrap && \
    env PKG_CONFIG_PATH=/usr/local/attestationcurl/lib/pkgconfig:/usr/local/attestationssl/lib64/pkgconfig \
    LDFLAGS='-Wl,-R/usr/local/attestationssl/lib64 -Wl,-R/usr/local/attestationcurl/lib' \
    ./configure --prefix=/usr/local/attestationtpm2-tss && \
    sudo make -j$(nproc) && \
    # Install
    sudo make install && \
    # Cleanup
    sudo rm -rf /usr/src/tpm2-tss

cd ${CURRENT_DIR}

popd
