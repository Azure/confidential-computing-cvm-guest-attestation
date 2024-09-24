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
    g++ \
    pkg-config \
    libjsoncpp-dev \
    gcc \
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
	libboost-dev

# Needed to sudo the Attestation extension tests.
sudo pip3 install mock

#sudo cp /usr/lib/x86_64-linux-gnu/libjsoncpp.a /usr/local/lib && \
#    sudo ls /usr/local/lib/libjsoncpp.a && \
#    sudo cp /usr/lib/x86_64-linux-gnu/libgtest.a /usr/local/lib && \
#    sudo ls /usr/local/lib/libgtest.a && \
#    sudo cp /usr/lib/x86_64-linux-gnu/libgtest_main.a /usr/local/lib && \
#    sudo ls /usr/local/lib/libgtest_main.a && \
#    sudo cp /usr/lib/x86_64-linux-gnu/libgmock.a /usr/local/lib && \
#    sudo ls /usr/local/lib/libgmock.a && \
#    sudo cp /usr/lib/x86_64-linux-gnu/libgmock_main.a /usr/local/lib && \
#    sudo ls /usr/local/lib/libgmock.a

CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"


sudo wget https://www.openssl.org/source/openssl-3.2.0.tar.gz && \
    echo 14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e openssl-3.2.0.tar.gz | sha256sum -c - && \
    sudo tar -C /tmp -xzf openssl-3.2.0.tar.gz && \
    sudo rm -rf openssl-3.2.0.tar.gz && \
    cd /tmp/openssl-3.2.0 && \
    sudo ./config --prefix=/usr/local/attestationssl --openssldir=/usr/local/attestationssl && \
    sudo make -j$(nproc) && \
    sudo make install && \
    sudo ln -sf /usr/local/attestationssl/lib64/libssl.so /usr/lib/x86_64-linux-gnu/libssl.so.3 && \
    sudo ln -sf /usr/local/attestationssl/lib64/libcrypto.so /usr/lib/x86_64-linux-gnu/libcrypto.so.3 && \
    sudo ldconfig

cd ${CURRENT_DIR}

export LDFLAGS="-L/usr/local/attestationssl/lib64" && \ 
	export CPPFLAGS="-I/usr/local/attestationssl/include" && \ 
    sudo wget https://curl.se/download/curl-8.5.0.tar.gz --no-check-certificate && \
    sudo tar -C /tmp -xzf curl-8.5.0.tar.gz && \
    sudo rm -rf curl-8.5.0.tar.gz && cd /tmp/curl-8.5.0 && \
    ./configure --with-ssl --prefix=/usr/local/attestationcurl && \
    sudo make -j$(nproc) && \
    sudo make LIBDIR=lib && sudo make install && \
    sudo ldconfig -n /usr/local/attestationcurl/lib

cd ${CURRENT_DIR}

sudo mkdir -p /usr/src

export CC=gcc && export CXX=g++ && \
    export LDFLAGS="-L/usr/local/attestationssl/lib64 -lcrypto" && \
    export CPPFLAGS="-I/usr/local/attestationssl/include" && \
    # Download tpm2-tss
    sudo mkdir -p /usr/src/tpm2-tss && \
	sudo git config --global --add safe.directory /usr/src/tpm2-tss && \
    sudo git clone https://github.com/tpm2-software/tpm2-tss.git /usr/src/tpm2-tss && \
    cd /usr/src/tpm2-tss && \
    sudo git checkout 8b404ee7e5886c71aa53accb4ad38823724f7b13 && \
    # Build tpm2-tss
    sudo ./bootstrap && \
    sudo ./configure && \
    sudo make -j$(nproc) && \
    # Install
    sudo make install && \
    sudo ldconfig && \
    # Cleanup
    sudo rm -rf /usr/src/tpm2-tss

cd ${CURRENT_DIR}

# Install RapidJSON
sudo git config --global --add safe.directory /usr/src/rapidjson
sudo git clone https://github.com/Tencent/rapidjson /usr/src/rapidjson && \
    cd /usr/src/rapidjson && sudo mkdir -p build && cd build && \
    # Build
    sudo cmake .. && sudo make -j$(nproc) && \
    # Install
    sudo make install && \
    # Cleanup
    sudo rm -rf /usr/src/rapidjson

cd ${CURRENT_DIR}

popd