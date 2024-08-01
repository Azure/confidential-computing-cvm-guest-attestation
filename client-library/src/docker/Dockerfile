FROM ubuntu:22.04

RUN apt-get update

RUN apt-get install -y curl apt-transport-https lsb-release gnupg
RUN curl -sL https://packages.microsoft.com/keys/microsoft.asc | \
        gpg --dearmor | \
        tee /etc/apt/trusted.gpg.d/microsoft.asc.gpg > /dev/null
RUN echo "deb [arch=amd64] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" | \
    tee /etc/apt/sources.list.d/azure-cli.list
RUN apt-get update
RUN apt-get install -y azure-cli
RUN apt-get install -y wget

RUN az extension add --name azure-devops

RUN apt-get update
RUN apt-get install -y --fix-missing \
    autoconf \
    autoconf-archive \
    automake \
    build-essential \
    doxygen \
    libssl-dev \
    libtool \
    libgcrypt-dev \
    gnulib \
    pkg-config \
    libjsoncpp-dev \
    gcc-12 \
    g++-12 \
    attr \
    squashfs-tools \
    cryptsetup-bin \
    libcap-dev \
    python-pip \
    libcurl4-openssl-dev \
    libtspi-dev \
    rpm \
    debhelper \
    zip

RUN mkdir -p /usr/src

# Install Intel TPM TSS stack
RUN export CC=gcc && export CXX=g++ && \
    # Download tpm2-tss
    mkdir -p /usr/src/tpm2-tss && \
    cd /usr/src/tpm2-tss && \
    TSS_VER=2.3.0 && \
    wget --quiet https://github.com/tpm2-software/tpm2-tss/archive/$TSS_VER.tar.gz && \
    echo 425fc9abf44ebb662ccfe0cfa8315fc1b9f8eee8ed8fd8e0894961415176524d $TSS_VER.tar.gz | sha256sum -c && \
    # Build tpm2-tss
    tar xzf $TSS_VER.tar.gz && \
    TSS_SRC_DIR=/usr/src/tpm2-tss/tpm2-tss-$TSS_VER && \
    cd $TSS_SRC_DIR && \
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) check && \
    # Install
    make install && \
    ldconfig && \
    # Cleanup
    rm -rf /usr/src/tpm2-tss

# Install CMake
RUN apt-get install -y cmake git libboost-all-dev

# Install Google Test
RUN git clone https://github.com/google/googletest.git /src/googletest && \
    cd /src/googletest && git checkout e2239ee6043f73722e7aa812a459f54a28552929 && \
    cmake . && make && make install && \
#    cp googlemock/lib* googlemock/gtest/lib* /usr/local/lib && \
#    cp -R /src/googletest/googletest/include/* /usr/local/include && \
#    cp -R /src/googletest/googlemock/include/* /usr/local/include && \
    cd / && rm -rf /src/googletest

# Install RapidJSON
RUN git clone https://github.com/Tencent/rapidjson /usr/src/rapidjson && \
    cd /usr/src/rapidjson && mkdir -p build && cd build && \
    # Build
    cmake .. && make -j$(nproc) && \
    # Install
    make install && \
    # Cleanup
    rm -rf /usr/src/rapidjson

# Install libarchive
RUN wget --quiet https://www.libarchive.org/downloads/libarchive-3.4.3.tar.gz && \
    tar -C /usr/src -xzf libarchive-3.4.3.tar.gz && \
    rm -rf libarchive-3.4.3.tar.gz && cd /usr/src/libarchive-3.4.3 && \
    ./configure && make && make install && \
    cd /usr/src && rm -rf libarchive-3.4.3

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    rm -rf /var/lib/apt/lists/*
