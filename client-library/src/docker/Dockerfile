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

# Install Boost, TSS2, Archive
RUN apt-get install -y cmake git libboost-dev libtss2-dev libarchive-dev

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

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    rm -rf /var/lib/apt/lists/*
