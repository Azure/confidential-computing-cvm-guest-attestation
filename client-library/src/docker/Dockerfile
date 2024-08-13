FROM mcr.microsoft.com/mirror/docker/library/ubuntu:20.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y python3.8

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
    libtool \
    libgcrypt-dev \
    gnulib \
    g++-8 \
    pkg-config \
    libjsoncpp-dev \
    gcc-8 \
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
    libjson-c-dev

# Needed to run the Attestation extension tests.
RUN pip3 install mock

RUN cp /usr/lib/x86_64-linux-gnu/libjsoncpp.a /usr/local/lib && \
    ls /usr/local/lib/libjsoncpp.a && \
    cp /usr/lib/x86_64-linux-gnu/libgtest.a /usr/local/lib && \
    ls /usr/local/lib/libgtest.a && \
    cp /usr/lib/x86_64-linux-gnu/libgtest_main.a /usr/local/lib && \
    ls /usr/local/lib/libgtest_main.a && \
    cp /usr/lib/x86_64-linux-gnu/libgmock.a /usr/local/lib && \
    ls /usr/local/lib/libgmock.a && \
    cp /usr/lib/x86_64-linux-gnu/libgmock_main.a /usr/local/lib && \
    ls /usr/local/lib/libgmock.a

RUN mkdir -p /usr/src

RUN wget https://www.openssl.org/source/openssl-3.2.0.tar.gz  && \
    echo 14c826f07c7e433706fb5c69fa9e25dab95684844b4c962a2cf1bf183eb4690e openssl-3.2.0.tar.gz | sha256sum -c - && \
    tar -C /tmp -xzf openssl-3.2.0.tar.gz && \
    rm -rf openssl-3.2.0.tar.gz && \
    cd /tmp/openssl-3.2.0 && \
    ./config --prefix=/usr/local/openssl && \
    make && \
    make test && \
    make install && \
    ln -s /usr/local/openssl/lib64/libssl.so /usr/lib/x86_64-linux-gnu/libssl.so.3 && \
    ln -s /usr/local/openssl/lib64/libcrypto.so /usr/lib/x86_64-linux-gnu/libcrypto.so.3 && \
    ldconfig

#Install curl
RUN export LDFLAGS="-L/usr/local/openssl/lib64" && \ 
    export CPPFLAGS="-I/usr/local/openssl/include" && \ 
    wget --quiet https://curl.se/download/curl-8.5.0.tar.gz && \
    tar -C /tmp -xzf curl-8.5.0.tar.gz && \
    rm -rf curl-8.5.0.tar.gz && cd /tmp/curl-8.5.0 && \
    ./configure --with-ssl --prefix=/usr && \
    make -j && \
    make LIBDIR=lib && make install && \
    ldconfig -n /usr/lib

RUN export CC=gcc && export CXX=g++ && \
    export LDFLAGS="-L/usr/local/openssl/lib64 -lcrypto" && \
    export CPPFLAGS="-I/usr/local/openssl/include" && \
    # Download tpm2-tss
    mkdir -p /usr/src/tpm2-tss && \
    git clone https://github.com/tpm2-software/tpm2-tss.git /usr/src/tpm2-tss && \
    cd /usr/src/tpm2-tss && \
    git checkout 8b404ee7e5886c71aa53accb4ad38823724f7b13 && \
    # Build tpm2-tss
    ./bootstrap && \
    ./configure && \
    make -j$(nproc) && \
    # Install
    make install && \
    ldconfig && \
    # Cleanup
    rm -rf /usr/src/tpm2-tss

# Install RapidJSON
RUN git clone https://github.com/Tencent/rapidjson /usr/src/rapidjson && \
    cd /usr/src/rapidjson && mkdir -p build && cd build && \
    # Build
    cmake .. && make -j$(nproc) && \
    # Install
    make install && \
    # Cleanup
    rm -rf /usr/src/rapidjson

# Install Boost
RUN mkdir -p /usr/src/boost && \
    cd /usr/src/boost && \
    wget --quiet https://boostorg.jfrog.io/artifactory/main/release/1.70.0/source/boost_1_70_0.tar.gz && \
    echo 882b48708d211a5f48e60b0124cf5863c1534cd544ecd0664bb534a4b5d506e9 boost_1_70_0.tar.gz | sha256sum -c && \
    tar xzf boost_1_70_0.tar.gz && \
    cd boost_1_70_0 && \
    # Build
    ./bootstrap.sh && \
    # Install
    ./b2 --without-python install && \
    # Cleanup
    rm -rf /usr/src/boost

# Install libarchive
RUN wget --quiet https://www.libarchive.org/downloads/libarchive-3.4.3.tar.gz && \
    tar -C /usr/src -xzf libarchive-3.4.3.tar.gz && \
    rm -rf libarchive-3.4.3.tar.gz && cd /usr/src/libarchive-3.4.3 && \
    ./configure && make && make install && \
    cd /usr/src && rm -rf libarchive-3.4.3

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    rm -rf /var/lib/apt/lists/*