FROM ubuntu:20.04 as builder
ENV DEBIAN_FRONTEND=noninteractive
RUN apt update && apt upgrade -y && \
    apt-get  install -y \
    build-essential \
    libcurl4-openssl-dev \
    libjsoncpp-dev \
    libboost-all-dev \
    nlohmann-json3-dev \
    cmake \
    wget \
    git

RUN wget https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.0.2_amd64.deb
RUN dpkg -i azguestattestation1_1.0.2_amd64.deb

COPY . .

RUN cd cvm-attestation-sample-app && cmake . && make && cp ./AttestationClient /

FROM ubuntu:20.04 as app
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y jq && rm -rf /var/lib/apt/lists/*
COPY --from=builder /AttestationClient /
COPY aks-linux-sample/get-attestation-report.sh /

RUN chmod a+x /get-attestation-report.sh

ENTRYPOINT ["/get-attestation-report.sh"]
