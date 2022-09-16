FROM ubuntu:18.04
RUN apt update && apt upgrade -y
RUN apt-get  install -y \
    build-essential \
    libcurl4-openssl-dev \
    libjsoncpp-dev \
    cmake \
    wget \
    git
RUN apt-get install -y  jq

RUN wget https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.0.2_amd64.deb
RUN dpkg -i azguestattestation1_1.0.2_amd64.deb

RUN git clone https://github.com/Azure/confidential-computing-cvm-guest-attestation.git
RUN cd confidential-computing-cvm-guest-attestation/cvm-guest-attestation-linux-app && cmake . && make && cp ./AttestationClient /

COPY get-attestation-report.sh /

ENTRYPOINT ["/get-attestation-report.sh"]
