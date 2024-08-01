#!/bin/sh
sudo docker run --rm --privileged --detach -v "$(realpath ../):/mnt" --net=host --hostname "AttestationLibBuild" --name=cvm_attestation_build_container cvmattest_build:latest "bin/sleep" infinity
