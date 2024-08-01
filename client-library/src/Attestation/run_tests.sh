#!/bin/bash

ATTESTATION_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"
BUILD_DIR=${ATTESTATION_DIR}/_build/x86_64
TPM_LIB_DIR=${BUILD_DIR}/LinuxTpm
ATTESTATION_LIB_DIR=${BUILD_DIR}/AttestationClient

LOG_DIR=${BUILD_DIR}/log
TEST_LOG_DIR=${LOG_DIR}/tests
LIBTPM_TEST_LOG_DIR=${TEST_LOG_DIR}/LibTpm
ATTESTATION_LIB_TEST_LOG_DIR=${TEST_LOG_DIR}/AttestationLib

mkdir -p ${TEST_LOG_DIR}
mkdir -p ${LIBTPM_TEST_LOG_DIR}
mkdir -p ${ATTESTATION_LIB_TEST_LOG_DIR}

echo "Running LibTpm UnitTests"

${TPM_LIB_DIR}/unittests/LinuxTpmTests > ${LIBTPM_TEST_LOG_DIR}/unittest.log
rc=$?

if [ ${rc} != 0 ]; then
    echo "LibTpm unit tests failed"
    exit ${rc}
else
    echo "LibTpm unit tests succeeded"
fi

echo "Running AttestationLib UnitTests"

${ATTESTATION_LIB_DIR}/tests/lib/AttestationClientLibTests > ${ATTESTATION_LIB_TEST_LOG_DIR}/unittest.log
rc=$?

if [ ${rc} != 0 ]; then
    echo "AttestationLib unit tests failed"
    exit ${rc}
else
    echo "AttestationLib unit tests succeeded"
fi

cd -