#!/bin/bash

ATTESTATION_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../../../" && pwd  )"
CURRENT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd  )"

TEMP=./data
ATTESTATIONLIBPATH=${ATTESTATION_DIR}/_build/x86_64/AttestationClient/lib/DynamicLibrary
PACKAGE_DIR=${ATTESTATION_DIR}/_build/x86_64/packages/attestationlibrary/deb

rm -rf ${TEMP}

mkdir -p ${TEMP}
mkdir -p ${PACKAGE_DIR}

cp -r ${CURRENT_DIR}/debian ${TEMP}/.

cd ${TEMP}

#MUST be same as the package name in debian/control file.
export PACKAGE=azguestattestation1

#MUST be same as the version in the latest entry in debian/changelog file.
export VERSION=1.0.2

cp ${ATTESTATIONLIBPATH}/*.so.${VERSION} .

dpkg-buildpackage -us -uc

cd ${CURRENT_DIR}

rm -rf ${TEMP}

mv *.deb ${PACKAGE_DIR}/