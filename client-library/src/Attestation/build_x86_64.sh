#!/bin/bash

echo "Build for x86_64"
CMAKE_BUILDTYPE_OPT=""

function Usage()
{
    echo "Usage: $0 [-h] [-d] --> where -d enables Debug Build. It defaults to Release Builds.";
    exit 1;
}

while getopts ":hd" opt; do
  case ${opt} in
    h )
        Usage
      ;;
    d )
        CMAKE_BUILDTYPE_OPT="-DCMAKE_BUILD_TYPE=Debug"
        echo "Build Type = Debug"
      ;;
    \? )
        Usage
      ;;
  esac
done

# Exit with exit code of the last executed command in case of command failure.
set -e
set -o pipefail

pushd `pwd`

# Define all directory paths.
ATTESTATION_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"
REPO_ROOT_DIR=${ATTESTATION_DIR}/..
BUILD_DIR=${ATTESTATION_DIR}/_build/x86_64
PACKAGE_DIR=${BUILD_DIR}/packages
LOG_DIR=${BUILD_DIR}/log
ATTESTATION_LIB_SHARED_DIR=${ATTESTATION_DIR}/AttestationClient/lib/DynamicLibrary
VERSION="1.0.2"
: ${CC:=/usr/bin/gcc-12}
: ${CXX:=/usr/bin/g++-12}
export CC
export CXX
# Create all directories
mkdir -p $BUILD_DIR
mkdir -p $PACKAGE_DIR
mkdir -p $LOG_DIR
cd $BUILD_DIR

cmake $CMAKE_BUILDTYPE_OPT ../.. > $LOG_DIR/cmake.build.log
make -j`nproc` > $LOG_DIR/make.build.log

cd ${ATTESTATION_LIB_SHARED_DIR}

cp ${BUILD_DIR}/AttestationClient/lib/DynamicLibrary/libazguestattestation.so.${VERSION} ${PACKAGE_DIR}

./createDebPackage.sh


popd
