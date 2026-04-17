#!/bin/bash

pushd `pwd`

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}"  )" && pwd  )"

BUILDTYPE=""

function Usage()
{
    echo "Usage: $0 [-h] [-d] [-l] --> where -d enables Debug Build, -l enables Azure Local. It defaults to Release Builds.";
    exit 1;
}

while getopts ":hdl" opt; do
  case ${opt} in
    h )
        Usage
      ;;
    d )
        BUILDTYPE="${BUILDTYPE} -d"
      ;;
    l )
        BUILDTYPE="${BUILDTYPE} -l"
      ;;
    \? )
        Usage
      ;;
  esac
done

${SCRIPT_DIR}/build_x86_64.sh ${BUILDTYPE}

popd
