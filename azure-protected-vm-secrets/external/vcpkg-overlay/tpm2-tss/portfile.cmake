vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO tpm2-software/tpm2-tss
    REF 4.0.1
    SHA512 e2342517c7b36e74cc8695af3616002472f60cc0c4d61d58c4829fe0eb4518adfc133d24e2559ab93b33ca47fd5fcd0c0963aa66a5febaa107560db7ae1ac8b2
    HEAD_REF master
)

# Set OpenSSL paths from vcpkg installed location
set(OPENSSL_INCLUDE "${CURRENT_INSTALLED_DIR}/include")
set(OPENSSL_LIB "${CURRENT_INSTALLED_DIR}/lib")
set(OPENSSL_DEBUG_LIB "${CURRENT_INSTALLED_DIR}/debug/lib")

# Determine if static build
if(VCPKG_LIBRARY_LINKAGE STREQUAL "static")
    set(STATIC_FLAG "-Static")
else()
    set(STATIC_FLAG "")
endif()

# Fix vcxproj files (toolset, SDK version, static/dynamic)
vcpkg_execute_required_process(
    COMMAND powershell -ExecutionPolicy Bypass -File "${CMAKE_CURRENT_LIST_DIR}/fix-vcxproj.ps1"
        -SourcePath "${SOURCE_PATH}"
        -OpenSslInclude "${OPENSSL_INCLUDE}"
        -OpenSslLib "${OPENSSL_LIB}"
        -OpenSslDebugLib "${OPENSSL_DEBUG_LIB}"
        ${STATIC_FLAG}
    WORKING_DIRECTORY "${SOURCE_PATH}"
    LOGNAME fix-vcxproj-${TARGET_TRIPLET}
)

# Build Release - pass OpenSSL paths via MSBuild properties
vcpkg_execute_required_process(
    COMMAND msbuild "${SOURCE_PATH}/tpm2-tss.sln"
        /p:Configuration=Release
        /p:Platform=x64
        /p:OpenSslDir=${CURRENT_INSTALLED_DIR}
        /m
    WORKING_DIRECTORY "${SOURCE_PATH}"
    LOGNAME build-${TARGET_TRIPLET}-rel
)

# Build Debug
vcpkg_execute_required_process(
    COMMAND msbuild "${SOURCE_PATH}/tpm2-tss.sln"
        /p:Configuration=Debug
        /p:Platform=x64
        /p:OpenSslDir=${CURRENT_INSTALLED_DIR}
        /m
    WORKING_DIRECTORY "${SOURCE_PATH}"
    LOGNAME build-${TARGET_TRIPLET}-dbg
)

# Install headers (only tss2 headers, not OpenSSL)
file(GLOB TSS2_HEADERS "${SOURCE_PATH}/include/tss2/*.h")
file(INSTALL ${TSS2_HEADERS} DESTINATION "${CURRENT_PACKAGES_DIR}/include/tss2")

# Install libraries (only tss2 libs, not OpenSSL)
file(GLOB RELEASE_LIBS "${SOURCE_PATH}/x64/Release/tss2*.lib")
file(GLOB DEBUG_LIBS "${SOURCE_PATH}/x64/Debug/tss2*.lib")
file(INSTALL ${RELEASE_LIBS} DESTINATION "${CURRENT_PACKAGES_DIR}/lib")
file(INSTALL ${DEBUG_LIBS} DESTINATION "${CURRENT_PACKAGES_DIR}/debug/lib")

# Install DLLs for dynamic builds (only tss2 DLLs, not OpenSSL)
if(NOT VCPKG_LIBRARY_LINKAGE STREQUAL "static")
    file(GLOB RELEASE_DLLS "${SOURCE_PATH}/x64/Release/tss2*.dll")
    file(GLOB DEBUG_DLLS "${SOURCE_PATH}/x64/Debug/tss2*.dll")
    file(INSTALL ${RELEASE_DLLS} DESTINATION "${CURRENT_PACKAGES_DIR}/bin")
    file(INSTALL ${DEBUG_DLLS} DESTINATION "${CURRENT_PACKAGES_DIR}/debug/bin")
endif()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE")