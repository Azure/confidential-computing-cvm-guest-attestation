cmake_minimum_required(VERSION 3.15)

project(AzureAttestSKR)

set(CMAKE_PROJECT_TARGET AzureAttestSKR)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# define TRACE constant for extensive logging.
if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions (-DTRACE)
endif()

# Use dynamic CRT (/MD) on Windows — required by security policy for DLL servicing
if(WIN32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    # Security hardening (match internal repo)
    # Note: add /Qspectre when Spectre-mitigated libs are installed via VS Installer
    add_compile_options(/guard:cf /sdl)
    add_link_options(/guard:cf)
    # Link optimizations for Release
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /OPT:REF /OPT:ICF")
endif()

add_executable(${CMAKE_PROJECT_TARGET}
    AttestationUtil.cpp
    Logger.cpp
    Main.cpp
)

# ===========================================================================
# Platform-specific dependencies
# ===========================================================================

if(UNIX)
    add_definitions(-DPLATFORM_UNIX)

    if(AZURE_LOCAL)
        add_compile_definitions(AZURE_LOCAL)
        message(STATUS "Azure Local mode: ENABLED")
    else()
        message(STATUS "Azure Local mode: DISABLED")
    endif()

    # -------------------------------------------------------------------
    # SKR_PORTABLE_DEPLOY (default: OFF)
    #   OFF — "classic" build: hardcoded paths, links jsoncpp, no RPATH.
    #         Matches the original main-branch CMakeLists.txt exactly.
    #         Use when the .deb is installed system-wide and the binary
    #         runs from a standard location.
    #
    #   ON  — "portable" build: uses find_path/find_library, drops
    #         jsoncpp from the link line, sets RPATH=$ORIGIN so the
    #         attestation .so can live next to the binary.
    #         Used by Dockerfile, build-linux.sh, and CI pipelines.
    #
    # Usage:
    #   cmake -S . -B build                              # classic
    #   cmake -S . -B build -DSKR_PORTABLE_DEPLOY=ON     # portable
    # -------------------------------------------------------------------
    option(SKR_PORTABLE_DEPLOY
        "Portable flat-directory deploy (find libs, RPATH=\$ORIGIN, no jsoncpp)"
        OFF)

    if(SKR_PORTABLE_DEPLOY)
        # --- Portable / flat-deploy mode ---
        # See Dockerfile / Dockerfile.azurelinux for the full install steps.
        # The attestation library comes from the azguestattestation1 .deb
        # (packages.microsoft.com) or is built from source on Azure Linux.

        # Guest Attestation (not in vcpkg or standard repos)
        find_path(ATTESTATION_INCLUDE_DIR
            NAMES AttestationClient.h
            PATHS /usr/include/azguestattestation1
        )
        find_library(ATTESTATION_LIBRARY
            NAMES azguestattestation
        )
        if(NOT ATTESTATION_INCLUDE_DIR OR NOT ATTESTATION_LIBRARY)
            message(FATAL_ERROR "azguestattestation not found. Install the .deb from:\n"
                                "  https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/")
        endif()

        target_include_directories(${CMAKE_PROJECT_TARGET} PRIVATE
            ${ATTESTATION_INCLUDE_DIR}
        )

        # RPATH: find the shipped attestation .so next to the binary
        set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES
            BUILD_RPATH   "\$ORIGIN"
            INSTALL_RPATH "\$ORIGIN"
        )

        # Note: jsoncpp is NOT linked here.  The pre-built .deb has a
        # transitive link-time dependency on jsoncpp (via a .la/.pc file
        # it ships — the amalgamated source is baked into the .so itself).
        # The Ubuntu Dockerfile installs libjsoncpp-dev to satisfy the
        # linker; Azure Linux builds from source with the vendored
        # amalgamation and doesn't need system jsoncpp at all.
        target_link_libraries(${CMAKE_PROJECT_TARGET}
            ${ATTESTATION_LIBRARY}
            curl
            ssl crypto
            z
        )

    else()
        # --- Classic mode (matches main branch) ---
        include_directories(
            /usr/include/azguestattestation1
            /usr/include/jsoncpp
        )

        link_directories(
            /usr/lib
            /usr/lib/x86_64-linux-gnu
        )

        target_link_libraries(${CMAKE_PROJECT_TARGET}
            azguestattestation
            curl
            jsoncpp
            crypto
        )
    endif()

    if(AZURE_LOCAL)
        target_link_libraries(${CMAKE_PROJECT_TARGET} edge-cc-base-attestation-sdk)
    endif()

elseif(WIN32)
    # ===================================================================
    # vcpkg (Windows only) — manifest mode via find_package()
    # Disable vcpkg's applocal DLL deploy (requires dumpbin in PATH which
    # isn't reliably available when MSBuild spawns pwsh.exe post-build).
    # We copy vcpkg DLLs ourselves below using a glob.
    # ===================================================================
    set(VCPKG_APPLOCAL_DEPS OFF CACHE BOOL "" FORCE)
    find_package(CURL REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_package(nlohmann_json CONFIG REQUIRED)
    find_package(ZLIB REQUIRED)
    # --- Guest Attestation (NuGet: Microsoft.Azure.Security.GuestAttestation) ---
    set(ATTESTATION_NUGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/packages/Microsoft.Azure.Security.GuestAttestation.1.1.0/build/native"
        CACHE PATH "GuestAttestation NuGet package root")
    if(EXISTS "${ATTESTATION_NUGET_DIR}/include/AttestationClient.h")
        target_include_directories(${CMAKE_PROJECT_TARGET} PRIVATE
            "${ATTESTATION_NUGET_DIR}/include"
        )
        target_link_directories(${CMAKE_PROJECT_TARGET} PRIVATE
            "${ATTESTATION_NUGET_DIR}/lib/x64"
        )
    else()
        message(WARNING "GuestAttestation NuGet package not found. Run:\n"
                        "  nuget install Microsoft.Azure.Security.GuestAttestation "
                        "-Version 1.1.0 -OutputDirectory ${CMAKE_CURRENT_SOURCE_DIR}/packages")
    endif()

    target_link_libraries(${CMAKE_PROJECT_TARGET}
        AttestationClientLib
        CURL::libcurl                         # vcpkg (transitive deps handled automatically)
        nlohmann_json::nlohmann_json
        OpenSSL::SSL OpenSSL::Crypto
        ZLIB::ZLIB
        bcrypt crypt32 winhttp                # Windows system libs
    )

    # --- Post-build: copy required vcpkg DLLs to output directory ---
    # The vcpkg toolchain installs packages into build/vcpkg_installed/<triplet>/
    # Exclude DLLs that are not needed at runtime:
    #  - boost_*  : header-only usage (base64 iterators, algorithm) — verified via dumpbin /DEPENDENTS
    #  - legacy   : OpenSSL legacy provider (DES, RC4, MD4 etc.) — not used, and its
    #               presence can trigger security/compliance findings for weak crypto
    set(VCPKG_BIN_DIR "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/bin")
    file(GLOB VCPKG_RUNTIME_DLLS "${VCPKG_BIN_DIR}/*.dll")
    list(FILTER VCPKG_RUNTIME_DLLS EXCLUDE REGEX "boost_|legacy")
    foreach(DLL_PATH ${VCPKG_RUNTIME_DLLS})
        get_filename_component(DLL_NAME "${DLL_PATH}" NAME)
        add_custom_command(TARGET ${CMAKE_PROJECT_TARGET} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${DLL_PATH}" $<TARGET_FILE_DIR:${CMAKE_PROJECT_TARGET}>
            COMMENT "Copying ${DLL_NAME}")
    endforeach()

    # --- Post-build: copy AttestationClientLib DLL (not managed by vcpkg) ---
    if(EXISTS "${ATTESTATION_NUGET_DIR}/lib/x64/AttestationClientLib.dll")
        add_custom_command(TARGET ${CMAKE_PROJECT_TARGET} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "${ATTESTATION_NUGET_DIR}/lib/x64/AttestationClientLib.dll"
                $<TARGET_FILE_DIR:${CMAKE_PROJECT_TARGET}>
            COMMENT "Copying AttestationClientLib.dll")
    endif()

    # --- Post-build: copy MSVC runtime DLLs (vcruntime140*.dll, msvcp140.dll) ---
    # Required because we link against the dynamic CRT (/MD).
    # Only vcruntime and msvcp140 are needed; skip concrt140, msvcp140_* variants.
    include(InstallRequiredSystemLibraries)
    foreach(RTL ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS})
        get_filename_component(RTL_NAME "${RTL}" NAME)
        if(RTL_NAME MATCHES "^vcruntime" OR RTL_NAME STREQUAL "msvcp140.dll")
            add_custom_command(TARGET ${CMAKE_PROJECT_TARGET} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${RTL}" $<TARGET_FILE_DIR:${CMAKE_PROJECT_TARGET}>
                COMMENT "Copying MSVC runtime: ${RTL_NAME}")
        endif()
    endforeach()
endif()