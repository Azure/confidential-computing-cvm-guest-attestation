cmake_minimum_required(VERSION 3.5)

# Renamed from `DynamicSecretsProvisioningLibrary` -> `azure_protected_vm_secrets`
# so the on-disk shared library file (`libazure_protected_vm_secrets.so.X.Y.Z`)
# matches the package name `azure-protected-vm-secrets` per Fedora's
# Packaging Guidelines (§Listing Shared Library Files: shared libs SHOULD be
# named `lib<package-name>.so.*`). The directory on disk
# (`DynamicSecretsProvisioningLibrary/`) is preserved so the
# `add_subdirectory(DynamicSecretsProvisioningLibrary)` call in the parent
# CMakeLists, and the OneBranch sync to the public mirror, continue to work
# unchanged. Underscores (not hyphens) because CMake target names disallow
# hyphens; the linker emits `libazure_protected_vm_secrets.so.<version>`.
# Public C API symbols (unprotect_secret, free_secret, ...) are NOT changed.
project (azure_protected_vm_secrets)

add_definitions (-DPLATFORM_UNIX -DDYNAMIC_SAMPLE)

# Library on-disk name follows Fedora package-name convention (lib<package>.so).
# CMake target name uses underscores because hyphens aren't permitted in target
# names; the resulting shared object is libazure_protected_vm_secrets.so.X.Y.Z.
set (CMAKE_PROJECT_TARGET azure_protected_vm_secrets)
project (Linux${CMAKE_PROJECT_TARGET})

# Try to find Tss2
find_path(TSS2_INCLUDE_DIR NAMES tss2 PATHS ${SYSTEM_LIBRARY_PREFIX}/usr/local/include ${SYSTEM_LIBRARY_PREFIX}/usr/include NO_DEFAULT_PATH)

# Invalidate cache to force cmake to lookup the libraries again
set (TSS2_ESYS TSS2_ESYS-NOTFOUND)
set (TSS2_SYS TSS2_SYS-NOTFOUND)
set (TSS2_MU TSS2_MU-NOTFOUND)
set (TSS2_TCTI_DEVICE TSS2_TCTI_DEVICE-NOTFOUND)
set (TSS2_RC TSS2_RC-NOTFOUND)

find_library(TSS2_ESYS names libtss2-esys.so tss2-esys PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/ /usr/lib64 NO_DEFAULT_PATH)
find_library(TSS2_SYS names libtss2-sys.so tss2-sys PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/ /usr/lib64  NO_DEFAULT_PATH)
find_library(TSS2_MU NAMES libtss2-mu.so tss2-mu PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/ /usr/lib64  NO_DEFAULT_PATH)
find_library(TSS2_TCTI_DEVICE NAMES libtss2-tcti-device.so tss2-tcti-device PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/ /usr/lib64  NO_DEFAULT_PATH)
find_library(TSS2_RC NAMES libtss2-rc.so tss2-rc PATHS /usr/local/lib /usr/lib /usr/lib/x86_64-linux-gnu/ /usr/lib64  NO_DEFAULT_PATH)

set(TSS2_LIBRARIES ${TSS2_ESYS} ${TSS2_SYS} ${TSS2_MU} ${TSS2_TCTI_DEVICE} dl ${TSS2_RC})

set(TSS2_INCLUDE_DIRS ${TSS2_INCLUDE_DIR})

set(ATTESTATION_INCLUDE_DIRS external/attestation/)

# Find Boost
find_package(Boost REQUIRED)

#find_package(Tss2 REQUIRED)
include_directories(${TSS2_INCLUDE_DIRS} ${Boost_INCLUDE_DIRS} ${ATTESTATION_INCLUDE_DIRS})

# set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)

file(GLOB SOURCES "../*.cpp" "../Linux/*.cpp" "../CvmHelper/src/*.cpp")

# nlohmann/json: prefer system package (Fedora ships nlohmann-json-devel), fall
# back to FetchContent for build environments without it. See root CMakeLists
# for rationale.
find_package(nlohmann_json QUIET)
if(NOT nlohmann_json_FOUND)
    include(FetchContent)
    FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
    FetchContent_MakeAvailable(json)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD libsystemd)

if(NOT SYSTEMD_FOUND)
    # Fallback for older or different distributions
    find_path(SYSTEMD_INCLUDE_DIRS systemd/sd-journal.h)
    find_library(SYSTEMD_LIBRARIES systemd)
    if(SYSTEMD_INCLUDE_DIRS AND SYSTEMD_LIBRARIES)
        set(SYSTEMD_FOUND TRUE)
    endif()
endif()

if(SYSTEMD_FOUND)
    include_directories(${SYSTEMD_INCLUDE_DIRS})
    add_definitions(-DUSE_SYSTEMD)
else()
    message(WARNING "systemd development files not found - falling back to stdout logging only")
endif()

add_library(${CMAKE_PROJECT_TARGET} SHARED ${SOURCES})

# SONAME and full version on the SHARED library so that, on disk, we get the
# Fedora-required triplet (lib<name>.so.X.Y.Z real ELF, .so.X SONAME symlink,
# .so devel symlink). See Fedora index.adoc §SONAME Handling, §Listing Shared
# Library Files, §Devel Packages.
set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES
  VERSION   ${SECRETS_LIB_VERSION}
  SOVERSION ${SECRETS_LIB_VERSION_MAJOR}
)

target_link_libraries(${CMAKE_PROJECT_TARGET} ${SYSTEMD_LIBRARIES})
target_link_libraries(${CMAKE_PROJECT_TARGET} ${TSS2_LIBRARIES})
#target_link_libraries(${CMAKE_PROJECT_TARGET} ${CRYPTO_LIB})
target_link_libraries(${CMAKE_PROJECT_TARGET} OpenSSL::Crypto)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${SSL_LIB})
target_link_libraries(${CMAKE_PROJECT_TARGET} pthread)
target_link_libraries(${CMAKE_PROJECT_TARGET} dl)
target_link_libraries(${CMAKE_PROJECT_TARGET} tss2-mu)
target_link_libraries(${CMAKE_PROJECT_TARGET} nlohmann_json::nlohmann_json)
target_link_libraries(${CMAKE_PROJECT_TARGET} Boost::boost)
set_property(TARGET ${CMAKE_PROJECT_TARGET} PROPERTY POSITION_INDEPENDENT_CODE ON)

# Install shared library and public header (CPack is configured at the root).
# Use GNUInstallDirs so that on Fedora x86_64, %cmake's -DCMAKE_INSTALL_LIBDIR=lib64
# is honored (multilib-correct location: /usr/lib64/). Falls back to "lib" on
# distros that don't set CMAKE_INSTALL_LIBDIR.
include(GNUInstallDirs)
install(TARGETS ${CMAKE_PROJECT_TARGET} LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${CMAKE_SOURCE_DIR}/SecretsProvisioningLibrary.h DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})