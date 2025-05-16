cmake_minimum_required(VERSION 3.5)
project (DynamicSecretsProvisioningLibrary)

add_definitions (-DPLATFORM_UNIX)

set (CMAKE_PROJECT_TARGET DynamicSecretsProvisioningLibrary)
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

file(GLOB SOURCES "../*.cpp" "../Linux/*.cpp")

# Add nlohmann/json.hpp using FetchContent
include(FetchContent)
FetchContent_Declare(json URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(json)
# find_package(nlohmann_json REQUIRED)

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

# CPack configuration

# Check if /bin/apt or /bin/rpm exists
find_program(APT_PROGRAM apt)
find_program(RPM_PROGRAM rpm)

# Check if running on Ubuntu
execute_process(COMMAND lsb_release -is OUTPUT_VARIABLE DISTRO OUTPUT_STRIP_TRAILING_WHITESPACE)
if(APT_PROGRAM)
    set(CPACK_GENERATOR "DEB")
    set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Microsoft Corp")
    set(CPACK_DEBIAN_PACKAGE_DEPENDS "libssl3t64, libtss2-esys-3.0.2-0t64, libtss2-sys1t64, libtss2-mu-4.0.1-0t64, libtss2-tcti-device0t64, libtss2-rc0t64")
    set(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "x86_64")
elseif(RPM_PROGRAM)
    set(CPACK_GENERATOR "RPM")
    set(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
endif()
set(CPACK_PACKAGE_VERSION "0.1.0")
set(CPACK_PACKAGE_CONTACT "")
set(CPACK_PACKAGE_NAME "azure-protected-vm-secrets")
set(CPACK_PACKAGE_DESCRIPTION "Dynamic Library for the Azure Protected VM Secrets feature for CVMs")
set(CPACK_PACKAGE_VENDOR "Microsoft Corp")
set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}")

# Include additional files in the package
install(TARGETS ${CMAKE_PROJECT_TARGET} DESTINATION lib)
install(FILES ${CMAKE_SOURCE_DIR}/SecretsProvisioningLibrary.h DESTINATION include)

# Exclude gtest and gmock files from the package
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/ DESTINATION include
        FILES_MATCHING PATTERN "*.h"
        PATTERN "gtest" EXCLUDE
        PATTERN "gmock" EXCLUDE)

include(CPack)