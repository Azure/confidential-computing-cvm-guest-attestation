cmake_minimum_required(VERSION 3.5)

#MUST be same as the version in the latest entry in debian/changelog file.
project(azguestattestation VERSION 1.0.5)

set(CMAKE_PROJECT_TARGET azguestattestation)

add_definitions (-DPLATFORM_UNIX)

find_path(CURL_INCLUDE_DIR NAMES curl PATHS /usr/include
                                            NO_DEFAULT_PATH)
find_path(CRYPTO_INCLUDE_DIR NAMES openssl PATHS /usr/local/openssl/include
                                            NO_DEFAULT_PATH)
include_directories()

include_directories(
    ${CURL_INCLUDE_DIR}
    ${CRYPTO_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../../../LinuxTpm/include
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${CMAKE_CURRENT_SOURCE_DIR}/../..
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
    ${CMAKE_SOURCE_DIR}/../external/jsoncpp-0.10.7/src
    ${CMAKE_SOURCE_DIR}/../external/SnpVmReport
)

add_library(${CMAKE_PROJECT_TARGET} SHARED ../../AttestationHelper.cpp
                                           ../AttestationClientImpl.cpp
                                           ../AttestationClient.cpp
                                           ../AttestationParameters.cpp
                                           ../TpmInfo.cpp
                                           ../Logging.cpp
                                           ../TpmUnseal.cpp
                                           ../NativeConverter.cpp
                                           ../AttestationLibUtils.cpp
                                           ../ImdsOperations.cpp
                                           ../IsolationInfo.cpp
                                           ../HclReportParser.cpp
                                           ../HttpClient.cpp
                                           ../TpmCertOperations.cpp
                                           ../ImdsClient.cpp
                                           ../AttestationLibTelemetry.cpp
                                           ${CMAKE_SOURCE_DIR}/../external/jsoncpp-0.10.7/src/jsoncpp.cpp)
                                           
find_library(CURL_LIB NAMES libcurl.a PATHS /usr/lib
                                           NO_DEFAULT_PATH)

target_link_libraries(${CMAKE_PROJECT_TARGET} Tpm2)
target_link_libraries(${CMAKE_PROJECT_TARGET} ${CURL_LIB})

set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(${CMAKE_PROJECT_TARGET} PROPERTIES SOVERSION 1)
